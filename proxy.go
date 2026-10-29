package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Sites: the reverse proxies on the server (nginx, Caddy, Traefik, Nginx
// Proxy Manager), every site they serve, where each one forwards to, its
// HTTPS certificate and the last 10 minutes of its traffic. Sites Apex adds
// are written to their own files (never into the owner's), with what was
// asked for in the first line, so they can be edited again. Every change is
// tested with the proxy's own check, then reloaded; if either fails, every
// file is put back as it was.

type ProxyReport struct {
	Proxies []ProxyInfo `json:"proxies"`
	Sites   []Site      `json:"sites"`
	Taken   int64       `json:"taken"` // Unix ms
}

type ProxyInfo struct {
	Kind     string `json:"kind"` // nginx, caddy, traefik, npm
	Name     string `json:"name"`
	Running  bool   `json:"running"`
	Editable bool   `json:"editable"`
	Note     string `json:"note,omitempty"`
	Admin    string `json:"admin,omitempty"` // a proxy's own page (Nginx Proxy Manager)
}

type Site struct {
	ID          string       `json:"id"`
	Proxy       string       `json:"proxy"`
	Domains     []string     `json:"domains"`
	Targets     []string     `json:"targets"`
	HTTPS       bool         `json:"https"`
	Enabled     bool         `json:"enabled"`
	Managed     bool         `json:"managed"`   // added in Apex: can be edited
	CanToggle   bool         `json:"canToggle"` // can be switched off and on
	File        string       `json:"file,omitempty"`
	Spec        *SiteSpec    `json:"spec,omitempty"`
	Cert        *CertInfo    `json:"cert,omitempty"`
	Traffic     *SiteTraffic `json:"traffic,omitempty"`
	TrafficNote string       `json:"trafficNote,omitempty"`

	logs   []string // its own access logs
	router string   // Traefik: the router's name, as access logs write it
}

type SiteSpec struct {
	Domains    []string `json:"domains"`
	Upstream   string   `json:"upstream"`
	HTTPS      bool     `json:"https"`
	Websockets bool     `json:"websockets"`
}

type CertInfo struct {
	Expires int64  `json:"expires,omitempty"` // Unix s
	Issuer  string `json:"issuer,omitempty"`
	Problem string `json:"problem,omitempty"`
}

type ProxyChange struct {
	Proxy string   `json:"proxy"`
	Verb  string   `json:"verb"` // add, update, enable, disable, remove
	Site  string   `json:"site"` // the site's id (all but add)
	Spec  SiteSpec `json:"spec"` // add, update
}

// MARK: Checking what's asked for

var (
	domainRE   = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
)

// cleanSpec checks a site and returns it in its one written form: lower-case
// domains, `scheme://host[:port]` upstream. Nothing else reaches a config
// file, so nothing can be slipped into one.
func cleanSpec(s SiteSpec) (SiteSpec, error) {
	out := SiteSpec{HTTPS: s.HTTPS, Websockets: s.Websockets}
	seen := map[string]bool{}
	for _, d := range s.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" || seen[d] {
			continue
		}
		if len(d) > 253 || !domainRE.MatchString(d) {
			return out, fmt.Errorf("%q isn't a domain name (like example.com or *.example.com)", d)
		}
		seen[d] = true
		out.Domains = append(out.Domains, d)
	}
	if len(out.Domains) == 0 {
		return out, errors.New("give at least one domain")
	}
	if len(out.Domains) > 20 {
		return out, errors.New("at most 20 domains a site")
	}
	up := strings.TrimSpace(s.Upstream)
	if !strings.Contains(up, "://") {
		up = "http://" + up
	}
	u, err := url.Parse(up)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.Hostname() == "" {
		return out, fmt.Errorf("%q isn't an address to forward to (like http://127.0.0.1:3000)", s.Upstream)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			host = "[" + ip.String() + "]"
		} else {
			host = ip.String()
		}
	} else if !hostnameRE.MatchString(host) {
		return out, fmt.Errorf("%q isn't a host name", host)
	}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscan(p, &n); err != nil || n < 1 || n > 65535 || fmt.Sprint(n) != p {
			return out, fmt.Errorf("%q isn't a port", p)
		}
		host += ":" + p
	}
	out.Upstream = u.Scheme + "://" + host
	return out, nil
}

// slug: a file name from the first domain.
func slug(domains []string) string {
	return strings.ReplaceAll(domains[0], "*", "wildcard")
}

const specMark = "# apex-site "
const managedNote = "# Added in Apex Server Edition. Edit it in Apex: changes made here by hand are replaced."

func specLine(s SiteSpec) string {
	b, _ := json.Marshal(s)
	return specMark + string(b)
}

// readSpec: the site Apex wrote into a file, from its first line.
func readSpec(text string) *SiteSpec {
	first, _, _ := strings.Cut(text, "\n")
	if !strings.HasPrefix(first, specMark) {
		return nil
	}
	var s SiteSpec
	if json.Unmarshal([]byte(strings.TrimPrefix(first, specMark)), &s) != nil || len(s.Domains) == 0 {
		return nil
	}
	return &s
}

// MARK: Changing files, all or nothing

type fileState struct {
	exists bool
	link   string // a symlink's target
	data   []byte
	mode   os.FileMode
}

func stateOf(p string) fileState {
	if st, err := os.Lstat(p); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			t, _ := os.Readlink(p)
			return fileState{exists: true, link: t}
		}
		b, _ := os.ReadFile(p)
		return fileState{exists: true, data: b, mode: st.Mode().Perm()}
	}
	return fileState{}
}

func putState(p string, s fileState) error {
	os.Remove(p)
	switch {
	case !s.exists:
		return nil
	case s.link != "":
		return os.Symlink(s.link, p)
	default:
		return os.WriteFile(p, s.data, s.mode)
	}
}

// A planned change: each path's new state.
type edit struct {
	path  string
	state fileState
}

func writeFile(p, text string) edit {
	return edit{p, fileState{exists: true, data: []byte(text), mode: 0o644}}
}
func symlink(p, target string) edit { return edit{p, fileState{exists: true, link: target}} }
func removeFile(p string) edit      { return edit{p, fileState{}} }
func moveFile(from, to string) []edit {
	s := stateOf(from)
	return []edit{{to, s}, removeFile(from)}
}

var proxyLock sync.Mutex

// apply writes every edit, runs the proxy's check, then reloads it. If
// anything fails, every path is put back and the proxy reloaded as it was.
func apply(edits []edit, check func() error, reload func() error) error {
	before := map[string]fileState{}
	for _, e := range edits {
		if _, ok := before[e.path]; !ok {
			before[e.path] = stateOf(e.path)
		}
	}
	undo := func() {
		for p, s := range before {
			putState(p, s)
		}
	}
	for _, e := range edits {
		if err := os.MkdirAll(filepath.Dir(e.path), 0o755); err != nil {
			undo()
			return err
		}
		if err := putState(e.path, e.state); err != nil {
			undo()
			if errors.Is(err, syscall.EROFS) {
				return fmt.Errorf("Apex Server Edition isn't allowed to write %s. Allow its folder with `sudo systemctl edit apex-server` (add [Service] and ReadWritePaths=%s), then try again", filepath.Dir(e.path), filepath.Dir(e.path))
			}
			return err
		}
	}
	if err := check(); err != nil {
		undo()
		return fmt.Errorf("the proxy refused the change, so nothing was changed: %v", err)
	}
	if err := reload(); err != nil {
		undo()
		reload()
		return fmt.Errorf("the proxy didn't reload, so the change was undone: %v", err)
	}
	return nil
}

// MARK: The report

type proxyKind interface {
	info() ProxyInfo
	sites() []Site
	change(c ProxyChange, site *Site) error
}

func detectProxies() []proxyKind {
	var out []proxyKind
	if n := findNginx(); n != nil {
		out = append(out, n)
	}
	if c := findCaddy(); c != nil {
		out = append(out, c)
	}
	if t := findTraefik(); t != nil {
		out = append(out, t)
	}
	if p := findNPM(); p != nil {
		out = append(out, p)
	}
	return out
}

var (
	reportMu   sync.Mutex
	lastReport ProxyReport
	lastKinds  []proxyKind
)

// Proxies: the report, at most every 10 seconds (or now, after a change).
func Proxies(fresh bool) (ProxyReport, []proxyKind) {
	reportMu.Lock()
	defer reportMu.Unlock()
	if !fresh && time.Since(time.UnixMilli(lastReport.Taken)) < 10*time.Second {
		return lastReport, lastKinds
	}
	kinds := detectProxies()
	r := ProxyReport{Proxies: []ProxyInfo{}, Sites: []Site{}, Taken: time.Now().UnixMilli()}
	for _, k := range kinds {
		r.Proxies = append(r.Proxies, k.info())
		r.Sites = append(r.Sites, k.sites()...)
	}
	sort.SliceStable(r.Sites, func(i, j int) bool { return r.Sites[i].Domains[0] < r.Sites[j].Domains[0] })
	addTraffic(r.Sites, kinds)
	for i := range r.Sites {
		if r.Sites[i].HTTPS && r.Sites[i].Enabled {
			r.Sites[i].Cert = certFor(r.Sites[i].Domains)
		}
	}
	lastReport, lastKinds = r, kinds
	return r, kinds
}

func ProxyDo(c ProxyChange) error {
	proxyLock.Lock()
	defer proxyLock.Unlock()
	r, kinds := Proxies(true)
	for i, k := range kinds {
		if k.info().Kind != c.Proxy {
			continue
		}
		if !r.Proxies[i].Editable && c.Verb != "enable" && c.Verb != "disable" {
			return errors.New(r.Proxies[i].Note)
		}
		var site *Site
		if c.Verb != "add" {
			for j := range r.Sites {
				if r.Sites[j].ID == c.Site && r.Sites[j].Proxy == c.Proxy {
					site = &r.Sites[j]
				}
			}
			if site == nil {
				return errors.New("that site isn't there any more")
			}
			if (c.Verb == "enable" || c.Verb == "disable") && !site.CanToggle {
				return errors.New("Apex can't switch this site off and on; change it where it was set up")
			}
			if (c.Verb == "update" || c.Verb == "remove") && !site.Managed {
				return errors.New("only sites added in Apex can be edited here")
			}
		}
		if c.Verb == "add" || c.Verb == "update" {
			s, err := cleanSpec(c.Spec)
			if err != nil {
				return err
			}
			for _, other := range r.Sites {
				if other.Proxy == c.Proxy && (site == nil || other.ID != site.ID) && other.Enabled {
					for _, d := range other.Domains {
						for _, mine := range s.Domains {
							if d == mine {
								return fmt.Errorf("%s is already a site on %s", d, k.info().Name)
							}
						}
					}
				}
			}
			c.Spec = s
		}
		err := k.change(c, site)
		logChange(c, err)
		Proxies(true)
		return err
	}
	return errors.New("that proxy isn't on this server")
}

func logChange(c ProxyChange, err error) {
	what := c.Site
	if len(c.Spec.Domains) > 0 {
		what = strings.Join(c.Spec.Domains, ",") + " -> " + c.Spec.Upstream
	}
	log.Printf("proxy %s %s %s: %s", c.Proxy, c.Verb, what, errText(err))
	f, e := os.OpenFile(path("proxy-changes.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if e == nil {
		fmt.Fprintf(f, "%s %s %s %s: %s\n", time.Now().UTC().Format(time.RFC3339), c.Proxy, c.Verb, what, errText(err))
		f.Close()
	}
}

// MARK: Certificates

type certCache struct {
	at   time.Time
	info *CertInfo
}

var (
	certMu    sync.Mutex
	certSeen  = map[string]certCache{}
	certProbe = func(domain string) *CertInfo { // tests replace it
		d := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", "127.0.0.1:443", &tls.Config{ServerName: domain, InsecureSkipVerify: true})
		if err != nil {
			return &CertInfo{Problem: "No certificate answered on port 443."}
		}
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			return &CertInfo{Problem: "No certificate answered on port 443."}
		}
		c := certs[0]
		info := &CertInfo{Expires: c.NotAfter.Unix(), Issuer: c.Issuer.CommonName}
		if len(c.Issuer.Organization) > 0 {
			info.Issuer = c.Issuer.Organization[0]
		}
		if c.VerifyHostname(domain) != nil {
			info.Problem = "The certificate is for another name."
		}
		return info
	}
)

// certFor: the certificate the server hands out for the site's first plain domain.
func certFor(domains []string) *CertInfo {
	var d string
	for _, x := range domains {
		if !strings.Contains(x, "*") && x != "_" && x != "localhost" {
			d = x
			break
		}
	}
	if d == "" {
		return nil
	}
	certMu.Lock()
	c, ok := certSeen[d]
	certMu.Unlock()
	if ok && time.Since(c.at) < 10*time.Minute {
		return c.info
	}
	info := certProbe(d)
	certMu.Lock()
	certSeen[d] = certCache{time.Now(), info}
	certMu.Unlock()
	return info
}

// MARK: HTTP

func (s *Server) proxies(w http.ResponseWriter, r *http.Request) {
	rep, _ := Proxies(r.URL.Query().Get("fresh") == "1")
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) proxyChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var c ProxyChange
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&c) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Bad request."})
		return
	}
	log.Printf("proxy change from %s", clientIP(r))
	if err := ProxyDo(c); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": capitalize(strings.TrimSuffix(err.Error(), ".")) + "."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Done."})
}
