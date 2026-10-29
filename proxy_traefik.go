package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Traefik and Nginx Proxy Manager, installed on the server or (usually) in
// Docker. Traefik is read from its API; Apex's sites are files for its file
// provider, and each change is checked by asking the API whether Traefik
// took the new router. Nginx Proxy Manager keeps its sites in its own
// database, so Apex shows them and their traffic, and edits stay in its page.

// MARK: Containers

type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Args   []string
	Config struct {
		Image string   `json:"Image"`
		Cmd   []string `json:"Cmd"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports    map[string][]struct{ HostPort string } `json:"Ports"`
		Networks map[string]struct{ IPAddress string }  `json:"Networks"`
	} `json:"NetworkSettings"`
}

// containersWith: running and stopped containers whose image contains one of the words.
func containersWith(words ...string) []dockerInspect {
	sock := containerSocket()
	if sock == "" {
		return nil
	}
	cl := dockerClient(sock, 3*time.Second)
	r, err := cl.Get("http://docker/containers/json?all=1")
	if err != nil {
		return nil
	}
	var list []dockerContainer
	json.NewDecoder(r.Body).Decode(&list)
	r.Body.Close()
	var out []dockerInspect
	for _, c := range list {
		img := strings.ToLower(c.Image)
		for _, w := range words {
			if strings.Contains(img, w) {
				if r, err := cl.Get("http://docker/containers/" + c.ID + "/json"); err == nil {
					var d dockerInspect
					json.NewDecoder(r.Body).Decode(&d)
					r.Body.Close()
					out = append(out, d)
				}
				break
			}
		}
	}
	return out
}

// hostPath: where a path inside the container is on the server.
func (d dockerInspect) hostPath(p string) string {
	best := ""
	src := ""
	for _, m := range d.Mounts {
		if (p == m.Destination || strings.HasPrefix(p, strings.TrimSuffix(m.Destination, "/")+"/")) && len(m.Destination) > len(best) {
			best, src = m.Destination, m.Source
		}
	}
	if best == "" {
		return ""
	}
	return filepath.Join(src, strings.TrimPrefix(p, best))
}

func (d dockerInspect) ip() string {
	for _, n := range d.NetworkSettings.Networks {
		if n.IPAddress != "" {
			return n.IPAddress
		}
	}
	return ""
}

func (d dockerInspect) hostPort(container string) string {
	for _, b := range d.NetworkSettings.Ports[container+"/tcp"] {
		if b.HostPort != "" {
			return b.HostPort
		}
	}
	return ""
}

// MARK: Traefik

type traefikProxy struct {
	running   bool
	version   string
	api       string // base URL of the API
	routers   []traefikRouter
	services  map[string][]string
	dir       string // the file provider's directory, on the server
	resolver  string // a certificate resolver, for HTTPS
	accessLog string
	inDocker  bool
}

type traefikRouter struct {
	Name     string   `json:"name"`
	Rule     string   `json:"rule"`
	Service  string   `json:"service"`
	Status   string   `json:"status"`
	Provider string   `json:"provider"`
	Error    []string `json:"error"`
	TLS      any      `json:"tls"`
}

func findTraefik() *traefikProxy {
	t := &traefikProxy{services: map[string][]string{}}
	var args []string
	var static string
	bases := []string{"http://127.0.0.1:8080"}
	if have("traefik") || processRunning("traefik") {
		t.running = processRunning("traefik")
		for _, f := range []string{"/etc/traefik/traefik.yml", "/etc/traefik/traefik.yaml"} {
			if b, err := os.ReadFile(f); err == nil {
				static = string(b)
				break
			}
		}
		t.dir = yamlValue(static, "providers", "file", "directory")
		t.accessLog = yamlValue(static, "accessLog", "filePath")
	} else if cs := containersWith("traefik"); len(cs) > 0 {
		c := cs[0]
		t.inDocker, t.running = true, c.State.Running
		args = append(c.Args, c.Config.Cmd...)
		for _, cfg := range []string{"/etc/traefik/traefik.yml", "/etc/traefik/traefik.yaml", "/traefik.yml"} {
			if hp := c.hostPath(cfg); hp != "" {
				if b, err := os.ReadFile(hp); err == nil {
					static = string(b)
					break
				}
			}
		}
		if d := argValue(args, "--providers.file.directory"); d != "" {
			t.dir = c.hostPath(d)
		} else if d := yamlValue(static, "providers", "file", "directory"); d != "" {
			t.dir = c.hostPath(d)
		}
		if l := argValue(args, "--accesslog.filepath"); l != "" {
			t.accessLog = c.hostPath(l)
		} else if l := yamlValue(static, "accessLog", "filePath"); l != "" {
			t.accessLog = c.hostPath(l)
		}
		if p := c.hostPort("8080"); p != "" {
			bases = append([]string{"http://127.0.0.1:" + p}, bases...)
		}
		if ip := c.ip(); ip != "" {
			bases = append(bases, "http://"+ip+":8080")
		}
	} else {
		return nil
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--certificatesresolvers.") {
			t.resolver = strings.SplitN(strings.TrimPrefix(a, "--certificatesresolvers."), ".", 2)[0]
			break
		}
	}
	if t.resolver == "" {
		t.resolver = firstChild(static, "certificatesResolvers")
	}
	cl := &http.Client{Timeout: 2 * time.Second}
	for _, b := range bases {
		if r, err := cl.Get(b + "/api/version"); err == nil {
			var v struct{ Version string }
			json.NewDecoder(r.Body).Decode(&v)
			r.Body.Close()
			if r.StatusCode == 200 {
				t.api, t.version = b, v.Version
				break
			}
		}
	}
	t.load()
	return t
}

func (t *traefikProxy) load() {
	if t.api == "" {
		return
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	if r, err := cl.Get(t.api + "/api/http/routers?per_page=1000"); err == nil {
		json.NewDecoder(r.Body).Decode(&t.routers)
		r.Body.Close()
	}
	var svcs []struct {
		Name         string `json:"name"`
		LoadBalancer struct {
			Servers []struct{ URL string } `json:"servers"`
		} `json:"loadBalancer"`
	}
	if r, err := cl.Get(t.api + "/api/http/services?per_page=1000"); err == nil {
		json.NewDecoder(r.Body).Decode(&svcs)
		r.Body.Close()
	}
	for _, s := range svcs {
		for _, u := range s.LoadBalancer.Servers {
			t.services[s.Name] = append(t.services[s.Name], u.URL)
		}
	}
}

func (t *traefikProxy) info() ProxyInfo {
	i := ProxyInfo{Kind: "traefik", Name: "Traefik", Running: t.running}
	if t.version != "" {
		i.Name = "Traefik " + t.version
	}
	switch {
	case t.api == "":
		i.Note = "Switch on Traefik's API (api.insecure, port 8080, reachable from the server) so Apex can see its sites and check each change."
	case t.dir == "":
		i.Note = "Traefik has no file provider directory, so Apex can only show its sites. Add providers.file.directory (and watch) to let Apex add sites."
	default:
		i.Editable = true
	}
	return i
}

var hostRuleRE = regexp.MustCompile("Host(?:SNI)?\\(([^)]*)\\)")

func ruleDomains(rule string) []string {
	var out []string
	for _, m := range hostRuleRE.FindAllStringSubmatch(rule, -1) {
		for _, h := range strings.Split(m[1], ",") {
			h = strings.ToLower(strings.Trim(strings.TrimSpace(h), "`\"'"))
			if h != "" {
				out = mergeStrings(out, []string{h})
			}
		}
	}
	return out
}

func (t *traefikProxy) sites() []Site {
	var out []Site
	managed := map[string]bool{}
	if t.dir != "" {
		files, _ := filepath.Glob(filepath.Join(t.dir, "apex-*.yml*"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			sp := readSpec(string(b))
			if err != nil || sp == nil {
				continue
			}
			on := strings.HasSuffix(f, ".yml")
			name := "apex-" + routerSlug(*sp)
			managed[name+"@file"] = true
			out = append(out, Site{ID: "traefik:" + f, Proxy: "traefik", Domains: sp.Domains, Targets: []string{sp.Upstream},
				HTTPS: sp.HTTPS, Enabled: on, Managed: true, CanToggle: true, File: f, Spec: sp, router: name + "@file"})
		}
	}
	for _, r := range t.routers {
		if managed[r.Name] || strings.HasSuffix(r.Name, "@internal") {
			continue
		}
		d := ruleDomains(r.Rule)
		if len(d) == 0 {
			continue
		}
		svc := r.Service
		if !strings.Contains(svc, "@") {
			if _, p, ok := strings.Cut(r.Name, "@"); ok {
				svc += "@" + p
			}
		}
		targets := t.services[svc]
		if targets == nil {
			targets = []string{}
		}
		out = append(out, Site{ID: "traefik:" + r.Name, Proxy: "traefik", Domains: d, Targets: targets,
			HTTPS: r.TLS != nil, Enabled: r.Status == "enabled", File: r.Provider, router: r.Name})
	}
	return out
}

func routerSlug(s SiteSpec) string {
	return regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(slug(s.Domains), "-")
}

// traefikConfig: what Apex writes for a site (dynamic configuration, YAML).
func traefikConfig(s SiteSpec, resolver string) string {
	name := "apex-" + routerSlug(s)
	rules := make([]string, len(s.Domains))
	for i, d := range s.Domains {
		if strings.HasPrefix(d, "*.") {
			rules[i] = "HostRegexp(`^[^.]+\\." + regexp.QuoteMeta(strings.TrimPrefix(d, "*.")) + "$`)"
		} else {
			rules[i] = "Host(`" + d + "`)"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\nhttp:\n  routers:\n    %s:\n", specLine(s), managedNote, name)
	fmt.Fprintf(&b, "      rule: %q\n      service: %s\n", strings.Join(rules, " || "), name)
	if s.HTTPS {
		if resolver != "" {
			fmt.Fprintf(&b, "      tls:\n        certResolver: %s\n", resolver)
		} else {
			b.WriteString("      tls: {}\n")
		}
	}
	fmt.Fprintf(&b, "  services:\n    %s:\n      loadBalancer:\n        servers:\n          - url: %q\n", name, s.Upstream)
	return b.String()
}

func (t *traefikProxy) change(c ProxyChange, site *Site) error {
	var edits []edit
	var want, gone, wantURL string // the router that must appear (forwarding to wantURL), or go
	switch c.Verb {
	case "add", "update":
		file := filepath.Join(t.dir, "apex-"+slug(c.Spec.Domains)+".yml")
		if site != nil && site.File != file {
			edits = append(edits, removeFile(site.File))
		}
		edits = append(edits, writeFile(file, traefikConfig(c.Spec, t.resolver)))
		want, wantURL = "apex-"+routerSlug(c.Spec)+"@file", c.Spec.Upstream
	case "remove":
		edits = []edit{removeFile(site.File)}
		if site.Enabled {
			gone = site.router
		}
	case "disable":
		edits = moveFile(site.File, site.File+".off")
		gone = site.router
	case "enable":
		edits = moveFile(site.File, strings.TrimSuffix(site.File, ".off"))
		want = site.router
	default:
		return errors.New("unknown change")
	}
	// Traefik reads the folder by itself; the check waits for its answer.
	check := func() error {
		cl := &http.Client{Timeout: 2 * time.Second}
		if gone != "" {
			for i := 0; i < 20; i++ {
				time.Sleep(500 * time.Millisecond)
				if r, err := cl.Get(t.api + "/api/http/routers/" + gone); err == nil {
					r.Body.Close()
					if r.StatusCode == http.StatusNotFound {
						return nil
					}
				}
			}
			return errors.New("Traefik still had the site after 10 seconds (is the file provider watching its folder?)")
		}
		if want == "" {
			return nil
		}
		for i := 0; i < 20; i++ {
			time.Sleep(500 * time.Millisecond)
			r, err := cl.Get(t.api + "/api/http/routers/" + want)
			if err != nil {
				continue
			}
			var rt traefikRouter
			json.NewDecoder(r.Body).Decode(&rt)
			r.Body.Close()
			if r.StatusCode == 200 && rt.Status == "enabled" && (wantURL == "" || t.serviceIs(cl, want, wantURL)) {
				return nil
			}
			if r.StatusCode == 200 && len(rt.Error) > 0 {
				return errors.New(strings.Join(rt.Error, "; "))
			}
		}
		return errors.New("Traefik didn't pick up the site within 10 seconds (is the file provider watching its folder?)")
	}
	return apply(edits, check, func() error { return nil })
}

// serviceIs: the router's service forwards to url now.
func (t *traefikProxy) serviceIs(cl *http.Client, router, url string) bool {
	r, err := cl.Get(t.api + "/api/http/services/" + router)
	if err != nil {
		return false
	}
	defer r.Body.Close()
	var svc struct {
		LoadBalancer struct {
			Servers []struct{ URL string } `json:"servers"`
		} `json:"loadBalancer"`
	}
	json.NewDecoder(r.Body).Decode(&svc)
	for _, s := range svc.LoadBalancer.Servers {
		if strings.TrimSuffix(s.URL, "/") == url {
			return true
		}
	}
	return false
}

// MARK: Nginx Proxy Manager

type npmProxy struct {
	running bool
	data    string // its /data folder, on the server
	admin   string
}

func findNPM() *npmProxy {
	cs := containersWith("nginx-proxy-manager")
	if len(cs) == 0 {
		return nil
	}
	c := cs[0]
	p := &npmProxy{running: c.State.Running, data: c.hostPath("/data")}
	if port := c.hostPort("81"); port != "" {
		p.admin = port
	}
	return p
}

func (p *npmProxy) info() ProxyInfo {
	i := ProxyInfo{Kind: "npm", Name: "Nginx Proxy Manager", Running: p.running,
		Note: "Nginx Proxy Manager keeps its sites in its own database: change them on its page. Apex shows each one and its traffic."}
	if p.admin != "" {
		i.Admin = p.admin
	}
	return i
}

var npmNumberRE = regexp.MustCompile(`^(\d+)\.conf$`)

func (p *npmProxy) sites() []Site {
	if p.data == "" {
		return nil
	}
	var out []Site
	files, _ := filepath.Glob(filepath.Join(p.data, "nginx", "proxy_host", "*.conf"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, s := range ngxSites(f, string(b), true) {
			s.Proxy, s.ID = "npm", "npm:"+f
			s.logs = nil
			if m := npmNumberRE.FindStringSubmatch(filepath.Base(f)); m != nil {
				s.logs = []string{filepath.Join(p.data, "logs", "proxy-host-"+m[1]+"_access.log")}
			}
			out = append(out, s)
		}
	}
	return out
}

func (p *npmProxy) change(ProxyChange, *Site) error {
	return errors.New("change Nginx Proxy Manager's sites on its own page")
}

// MARK: Reading a little YAML

// yamlValue: a nested key's value from simple YAML (two-space or any
// consistent indent), enough for Traefik's static configuration.
func yamlValue(text string, keys ...string) string {
	level, indent := 0, -1
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		ind := len(line) - len(strings.TrimLeft(line, " "))
		if level > 0 && ind <= indent {
			return ""
		}
		k, v, ok := strings.Cut(trim, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), keys[level]) {
			continue
		}
		if level == len(keys)-1 {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
		level, indent = level+1, ind
	}
	return ""
}

// firstChild: the first key under a top-level key.
func firstChild(text, key string) string {
	in := false
	for _, raw := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if !strings.HasPrefix(raw, " ") {
			in = strings.HasPrefix(trim, key+":")
			continue
		}
		if in {
			k, _, _ := strings.Cut(trim, ":")
			return strings.TrimSpace(k)
		}
	}
	return ""
}

func argValue(args []string, name string) string {
	for _, a := range args {
		if strings.HasPrefix(strings.ToLower(a), name+"=") {
			return a[len(name)+1:]
		}
	}
	return ""
}
