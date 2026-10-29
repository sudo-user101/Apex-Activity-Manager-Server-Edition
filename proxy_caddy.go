package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Caddy: what it serves now is read from its admin API (localhost:2019);
// without the API, from the Caddyfile. Apex's sites are files in
// /etc/caddy/apex/, brought in by one import line added to the Caddyfile.
// Caddy gets HTTPS certificates by itself.

var caddyRoot = "/etc/caddy" // tests

type caddyProxy struct {
	version  string
	running  bool
	config   map[string]any // from the admin API
	file     string         // the Caddyfile
	problem  string
	apexDir  string
	logFiles []string // shared JSON logs, from the API
}

func findCaddy() *caddyProxy {
	file := filepath.Join(caddyRoot, "Caddyfile")
	_, statErr := os.Stat(file)
	if !have("caddy") && statErr != nil {
		return nil
	}
	c := &caddyProxy{running: processRunning("caddy"), file: file, apexDir: filepath.Join(caddyRoot, "apex")}
	if out, err := run(5*time.Second, "caddy", "version"); err == nil {
		c.version = "Caddy " + strings.Fields(out + " ")[0]
	}
	if statErr != nil {
		c.problem = "Apex adds sites through the Caddyfile, and there isn't one at " + file + "."
	}
	cl := &http.Client{Timeout: 2 * time.Second}
	if r, err := cl.Get("http://127.0.0.1:2019/config/"); err == nil {
		json.NewDecoder(r.Body).Decode(&c.config)
		r.Body.Close()
	}
	return c
}

func (c *caddyProxy) info() ProxyInfo {
	i := ProxyInfo{Kind: "caddy", Name: "Caddy", Running: c.running, Editable: c.problem == "" && have("caddy"), Note: c.problem}
	if c.version != "" {
		i.Name = c.version
	}
	if !have("caddy") && i.Note == "" {
		i.Note = "Caddy runs in a container here; Apex changes Caddy only when it's installed on the server itself."
	}
	return i
}

func (c *caddyProxy) sites() []Site {
	var out []Site
	managed := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(c.apexDir, "*.caddy*"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		sp := readSpec(string(b))
		if err != nil || sp == nil {
			continue
		}
		on := strings.HasSuffix(f, ".caddy")
		s := Site{ID: "caddy:" + f, Proxy: "caddy", Domains: sp.Domains, Targets: []string{sp.Upstream}, HTTPS: sp.HTTPS,
			Enabled: on, Managed: true, CanToggle: true, File: f, Spec: sp, logs: []string{caddyLog(*sp)}}
		out = append(out, s)
		if on {
			for _, d := range sp.Domains {
				managed[d] = true
			}
		}
	}
	var others []Site
	if c.config != nil {
		others = caddySitesFromConfig(c.config)
		c.logFiles = caddyLogFiles(c.config)
	} else if b, err := os.ReadFile(c.file); err == nil {
		others = caddySitesFromFile(string(b))
	}
	for _, s := range others {
		if len(s.Domains) > 0 && managed[s.Domains[0]] {
			continue
		}
		s.Proxy, s.Enabled = "caddy", true
		s.ID = "caddy:" + strings.Join(s.Domains, " ")
		s.File = c.file
		out = append(out, s)
	}
	return out
}

// caddySitesFromConfig: each route with hosts, from Caddy's JSON config.
func caddySitesFromConfig(cfg map[string]any) []Site {
	var out []Site
	servers, _ := dig(cfg, "apps", "http", "servers").(map[string]any)
	for _, sv := range servers {
		srv, _ := sv.(map[string]any)
		https := true
		if listen, ok := srv["listen"].([]any); ok {
			https = false
			for _, l := range listen {
				if ls, _ := l.(string); strings.HasSuffix(ls, ":443") {
					https = true
				}
			}
		}
		routes, _ := srv["routes"].([]any)
		for _, r := range routes {
			route, _ := r.(map[string]any)
			var hosts []string
			matches, _ := route["match"].([]any)
			for _, m := range matches {
				if mm, ok := m.(map[string]any); ok {
					if hs, ok := mm["host"].([]any); ok {
						for _, h := range hs {
							if s, ok := h.(string); ok {
								hosts = append(hosts, strings.ToLower(s))
							}
						}
					}
				}
			}
			if len(hosts) == 0 {
				continue
			}
			s := Site{Domains: hosts, HTTPS: https, Targets: caddyTargets(route)}
			if len(s.Targets) == 0 {
				s.Targets = []string{}
			}
			out = append(out, s)
		}
	}
	return out
}

// caddyTargets: every reverse_proxy upstream and file_server root in a route.
func caddyTargets(v any) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		if h, _ := x["handler"].(string); h == "reverse_proxy" {
			if ups, ok := x["upstreams"].([]any); ok {
				for _, u := range ups {
					if um, ok := u.(map[string]any); ok {
						if d, ok := um["dial"].(string); ok {
							out = mergeStrings(out, []string{d})
						}
					}
				}
			}
		}
		if h, _ := x["handler"].(string); h == "file_server" {
			root, _ := x["root"].(string)
			out = mergeStrings(out, []string{strings.TrimSpace("Files " + root)})
		}
		if h, _ := x["handler"].(string); h == "static_response" {
			if hd, ok := x["headers"].(map[string]any); ok && hd["Location"] != nil {
				out = mergeStrings(out, []string{"Redirects"})
			}
		}
		for _, v := range x {
			out = mergeStrings(out, caddyTargets(v))
		}
	case []any:
		for _, v := range x {
			out = mergeStrings(out, caddyTargets(v))
		}
	}
	return out
}

// caddyLogFiles: the files Caddy's own logs are written to.
func caddyLogFiles(cfg map[string]any) []string {
	var out []string
	logs, _ := dig(cfg, "logging", "logs").(map[string]any)
	for _, l := range logs {
		if w, ok := dig(l, "writer").(map[string]any); ok {
			if f, ok := w["filename"].(string); ok {
				out = mergeStrings(out, []string{f})
			}
		}
	}
	return out
}

// caddySitesFromFile: site blocks from a Caddyfile (when the API is off).
func caddySitesFromFile(text string) []Site {
	var out []Site
	depth := 0
	var cur *Site
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if depth == 0 && strings.HasSuffix(line, "{") && line != "{" && !strings.HasPrefix(line, "(") {
			addr := strings.TrimSpace(strings.TrimSuffix(line, "{"))
			s := Site{Domains: []string{}, Targets: []string{}, HTTPS: true}
			for _, a := range strings.FieldsFunc(addr, func(r rune) bool { return r == ',' || r == ' ' }) {
				if strings.HasPrefix(a, "http://") || strings.HasSuffix(a, ":80") {
					s.HTTPS = false
				}
				a = strings.TrimPrefix(strings.TrimPrefix(a, "https://"), "http://")
				if h, _, ok := strings.Cut(a, ":"); ok {
					a = h
				}
				if a == "" {
					a = "(any name)"
				}
				s.Domains = append(s.Domains, strings.ToLower(a))
			}
			out = append(out, s)
			cur = &out[len(out)-1]
		} else if cur != nil && depth >= 1 {
			f := strings.Fields(line)
			if len(f) > 1 && f[0] == "reverse_proxy" {
				for _, t := range f[1:] {
					if t != "{" && !strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "*") {
						cur.Targets = mergeStrings(cur.Targets, []string{t})
					}
				}
			}
			if len(f) > 1 && f[0] == "root" {
				cur.Targets = mergeStrings(cur.Targets, []string{"Files in " + f[len(f)-1]})
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			depth, cur = 0, nil
		}
	}
	return out
}

func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func caddyLog(s SiteSpec) string { return "/var/log/caddy/apex-" + slug(s.Domains) + ".log" }

// caddyConfig: what Apex writes for a site.
func caddyConfig(s SiteSpec) string {
	addrs := make([]string, len(s.Domains))
	for i, d := range s.Domains {
		if s.HTTPS {
			addrs[i] = d
		} else {
			addrs[i] = "http://" + d
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n", specLine(s), managedNote)
	fmt.Fprintf(&b, "%s {\n\treverse_proxy %s\n", strings.Join(addrs, ", "), s.Upstream)
	fmt.Fprintf(&b, "\tlog {\n\t\toutput file %s\n\t\tformat json\n\t}\n}\n", caddyLog(s))
	return b.String()
}

func (c *caddyProxy) importLine() string { return "import " + filepath.Join(c.apexDir, "*.caddy") }

func (c *caddyProxy) change(ch ProxyChange, site *Site) error {
	check := func() error {
		out, err := combined(30*time.Second, "caddy", "validate", "--config", c.file, "--adapter", "caddyfile")
		if err != nil {
			return errors.New(lastLine(out))
		}
		return nil
	}
	reload := func() error {
		if !c.running {
			return nil
		}
		out, err := combined(30*time.Second, "caddy", "reload", "--config", c.file, "--adapter", "caddyfile")
		if err == nil {
			return nil
		}
		if _, e := run(30*time.Second, "systemctl", "reload", "caddy"); e == nil {
			return nil
		}
		return errors.New(lastLine(out))
	}
	var edits []edit
	main := stateOf(c.file)
	if !strings.Contains(string(main.data), c.importLine()) {
		text := strings.TrimRight(string(main.data), "\n") + "\n\n# Sites added in Apex\n" + c.importLine() + "\n"
		edits = append(edits, edit{c.file, fileState{exists: true, data: []byte(text), mode: main.mode}})
	}
	switch ch.Verb {
	case "add", "update":
		file := filepath.Join(c.apexDir, "apex-"+slug(ch.Spec.Domains)+".caddy")
		if site != nil && site.File != file {
			edits = append(edits, removeFile(site.File))
		}
		edits = append(edits, writeFile(file, caddyConfig(ch.Spec)))
		caddyLogDir()
	case "remove":
		edits = append(edits, removeFile(site.File))
	case "disable":
		edits = append(edits, moveFile(site.File, site.File+".off")...)
	case "enable":
		edits = append(edits, moveFile(site.File, strings.TrimSuffix(site.File, ".off"))...)
	default:
		return errors.New("unknown change")
	}
	return apply(edits, check, reload)
}

// caddyLogDir: Caddy runs as its own user and must be able to write the log.
func caddyLogDir() {
	dir := "/var/log/caddy"
	if _, err := os.Stat(dir); err == nil {
		return
	}
	os.MkdirAll(dir, 0o755)
	if u, err := user.Lookup("caddy"); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		os.Chown(dir, uid, gid)
	}
}
