package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Apps: detect known software on the server — WordPress, databases, Node
// apps, etc. — and group every instance by its kind, with the domains it
// serves (matched from the reverse proxy report). The Mac app shows this
// as a catalog; nothing here changes anything.

type AppsReport struct {
	Apps  []AppGroup `json:"apps"`
	Taken int64      `json:"taken"` // Unix ms
}

type AppGroup struct {
	Kind      string    `json:"kind"`      // wordpress, mysql, postgres, redis, mongodb, node, ghost, nextcloud, gitea…
	Label     string    `json:"label"`     // "WordPress", "MySQL", …
	Instances []AppInst `json:"instances"` // at least one
}

type AppInst struct {
	Name    string   `json:"name"`              // the container's name, the site's folder, the service
	Source  string   `json:"source"`            // docker, native
	Details string   `json:"details,omitempty"` // image, version, folder
	Domains []string `json:"domains,omitempty"` // matched from Sites
	Stopped bool     `json:"stopped,omitempty"` // a container that isn't running
	ends    []endpoint
	docRoot string
}

// endpoint: where a proxy can reach an instance. An empty host means this
// server itself (loopback, any of its addresses, the Docker gateway).
type endpoint struct{ host, port string }

// webApps: Docker images Apex knows, and the port each serves its site on
// inside the container ("" = any published port).
var webApps = []struct{ word, kind, label, port string }{
	{"wordpress", "wordpress", "WordPress", "80"},
	{"ghost", "ghost", "Ghost", "2368"},
	{"nextcloud", "nextcloud", "Nextcloud", "80"},
	{"gitea", "gitea", "Gitea", "3000"},
	{"forgejo", "gitea", "Gitea", "3000"},
	{"minio", "minio", "MinIO", ""},
	{"grafana", "grafana", "Grafana", "3000"},
}

var databases = []struct{ word, kind, label string }{
	{"mariadb", "mariadb", "MariaDB"},
	{"mysql", "mysql", "MySQL"},
	{"postgres", "postgres", "PostgreSQL"},
	{"redis", "redis", "Redis"},
	{"mongo", "mongodb", "MongoDB"},
}

// AppsDo: build the report. Sites are read to match apps to domains.
func AppsDo(stats []Container) AppsReport {
	sites, _ := Proxies(false)
	docker := DockerList(stats)

	groups := map[string]*AppGroup{}
	add := func(kind, label string, inst AppInst) {
		g, ok := groups[kind]
		if !ok {
			g = &AppGroup{Kind: kind, Label: label}
			groups[kind] = g
		}
		g.Instances = append(g.Instances, inst)
	}

	for _, c := range docker.Containers {
		if kind, label, port, ok := classifyImage(c.Image); ok {
			inst := AppInst{Name: c.Name, Source: "docker", Details: c.Image, Stopped: c.State != "running"}
			inst.ends = containerEndpoints(c.Name, c.Service, c.Ports, port)
			add(kind, label, inst)
		}
	}

	for _, inst := range findNativeWordPress() {
		add("wordpress", "WordPress", inst)
	}

	svcs, _ := listServices()
	for _, s := range svcs {
		if s.Active != "active" {
			continue
		}
		var kind, label, bin string
		switch s.Name {
		case "mysql", "mysqld":
			kind, label, bin = "mysql", "MySQL", "mysql"
		case "mariadb":
			kind, label, bin = "mariadb", "MariaDB", "mysql"
		case "postgresql", "postgres":
			kind, label, bin = "postgres", "PostgreSQL", "psql"
		case "redis", "redis-server":
			kind, label, bin = "redis", "Redis", "redis-server"
		case "mongod":
			kind, label, bin = "mongodb", "MongoDB", "mongod"
		default:
			continue
		}
		if !hasKindSource(groups, kind, "native") {
			add(kind, label, AppInst{Name: s.Name, Source: "native", Details: serviceVersion(bin, "--version")})
		}
	}

	matchDomains(groups, sites.Sites, localAddrs())

	out := []AppGroup{}
	for _, g := range groups {
		out = append(out, *g)
	}
	sortApps(out)
	return AppsReport{Apps: out, Taken: time.Now().UnixMilli()}
}

// classifyImage: what a Docker image is, and its site's port. Pure: tested.
func classifyImage(image string) (kind, label, port string, ok bool) {
	img := strings.ToLower(image)
	for _, p := range imageParts(img) {
		if tools[p] {
			return "", "", "", false
		}
	}
	for _, w := range webApps {
		if hasImage(img, w.word) {
			return w.kind, w.label, w.port, true
		}
	}
	for _, d := range databases {
		if hasImage(img, d.word) {
			return d.kind, d.label, "", true
		}
	}
	// Plain Node images only, not every app built on Node.
	if img == "node" || strings.HasPrefix(img, "node:") || strings.HasPrefix(img, "library/node:") {
		return "node", "Node.js", "", true
	}
	return "", "", "", false
}

// sortApps: sites and web apps first, then databases and the rest, each by name. Pure: tested.
func sortApps(out []AppGroup) {
	sort.Slice(out, func(i, j int) bool {
		if a, b := supporting[out[i].Kind], supporting[out[j].Kind]; a != b {
			return b
		}
		return out[i].Label < out[j].Label
	})
}

// supporting: services other apps use, listed after the sites and apps.
var supporting = map[string]bool{"mysql": true, "mariadb": true, "postgres": true, "redis": true, "mongodb": true, "minio": true}

// hasImage: a part of the image's name (split at / : - _ .) is the word:
// "wordpress", "bitnami/wordpress:6", "jc21/mariadb-aria". Pure: tested.
func hasImage(img, word string) bool {
	for _, p := range imageParts(img) {
		if p == word {
			return true
		}
	}
	return false
}

func imageParts(img string) []string {
	return strings.FieldsFunc(img, func(r rune) bool { return r == '/' || r == ':' || r == '-' || r == '_' || r == '.' })
}

// tools: images named after a database that are something else (admin pages, metrics).
var tools = map[string]bool{"exporter": true, "express": true, "commander": true, "insight": true, "admin": true, "backup": true, "cli": true}

// containerEndpoints: a container is reached on its published ports from
// the server itself, or by its name (or compose service) on its own port
// from a proxy on the same Docker network. port "" = any. Pure: tested.
func containerEndpoints(name, service string, ports []string, port string) []endpoint {
	var out []endpoint
	privs := map[string]bool{}
	for _, p := range ports { // "8080→80/tcp" or "127.0.0.1:8080→80/tcp"
		pub, priv, ok := strings.Cut(p, "→")
		if !ok {
			continue
		}
		if i := strings.LastIndex(pub, ":"); i >= 0 {
			pub = pub[i+1:]
		}
		priv = strings.SplitN(priv, "/", 2)[0]
		if port != "" && priv != port {
			continue
		}
		out = append(out, endpoint{"", pub})
		privs[priv] = true
	}
	if port != "" {
		privs[port] = true
	}
	for priv := range privs {
		for _, h := range []string{name, service} {
			if h != "" {
				out = append(out, endpoint{strings.ToLower(h), priv})
			}
		}
	}
	return out
}

// parseTarget: host and port from a proxy's target ("http://127.0.0.1:8080/",
// "localhost:3001", "https://wordpress", "[::1]:80"). Pure: tested.
func parseTarget(t string) (host, port string, ok bool) {
	t = strings.TrimSpace(t)
	if t == "" || strings.Contains(t, " ") {
		return "", "", false
	}
	scheme := "http"
	if s, rest, found := strings.Cut(t, "://"); found {
		scheme, t = strings.ToLower(s), rest
	}
	if i := strings.IndexAny(t, "/?"); i >= 0 {
		t = t[:i]
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		return strings.ToLower(h), p, true
	}
	if scheme == "https" {
		return strings.ToLower(strings.Trim(t, "[]")), "443", true
	}
	return strings.ToLower(strings.Trim(t, "[]")), "80", true
}

// localAddrs: names and addresses that mean "this server" to a proxy on it.
func localAddrs() map[string]bool {
	out := map[string]bool{"127.0.0.1": true, "localhost": true, "0.0.0.0": true, "::1": true, "::": true, "host.docker.internal": true}
	if as, err := net.InterfaceAddrs(); err == nil { // includes docker0 and bridge gateways
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok {
				out[ipn.IP.String()] = true
			}
		}
	}
	if h, err := os.Hostname(); err == nil {
		out[strings.ToLower(h)] = true
	}
	return out
}

// reaches: does a proxy target lead to this instance? Pure: tested.
func reaches(inst AppInst, target string, local map[string]bool) bool {
	if inst.docRoot != "" {
		if dir, ok := strings.CutPrefix(target, "Files in "); ok {
			dir = strings.TrimSuffix(dir, "/")
			if dir == inst.docRoot || strings.HasPrefix(inst.docRoot, dir+"/") || strings.HasPrefix(dir, inst.docRoot+"/") {
				return true
			}
		}
	}
	host, port, ok := parseTarget(target)
	if !ok {
		return false
	}
	for _, e := range inst.ends {
		if e.port != port {
			continue
		}
		if (e.host == "" && local[host]) || (e.host != "" && e.host == host) {
			return true
		}
	}
	return false
}

func matchDomains(groups map[string]*AppGroup, sites []Site, local map[string]bool) {
	for _, g := range groups {
		for i := range g.Instances {
			inst := &g.Instances[i]
			for _, s := range sites {
				if !s.Enabled {
					continue
				}
				for _, t := range s.Targets {
					if reaches(*inst, t, local) {
						inst.Domains = mergeStrings(inst.Domains, s.Domains)
					}
				}
			}
		}
	}
}

// findNativeWordPress: WordPress sites installed on the server itself
// (wp-config.php in the usual web folders, a few levels down).
var wpSearchDirs = []string{"/var/www", "/srv", "/home", "/opt", "/usr/share/nginx"}

var wpVersionRe = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)

func findNativeWordPress() []AppInst {
	var out []AppInst
	seen := map[string]bool{}
	for _, root := range wpSearchDirs {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				// Not too deep, and not into Docker's own data or code folders.
				if strings.Count(strings.TrimPrefix(p, root), "/") > 5 || p == "/var/lib/docker" ||
					d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "wp-content" {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() != "wp-config.php" {
				return nil
			}
			dir := filepath.Dir(p)
			if seen[dir] || !fileExists(filepath.Join(dir, "wp-includes", "version.php")) {
				return nil // a config without WordPress beside it (a backup, a container's volume being set up)
			}
			seen[dir] = true
			inst := AppInst{Name: filepath.Base(dir), Source: "native", Details: dir, docRoot: dir}
			if b, err := os.ReadFile(filepath.Join(dir, "wp-includes", "version.php")); err == nil {
				if m := wpVersionRe.FindSubmatch(b); m != nil {
					inst.Details = fmt.Sprintf("WordPress %s · %s", m[1], dir)
				}
			}
			out = append(out, inst)
			return nil
		})
	}
	return out
}

func serviceVersion(bin string, arg string) string {
	if !have(bin) {
		return ""
	}
	out, err := run(5*time.Second, bin, arg)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}

func hasKindSource(groups map[string]*AppGroup, kind, source string) bool {
	if g, ok := groups[kind]; ok {
		for _, inst := range g.Instances {
			if inst.Source == source {
				return true
			}
		}
	}
	return false
}

// MARK: HTTP

func (s *Server) apps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, AppsDo(s.collector.Latest().Containers))
}

// MARK: CLI

func appsCLI() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(AppsDo(listContainers()))
}
