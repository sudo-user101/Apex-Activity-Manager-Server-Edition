package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// nginx: read with `nginx -T` (the whole configuration, every include, the
// way nginx itself reads it). Apex's sites go in their own files: on Debian
// and Ubuntu sites-available + a link in sites-enabled, elsewhere conf.d.

// MARK: Reading nginx's configuration

type ngxDirective struct {
	name  string
	args  []string
	block []ngxDirective // nil: no block
}

// parseNginx: directives and blocks, with comments and quotes handled.
func parseNginx(text string) []ngxDirective {
	toks := ngxTokens(text)
	i := 0
	var parse func() []ngxDirective
	parse = func() []ngxDirective {
		var out []ngxDirective
		var cur []string
		for i < len(toks) {
			t := toks[i]
			i++
			switch t {
			case ";":
				if len(cur) > 0 {
					out = append(out, ngxDirective{name: cur[0], args: cur[1:]})
				}
				cur = nil
			case "{":
				d := ngxDirective{block: []ngxDirective{}}
				if len(cur) > 0 {
					d.name, d.args = cur[0], cur[1:]
				}
				d.block = parse()
				out = append(out, d)
				cur = nil
			case "}":
				return out
			default:
				cur = append(cur, t)
			}
		}
		return out
	}
	return parse()
}

func ngxTokens(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '#' && b.Len() == 0:
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			q := c
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
				i++
			}
			out = append(out, b.String())
			b.Reset()
		case c == ';' || c == '{' || c == '}':
			flush()
			out = append(out, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}

// splitDump: `nginx -T` output, file by file.
func splitDump(dump string) map[string]string {
	files := map[string]string{}
	var name string
	var b strings.Builder
	for _, line := range strings.SplitAfter(dump, "\n") {
		if strings.HasPrefix(line, "# configuration file ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			if name != "" {
				files[name] = b.String()
			}
			name = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "# configuration file ")), ":")
			b.Reset()
			continue
		}
		if name != "" {
			b.WriteString(line)
		}
	}
	if name != "" {
		files[name] = b.String()
	}
	return files
}

// ngxSites: the server blocks in one file, merged by name (the port 80
// redirect and the 443 site of one domain are one site).
func ngxSites(file, text string, enabled bool) []Site {
	var out []Site
	byName := map[string]int{}
	var walk func(ds []ngxDirective, inStream bool)
	walk = func(ds []ngxDirective, inStream bool) {
		for _, d := range ds {
			if d.block == nil {
				continue
			}
			switch d.name {
			case "stream", "upstream", "map", "types", "geo", "events":
				continue
			case "server":
				if inStream {
					continue
				}
				s := ngxSite(d)
				key := strings.Join(s.Domains, " ")
				if j, ok := byName[key]; ok {
					o := &out[j]
					o.HTTPS = o.HTTPS || s.HTTPS
					o.Targets = mergeStrings(o.Targets, s.Targets)
					o.logs = mergeStrings(o.logs, s.logs)
					continue
				}
				s.Proxy, s.File, s.Enabled = "nginx", file, enabled
				s.ID = "nginx:" + file + "#" + key
				byName[key] = len(out)
				out = append(out, s)
			default:
				walk(d.block, inStream)
			}
		}
	}
	walk(parseNginx(text), false)
	for i := range out {
		if len(out[i].Targets) > 1 {
			out[i].Targets = without(out[i].Targets, "Redirects to HTTPS")
		}
	}
	return out
}

func ngxSite(server ngxDirective) Site {
	s := Site{Domains: []string{}, Targets: []string{}}
	vars := map[string]string{}
	var walk func(ds []ngxDirective, inLocation bool)
	walk = func(ds []ngxDirective, inLocation bool) {
		for _, d := range ds {
			switch d.name {
			case "server_name":
				for _, a := range d.args {
					if a == "_" || a == "\"\"" || a == "" {
						a = "(any name)"
					}
					s.Domains = mergeStrings(s.Domains, []string{strings.ToLower(a)})
				}
			case "listen":
				for _, a := range d.args {
					if a == "ssl" || strings.HasSuffix(a, ":443") || a == "443" {
						s.HTTPS = true
					}
				}
			case "set":
				if len(d.args) == 2 {
					vars[d.args[0]] = d.args[1]
				}
			case "proxy_pass", "fastcgi_pass", "uwsgi_pass", "grpc_pass":
				if len(d.args) > 0 {
					t := d.args[0]
					for k, v := range vars {
						t = strings.ReplaceAll(t, k, v)
					}
					s.Targets = mergeStrings(s.Targets, []string{t})
				}
			case "root":
				if len(d.args) > 0 && !inLocation {
					s.Targets = mergeStrings(s.Targets, []string{"Files in " + d.args[0]})
				}
			case "return":
				if len(d.args) > 1 && strings.HasPrefix(d.args[1], "https://") {
					s.Targets = mergeStrings(s.Targets, []string{"Redirects to HTTPS"})
				}
			case "access_log":
				if len(d.args) > 0 && d.args[0] != "off" && !strings.HasPrefix(d.args[0], "syslog:") {
					s.logs = mergeStrings(s.logs, []string{d.args[0]})
				}
			}
			if d.block != nil && d.name != "if" {
				walk(d.block, inLocation || d.name == "location")
			}
		}
	}
	walk(server.block, false)
	// Nginx Proxy Manager: the address is in variables, and proxy_pass comes
	// from a shared include (proxy_pass $forward_scheme://$server:$port).
	if host := vars["$server"]; host != "" && !hasProxyTarget(s.Targets) {
		scheme := vars["$forward_scheme"]
		if scheme == "" {
			scheme = "http"
		}
		t := scheme + "://" + host
		if p := vars["$port"]; p != "" {
			t += ":" + p
		}
		s.Targets = append([]string{t}, s.Targets...)
	}
	if len(s.Domains) == 0 {
		s.Domains = []string{"(any name)"}
	}
	return s
}

func hasProxyTarget(t []string) bool {
	for _, x := range t {
		if strings.Contains(x, "://") {
			return true
		}
	}
	return false
}

func mergeStrings(a, b []string) []string {
	for _, x := range b {
		found := false
		for _, y := range a {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			a = append(a, x)
		}
	}
	return a
}

func without(a []string, x string) []string {
	var out []string
	for _, y := range a {
		if y != x {
			out = append(out, y)
		}
	}
	return out
}

// onlyServers: a file holding nothing but server blocks (and comments), so
// switching the whole file off takes nothing else with it.
func onlyServers(text string) bool {
	ds := parseNginx(text)
	for _, d := range ds {
		if d.name != "server" || d.block == nil {
			return false
		}
	}
	return len(ds) > 0
}

// MARK: The proxy

type nginxProxy struct {
	version  string
	running  bool
	dump     map[string]string
	problem  string
	debian   bool // sites-available / sites-enabled
	confDir  string
	availDir string
	enabDir  string
}

var nginxRoot = "/etc/nginx" // tests

func findNginx() *nginxProxy {
	if !have("nginx") {
		return nil
	}
	n := &nginxProxy{running: processRunning("nginx"), confDir: filepath.Join(nginxRoot, "conf.d"),
		availDir: filepath.Join(nginxRoot, "sites-available"), enabDir: filepath.Join(nginxRoot, "sites-enabled")}
	if out, _ := combined(5*time.Second, "nginx", "-v"); out != "" {
		n.version = strings.TrimPrefix(strings.TrimSpace(out), "nginx version: ")
	}
	out, err := combined(15*time.Second, "nginx", "-T")
	if err != nil {
		n.problem = "nginx's configuration has an error now, so Apex won't change it: " + lastLine(out)
	}
	n.dump = splitDump(out)
	main := n.dump[filepath.Join(nginxRoot, "nginx.conf")]
	_, statErr := os.Stat(n.enabDir)
	n.debian = statErr == nil && strings.Contains(main, "sites-enabled")
	return n
}

func (n *nginxProxy) info() ProxyInfo {
	i := ProxyInfo{Kind: "nginx", Name: "nginx", Running: n.running, Editable: n.problem == "", Note: n.problem}
	if n.version != "" {
		i.Name = n.version
	}
	return i
}

func (n *nginxProxy) sites() []Site {
	var out []Site
	for file, text := range n.dump {
		if strings.HasPrefix(file, "/usr/") || strings.HasSuffix(file, "nginx.conf") && !strings.Contains(text, "server_name") {
			continue
		}
		for _, s := range ngxSites(file, text, true) {
			if sp := readSpec(text); sp != nil {
				s.Managed, s.Spec = true, sp
			}
			s.CanToggle = n.canToggle(file, text)
			out = append(out, s)
		}
	}
	// Switched off: in sites-available without a link, or Apex's .off files.
	var off []string
	if n.debian {
		entries, _ := os.ReadDir(n.availDir)
		for _, e := range entries {
			p := filepath.Join(n.availDir, e.Name())
			if _, on := n.dump[p]; !on && !n.linked(p) && !e.IsDir() {
				off = append(off, p)
			}
		}
	}
	offConf, _ := filepath.Glob(filepath.Join(n.confDir, "*.conf.off"))
	off = append(off, offConf...)
	for _, p := range off {
		b, err := os.ReadFile(p)
		if err != nil || len(b) > 1<<20 {
			continue
		}
		for _, s := range ngxSites(p, string(b), false) {
			if sp := readSpec(string(b)); sp != nil {
				s.Managed, s.Spec = true, sp
			}
			s.CanToggle = true
			out = append(out, s)
		}
	}
	return out
}

func (n *nginxProxy) linked(target string) bool {
	entries, _ := os.ReadDir(n.enabDir)
	for _, e := range entries {
		p := filepath.Join(n.enabDir, e.Name())
		if t, err := filepath.EvalSymlinks(p); err == nil && t == target {
			return true
		}
	}
	return false
}

func (n *nginxProxy) canToggle(file, text string) bool {
	if n.debian && strings.HasPrefix(file, n.enabDir+"/") {
		return true
	}
	return filepath.Dir(file) == n.confDir && strings.HasSuffix(file, ".conf") && onlyServers(text)
}

// nginxConfig: what Apex writes for a site.
func nginxConfig(s SiteSpec, logPath string) string {
	names := strings.Join(s.Domains, " ")
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n", specLine(s), managedNote)
	location := func() {
		fmt.Fprintf(&b, "    access_log %s;\n\n", logPath)
		fmt.Fprintf(&b, "    location / {\n        proxy_pass %s;\n", s.Upstream)
		b.WriteString("        proxy_set_header Host $host;\n")
		b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		if s.Websockets {
			b.WriteString("        proxy_http_version 1.1;\n")
			b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
			b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
		}
		b.WriteString("    }\n}\n")
	}
	if s.HTTPS {
		live := filepath.Join(letsEncrypt, certName(s))
		fmt.Fprintf(&b, "server {\n    listen 80;\n    listen [::]:80;\n    server_name %s;\n    return 301 https://$host$request_uri;\n}\n\n", names)
		fmt.Fprintf(&b, "server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    server_name %s;\n", names)
		fmt.Fprintf(&b, "    ssl_certificate %s/fullchain.pem;\n    ssl_certificate_key %s/privkey.pem;\n", live, live)
	} else {
		fmt.Fprintf(&b, "server {\n    listen 80;\n    listen [::]:80;\n    server_name %s;\n", names)
	}
	location()
	return b.String()
}

var letsEncrypt = "/etc/letsencrypt/live"

func certName(s SiteSpec) string { return "apex-" + slug(s.Domains) }

// ensureCert: a Let's Encrypt certificate for the site, from certbot, before
// the site that uses it is written.
func ensureCert(s SiteSpec) error {
	if _, err := os.Stat(filepath.Join(letsEncrypt, certName(s), "fullchain.pem")); err == nil {
		return nil
	}
	for _, d := range s.Domains {
		if strings.HasPrefix(d, "*.") {
			return errors.New("a certificate for a wildcard needs a DNS check Apex can't do; leave HTTPS off or use a single name")
		}
	}
	if !have("certbot") {
		return errors.New("HTTPS needs certbot on the server for its certificate (sudo apt install certbot python3-certbot-nginx), or add the site to Caddy, which gets certificates by itself")
	}
	args := []string{"certonly", "--nginx", "--non-interactive", "--agree-tos", "--register-unsafely-without-email", "--cert-name", certName(s)}
	for _, d := range s.Domains {
		args = append(args, "-d", d)
	}
	if out, err := combined(3*time.Minute, "certbot", args...); err != nil {
		return fmt.Errorf("couldn't get a certificate (each domain must point at this server and port 80 be open): %s", lastLine(out))
	}
	return nil
}

func (n *nginxProxy) paths(s SiteSpec) (file, link string) {
	name := "apex-" + slug(s.Domains) + ".conf"
	if n.debian {
		return filepath.Join(n.availDir, name), filepath.Join(n.enabDir, name)
	}
	return filepath.Join(n.confDir, name), ""
}

func (n *nginxProxy) change(c ProxyChange, site *Site) error {
	check := func() error {
		out, err := combined(20*time.Second, "nginx", "-t")
		if err != nil {
			return errors.New(lastLine(out))
		}
		return nil
	}
	reload := func() error {
		if !n.running {
			return nil
		}
		before := nginxWorkers()
		out, err := combined(20*time.Second, "nginx", "-s", "reload")
		if err != nil {
			return errors.New(lastLine(out))
		}
		// The reload is only asked for; it's done once every old worker has
		// stopped taking requests (they finish the ones they have).
		for i := 0; i < 50; i++ {
			now, old := nginxWorkers(), false
			for pid := range before {
				old = old || now[pid]
			}
			if !old && len(now) > 0 {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return errors.New("nginx didn't start new workers within 5 seconds")
	}
	var edits []edit
	switch c.Verb {
	case "add", "update":
		if c.Spec.HTTPS {
			if err := ensureCert(c.Spec); err != nil {
				return err
			}
		}
		file, link := n.paths(c.Spec)
		logPath := "/var/log/nginx/apex-" + slug(c.Spec.Domains) + ".access.log"
		if site != nil && site.File != file {
			edits = append(edits, n.removeEdits(site)...)
		}
		edits = append(edits, writeFile(file, nginxConfig(c.Spec, logPath)))
		if link != "" {
			edits = append(edits, symlink(link, file))
		}
	case "remove":
		edits = n.removeEdits(site)
	case "disable":
		switch {
		case n.debian && strings.HasPrefix(site.File, n.enabDir+"/"):
			target, _ := filepath.EvalSymlinks(site.File)
			if target == site.File { // a real file in sites-enabled: keep it in sites-available
				edits = append(edits, writeFile(filepath.Join(n.availDir, filepath.Base(site.File)), string(stateOf(site.File).data)))
			}
			edits = append(edits, removeFile(site.File))
		default:
			edits = moveFile(site.File, site.File+".off")
		}
	case "enable":
		switch {
		case strings.HasSuffix(site.File, ".conf.off"):
			edits = moveFile(site.File, strings.TrimSuffix(site.File, ".off"))
		case n.debian && strings.HasPrefix(site.File, n.availDir+"/"):
			edits = []edit{symlink(filepath.Join(n.enabDir, filepath.Base(site.File)), site.File)}
		default:
			return errors.New("Apex can't switch this site on")
		}
	default:
		return errors.New("unknown change")
	}
	return apply(edits, check, reload)
}

func (n *nginxProxy) removeEdits(site *Site) []edit {
	edits := []edit{removeFile(site.File)}
	if n.debian {
		base := filepath.Base(strings.TrimSuffix(site.File, ".off"))
		edits = append(edits, removeFile(filepath.Join(n.enabDir, base)), removeFile(filepath.Join(n.availDir, base)))
	}
	return edits
}

// MARK: Helpers

// combined: a command's output and errors together (nginx writes its
// answers to stderr).
func combined(timeout time.Duration, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
		return string(out), err
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-done
		return string(out), errors.New("took too long")
	}
}

var noiseRE = regexp.MustCompile(`^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d )?(nginx: )?(\[(emerg|alert|crit|error)\] (\d+#\d+: )?)?`)

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.Contains(l, "test failed") {
			continue
		}
		return noiseRE.ReplaceAllString(l, "")
	}
	return "no details"
}

// nginxWorkers: the pids of nginx's worker processes now.
func nginxWorkers() map[string]bool {
	out := map[string]bool{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil && strings.HasPrefix(string(b), "nginx: worker process") &&
			!strings.Contains(string(b), "shutting down") {
			out[e.Name()] = true
		}
	}
	return out
}

// processRunning: a process with that name (from /proc).
func processRunning(name string) bool {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if b, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil && strings.TrimSpace(string(b)) == name {
			return true
		}
	}
	return false
}
