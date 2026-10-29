package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCleanSpec(t *testing.T) {
	s, err := cleanSpec(SiteSpec{Domains: []string{" Example.COM. ", "www.example.com", "example.com", "*.apps.example.com"}, Upstream: "127.0.0.1:3000"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.Domains, ",") != "example.com,www.example.com,*.apps.example.com" || s.Upstream != "http://127.0.0.1:3000" {
		t.Fatalf("%+v", s)
	}
	for _, up := range []string{"https://app.internal:8443/", "http://[::1]:8080", "http://web"} {
		if _, err := cleanSpec(SiteSpec{Domains: []string{"a.example"}, Upstream: up}); err != nil {
			t.Errorf("%s: %v", up, err)
		}
	}
	bad := []SiteSpec{
		{Domains: []string{"example.com; include /etc/passwd"}, Upstream: "http://a:1"},
		{Domains: []string{"example.com\n}"}, Upstream: "http://a:1"},
		{Domains: []string{"exa mple.com"}, Upstream: "http://a:1"},
		{Domains: []string{"example.com"}, Upstream: "http://a:1;rm -rf /"},
		{Domains: []string{"example.com"}, Upstream: "http://a:1/x\";"},
		{Domains: []string{"example.com"}, Upstream: "http://user:pw@a:1"},
		{Domains: []string{"example.com"}, Upstream: "ftp://a:1"},
		{Domains: []string{"example.com"}, Upstream: "http://a:99999"},
		{Domains: []string{"example.com"}, Upstream: "http://a:1?x=1"},
		{Domains: []string{"example.com"}, Upstream: "http://a`b:1"},
		{Domains: []string{}, Upstream: "http://a:1"},
	}
	for _, b := range bad {
		if _, err := cleanSpec(b); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
}

const debianDump = `nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/nginx.conf:
user www-data;
events { worker_connections 768; }
http {
	access_log /var/log/nginx/access.log;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
stream { server { listen 5353; proxy_pass dns; } }

# configuration file /etc/nginx/sites-enabled/shop:
upstream shop_app { server 127.0.0.1:4000; }
server {
	listen 80;
	server_name shop.example.com;
	return 301 https://$host$request_uri; # certbot
}
server {
	listen 443 ssl; # managed by Certbot
	server_name shop.example.com;
	access_log /var/log/nginx/shop.log;
	location / { proxy_pass http://shop_app; }
	location /static { root /srv/static; }
}

# configuration file /etc/nginx/sites-enabled/default:
server {
	listen 80 default_server;
	root /var/www/html;
	server_name _;
	location / { try_files $uri $uri/ =404; }
}
`

func TestNginxDump(t *testing.T) {
	files := splitDump(debianDump)
	if len(files) != 3 {
		t.Fatalf("files %d", len(files))
	}
	shop := ngxSites("/etc/nginx/sites-enabled/shop", files["/etc/nginx/sites-enabled/shop"], true)
	if len(shop) != 1 {
		t.Fatalf("port 80 and 443 blocks are one site: %+v", shop)
	}
	s := shop[0]
	if !s.HTTPS || s.Domains[0] != "shop.example.com" || strings.Join(s.Targets, ",") != "http://shop_app" || s.logs[0] != "/var/log/nginx/shop.log" {
		t.Fatalf("%+v", s)
	}
	def := ngxSites("x", files["/etc/nginx/sites-enabled/default"], true)
	if def[0].Domains[0] != "(any name)" || def[0].Targets[0] != "Files in /var/www/html" || def[0].HTTPS {
		t.Fatalf("%+v", def[0])
	}
	if got := ngxSites("x", files["/etc/nginx/nginx.conf"], true); len(got) != 0 {
		t.Fatalf("stream servers aren't web sites: %+v", got)
	}
	if onlyServers(files["/etc/nginx/sites-enabled/shop"]) {
		t.Fatal("a file with an upstream isn't only servers")
	}
	if !onlyServers(files["/etc/nginx/sites-enabled/default"]) {
		t.Fatal("default is only a server")
	}
}

func TestNPMHost(t *testing.T) {
	conf := `# ------------------------------------------------------------
# cloud.example.com
# ------------------------------------------------------------
server {
  set $forward_scheme http;
  set $server         "192.168.1.20";
  set $port           8080;
  listen 80;
  listen [::]:80;
  listen 443 ssl;
  server_name cloud.example.com;
  access_log /data/logs/proxy-host-3_access.log proxy;
  location / {
    include conf.d/include/proxy.conf;
  }
  include /data/nginx/custom/server_proxy[.]conf;
}`
	s := ngxSites("3.conf", conf, true)
	if len(s) != 1 || !s[0].HTTPS || s[0].Domains[0] != "cloud.example.com" {
		t.Fatalf("%+v", s)
	}
}

func TestNginxConfig(t *testing.T) {
	spec := SiteSpec{Domains: []string{"app.example.com"}, Upstream: "http://127.0.0.1:3000", Websockets: true}
	text := nginxConfig(spec, "/var/log/nginx/apex-app.example.com.access.log")
	if got := readSpec(text); got == nil || got.Upstream != spec.Upstream {
		t.Fatal("the spec reads back")
	}
	sites := ngxSites("f", text, true)
	if len(sites) != 1 || sites[0].Targets[0] != "http://127.0.0.1:3000" || sites[0].HTTPS || !strings.Contains(text, "Upgrade $http_upgrade") {
		t.Fatalf("%+v\n%s", sites, text)
	}
	spec.HTTPS = true
	text = nginxConfig(spec, "l")
	if !strings.Contains(text, "listen 443 ssl") || !strings.Contains(text, "/etc/letsencrypt/live/apex-app.example.com/fullchain.pem") || !strings.Contains(text, "return 301") {
		t.Fatal(text)
	}
	if s := ngxSites("f", text, true); len(s) != 1 || !s[0].HTTPS || len(s[0].Targets) != 1 {
		t.Fatalf("redirect + site are one: %+v", s)
	}
}

func TestCaddy(t *testing.T) {
	var cfg map[string]any
	json.Unmarshal([]byte(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["Blog.example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"localhost:2368"}]}]}]}]},
		{"match":[{"host":["files.example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"file_server","root":"/srv/files"}]}]}]}
	]}}}},"logging":{"logs":{"default":{"writer":{"output":"file","filename":"/var/log/caddy/access.log"}}}}}`), &cfg)
	sites := caddySitesFromConfig(cfg)
	if len(sites) != 2 || sites[0].Domains[0] != "blog.example.com" || sites[0].Targets[0] != "localhost:2368" || !sites[0].HTTPS {
		t.Fatalf("%+v", sites)
	}
	if sites[1].Targets[0] != "Files /srv/files" {
		t.Fatalf("%+v", sites[1])
	}
	if l := caddyLogFiles(cfg); len(l) != 1 || l[0] != "/var/log/caddy/access.log" {
		t.Fatal(l)
	}
	file := `{
	email me@example.com
}
blog.example.com, www.blog.example.com {
	reverse_proxy localhost:2368
}
http://intranet.lan {
	root * /srv/www
	file_server
}
(common) {
	encode gzip
}
`
	fs := caddySitesFromFile(file)
	if len(fs) != 2 || len(fs[0].Domains) != 2 || fs[0].Targets[0] != "localhost:2368" || fs[1].HTTPS || fs[1].Targets[0] != "Files in /srv/www" {
		t.Fatalf("%+v", fs)
	}
	out := caddyConfig(SiteSpec{Domains: []string{"a.example.com"}, Upstream: "http://127.0.0.1:8080"})
	if !strings.Contains(out, "http://a.example.com {") || !strings.Contains(out, "reverse_proxy http://127.0.0.1:8080") {
		t.Fatal(out)
	}
}

func TestTraefik(t *testing.T) {
	d := ruleDomains("Host(`a.example.com`) || (Host(`B.example.com`) && PathPrefix(`/api`))")
	if strings.Join(d, ",") != "a.example.com,b.example.com" {
		t.Fatal(d)
	}
	static := `entryPoints:
  web:
    address: ":80"
providers:
  docker: {}
  file:
    directory: /etc/traefik/dynamic
    watch: true
accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
certificatesResolvers:
  letsencrypt:
    acme:
      email: me@example.com
`
	if yamlValue(static, "providers", "file", "directory") != "/etc/traefik/dynamic" || yamlValue(static, "accessLog", "filePath") != "/var/log/traefik/access.log" {
		t.Fatal("yaml")
	}
	if yamlValue(static, "providers", "docker", "directory") != "" {
		t.Fatal("not under docker")
	}
	if firstChild(static, "certificatesResolvers") != "letsencrypt" {
		t.Fatal("resolver")
	}
	cfg := traefikConfig(SiteSpec{Domains: []string{"a.example.com", "*.b.example.com"}, Upstream: "http://10.0.0.5:80", HTTPS: true}, "letsencrypt")
	if !strings.Contains(cfg, "certResolver: letsencrypt") || !strings.Contains(cfg, "url: \"http://10.0.0.5:80\"") || readSpec(cfg) == nil {
		t.Fatal(cfg)
	}
	if !strings.Contains(cfg, "Host(`a.example.com`)") || !strings.Contains(cfg, "HostRegexp") {
		t.Fatal(cfg)
	}
}

func TestLogFormats(t *testing.T) {
	cases := map[string]hit{
		`203.0.113.7 - - [29/Oct/2026:10:00:00 +0000] "GET /cart?x=1 HTTP/1.1" 200 512 "-" "curl/8"`:                                                                                                 {ip: "203.0.113.7", path: "/cart?x=1", status: 200, bytes: 512},
		`203.0.113.7 - - [29/Oct/2026:10:00:00 +0000] "-" 400 0 "-" "-"`:                                                                                                                             {ip: "203.0.113.7", status: 400},
		`[29/Oct/2026:10:00:00 +0000] - 502 502 - GET https cloud.example.com "/login" [Client 198.51.100.4] [Length 166] [Gzip -] [Sent-to 192.168.1.20] "Mozilla" "-"`:                             {ip: "198.51.100.4", host: "cloud.example.com", path: "/login", status: 502, bytes: 166},
		`10.0.0.1 - - [29/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 304 0 "-" "Mozilla" 42 "web@docker" "http://172.18.0.3:80" 3ms`:                                                                  {ip: "10.0.0.1", path: "/", status: 304, rt: "web@docker"},
		`{"level":"info","ts":1793268000.5,"logger":"http.log.access","request":{"remote_ip":"192.0.2.1","host":"Blog.example.com","uri":"/feed"},"status":200,"size":2048}`:                         {ip: "192.0.2.1", host: "blog.example.com", path: "/feed", status: 200, bytes: 2048},
		`{"ClientHost":"192.0.2.9","RequestHost":"a.example.com","RequestPath":"/x","DownstreamStatus":503,"DownstreamContentSize":10,"RouterName":"apex-a@file","StartUTC":"2026-10-29T10:00:00Z"}`: {ip: "192.0.2.9", host: "a.example.com", path: "/x", status: 503, bytes: 10, rt: "apex-a@file"},
	}
	for line, want := range cases {
		h, ok := parseHit(line)
		if !ok {
			t.Errorf("not read: %s", line)
			continue
		}
		if h.t.IsZero() {
			t.Errorf("no time: %s", line)
		}
		h.t = time.Time{}
		if h != want {
			t.Errorf("%s\n got %+v\nwant %+v", line, h, want)
		}
	}
	if _, ok := parseHit("2026/10/29 10:00:00 [error] 12#12: connect() failed"); ok {
		t.Error("an error log line isn't a request")
	}
}

func TestTrafficWindow(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 29, 10, 30, 0, 0, time.UTC)
	var b strings.Builder
	line := func(at time.Time, ip, path string, st int) {
		b.WriteString(ip + ` - - [` + at.Format(clfTime) + `] "GET ` + path + ` HTTP/1.1" ` + itoa(st) + " 100 \"-\" \"-\"\n")
	}
	line(now.Add(-20*time.Minute), "1.1.1.1", "/old", 200) // outside the window
	for i := 0; i < 30; i++ {
		line(now.Add(-time.Duration(i)*10*time.Second), "2.2.2.2", "/", 200)
	}
	line(now.Add(-time.Minute), "3.3.3.3", "/wp-login.php", 404)
	line(now.Add(-time.Minute), "3.3.3.3", "/api", 502)
	p := filepath.Join(dir, "site.log")
	os.WriteFile(p, []byte(b.String()), 0o644)
	hits, window, ok := readHits(p, now)
	if !ok || len(hits) != 32 || window != 600 {
		t.Fatalf("%d hits, %v s", len(hits), window)
	}
	tr := summarize(hits, window)
	if tr.Statuses["2xx"] != 30 || tr.Statuses["4xx"] != 1 || tr.Statuses["5xx"] != 1 || tr.Bytes != 3200 {
		t.Fatalf("%+v", tr)
	}
	if tr.PerMinute < 3.19 || tr.PerMinute > 3.21 || tr.TopClients[0].Value != "2.2.2.2" || tr.TopPaths[0].Value != "/" {
		t.Fatalf("%+v", tr)
	}
	// Two sites in one shared log, told apart by host.
	sites := []Site{{Domains: []string{"a.example.com"}, Enabled: true}, {Domains: []string{"*.b.example.com"}, Enabled: true}}
	if !matches(sites[1], hit{host: "x.b.example.com"}) || matches(sites[0], hit{host: "b.example.com"}) || matches(sites[0], hit{}) {
		t.Fatal("matching")
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestApplyUndoesEverything(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "main.conf")
	os.WriteFile(keep, []byte("original"), 0o640)
	link := filepath.Join(dir, "enabled", "site")
	os.MkdirAll(filepath.Dir(link), 0o755)
	os.Symlink(keep, link)
	edits := []edit{writeFile(keep, "changed"), writeFile(filepath.Join(dir, "new.conf"), "new"), removeFile(link)}
	err := apply(edits, func() error { return errors.New("syntax error") }, func() error { t.Fatal("no reload after a failed check"); return nil })
	if err == nil {
		t.Fatal("the check failed")
	}
	if b, _ := os.ReadFile(keep); string(b) != "original" {
		t.Fatal("content back")
	}
	if st, _ := os.Stat(keep); st.Mode().Perm() != 0o640 {
		t.Fatal("mode back")
	}
	if _, err := os.Stat(filepath.Join(dir, "new.conf")); err == nil {
		t.Fatal("the new file is gone")
	}
	if tgt, _ := os.Readlink(link); tgt != keep {
		t.Fatal("the link is back")
	}
	reloads := 0
	err = apply([]edit{writeFile(keep, "changed")}, func() error { return nil }, func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload failed")
		}
		return nil
	})
	if err == nil || reloads != 2 {
		t.Fatalf("undone and reloaded the old one: %v %d", err, reloads)
	}
	if b, _ := os.ReadFile(keep); string(b) != "original" {
		t.Fatal("reload failure undoes too")
	}
	if err := apply([]edit{writeFile(keep, "changed")}, func() error { return nil }, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(keep); string(b) != "changed" {
		t.Fatal("written")
	}
}

func TestLastLine(t *testing.T) {
	out := "2026/10/29 10:22:25 [emerg] 4089#4089: host not found in upstream \"x.invalid\" in /etc/nginx/a.conf:10\nnginx: configuration file /etc/nginx/nginx.conf test failed\n"
	if got := lastLine(out); got != `host not found in upstream "x.invalid" in /etc/nginx/a.conf:10` {
		t.Fatal(got)
	}
	if got := lastLine("nginx: [emerg] unknown directive \"x\" in /a:1"); got != `unknown directive "x" in /a:1` {
		t.Fatal(got)
	}
}

func TestCertificateRenewsWithTheSameKey(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	defer func() { configDir = old }()
	c1, fp1, err := ensureCertificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c1.Certificate[0])
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > 825*24*time.Hour {
		t.Fatalf("macOS accepts at most 825 days: %v", d)
	}
	if needsNewCertificate(path("cert.pem"), time.Now()) {
		t.Fatal("a fresh one is kept")
	}
	if !needsNewCertificate(path("cert.pem"), time.Now().AddDate(0, 0, certDays-30)) {
		t.Fatal("renewed 60 days before it ends")
	}
	key1 := keyFingerprint(c1.Certificate[0])
	if err := makeCertificate(path("cert.pem"), path("key.pem")); err != nil {
		t.Fatal(err)
	}
	c2, fp2, _ := ensureCertificate()
	if fp1 == fp2 {
		t.Fatal("a renewal is a new certificate")
	}
	if keyFingerprint(c2.Certificate[0]) != key1 || key1 == "" {
		t.Fatal("with the same key, so the app's key pin still matches")
	}
	// A certificate from before 1.1 (20 years) is replaced, keeping its key.
	tpl := *leaf
	tpl.NotAfter = time.Now().AddDate(20, 0, 0)
	b, _ := os.ReadFile(path("key.pem"))
	blk, _ := pem.Decode(b)
	k, _ := x509.ParseECPrivateKey(blk.Bytes)
	der, _ := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &k.PublicKey, k)
	os.WriteFile(path("cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	if !needsNewCertificate(path("cert.pem"), time.Now()) {
		t.Fatal("a 20-year certificate is replaced")
	}
	c3, _, _ := ensureCertificate()
	if keyFingerprint(c3.Certificate[0]) != key1 {
		t.Fatal("same key after replacing an old one")
	}
}
