package main

import (
	"reflect"
	"testing"
)

func TestSortAppsSitesFirst(t *testing.T) {
	g := []AppGroup{{Kind: "mariadb", Label: "MariaDB"}, {Kind: "wordpress", Label: "WordPress"}, {Kind: "redis", Label: "Redis"}, {Kind: "ghost", Label: "Ghost"}}
	sortApps(g)
	var got []string
	for _, x := range g {
		got = append(got, x.Kind)
	}
	if want := []string{"ghost", "wordpress", "mariadb", "redis"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

func TestClassifyImage(t *testing.T) {
	cases := map[string]string{
		"wordpress:6.6-apache": "wordpress", "bitnami/wordpress:6": "wordpress", "wordpress": "wordpress",
		"jc21/mariadb-aria:latest": "mariadb", "mysql:8": "mysql", "postgres:16-alpine": "postgres",
		"redis:7-alpine": "redis", "mongo:7": "mongodb", "ghost:5": "ghost", "nextcloud:29-apache": "nextcloud",
		"gitea/gitea:1.22": "gitea", "codeberg.org/forgejo/forgejo:9": "gitea", "grafana/grafana:11.2.0": "grafana",
		"node:20-alpine": "node",
		// not these
		"ghostfolio/ghostfolio:latest": "", "mongo-express:1": "", "prometheuscommunity/postgres-exporter": "",
		"phpmyadmin:5": "", "wordpress:cli-php8.3": "", "jc21/nginx-proxy-manager:latest": "", "louislam/uptime-kuma:1": "", "nginx:1.27": "",
	}
	for img, want := range cases {
		kind, _, _, ok := classifyImage(img)
		if kind != want || ok != (want != "") {
			t.Errorf("%s: got %q, want %q", img, kind, want)
		}
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"http://127.0.0.1:8080", "127.0.0.1", "8080"}, {"http://127.0.0.1:8080/", "127.0.0.1", "8080"},
		{"localhost:3001", "localhost", "3001"}, {"https://WordPress", "wordpress", "443"},
		{"http://wp:80/blog?x=1", "wp", "80"}, {"[::1]:9000", "::1", "9000"}, {"http://blog", "blog", "80"},
	}
	for _, c := range cases {
		h, p, ok := parseTarget(c.in)
		if !ok || h != c.host || p != c.port {
			t.Errorf("%s: %s %s %v", c.in, h, p, ok)
		}
	}
	for _, bad := range []string{"", "Files in /var/www/x", "Redirects to HTTPS"} {
		if _, _, ok := parseTarget(bad); ok {
			t.Errorf("%q parsed as an address", bad)
		}
	}
}

// The ways real proxies point at a WordPress container or folder.
func TestReaches(t *testing.T) {
	local := map[string]bool{"127.0.0.1": true, "localhost": true, "172.17.0.1": true, "203.0.113.10": true}
	wp := AppInst{ends: containerEndpoints("blog-wordpress-1", "wordpress", []string{"8080\u219280/tcp"}, "80")}
	yes := []string{
		"http://127.0.0.1:8080",      // nginx on the server, published port
		"localhost:8080",             // Caddy
		"http://172.17.0.1:8080",     // a proxy in Docker, via the gateway
		"http://203.0.113.10:8080",   // the server's own address
		"http://blog-wordpress-1:80", // Nginx Proxy Manager, by container name
		"http://wordpress",           // by compose service, default port
	}
	for _, tgt := range yes {
		if !reaches(wp, tgt, local) {
			t.Errorf("should reach: %s", tgt)
		}
	}
	no := []string{"http://127.0.0.1:3000", "http://10.0.0.9:8080", "http://other:80", "http://wordpress:8080", "Files in /var/www/blog"}
	for _, tgt := range no {
		if reaches(wp, tgt, local) {
			t.Errorf("shouldn't reach: %s", tgt)
		}
	}
	native := AppInst{docRoot: "/var/www/shop"}
	if !reaches(native, "Files in /var/www/shop", local) || !reaches(native, "Files in /var/www/shop/", local) || reaches(native, "Files in /var/www/shopping", local) {
		t.Error("document root matching")
	}
	unpublished := AppInst{ends: containerEndpoints("wp", "", nil, "80")}
	if !reaches(unpublished, "http://wp:80", local) || reaches(unpublished, "http://127.0.0.1:80", local) {
		t.Error("an unpublished container is reachable only by name")
	}
}
