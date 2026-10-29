package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// APEX_LIVE_PROXY=1, as root on a Linux server or container with nginx on
// :80, Caddy on :8081 (admin API on) and Traefik on :8082 (API on :8080,
// file provider watching /etc/traefik/dynamic, JSON access log), and a
// web app on 127.0.0.1:3000: adds, checks, switches off and on, edits and
// removes a site on each, and a change each proxy refuses.
func TestLiveProxies(t *testing.T) {
	if os.Getenv("APEX_LIVE_PROXY") == "" {
		t.Skip("set APEX_LIVE_PROXY=1")
	}
	get := func(port, host string) (int, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:"+port+"/", nil)
		req.Host = host
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	find := func(proxy, domain string) *Site {
		r, _ := Proxies(true)
		for i, s := range r.Sites {
			if s.Proxy == proxy && s.Domains[0] == domain {
				return &r.Sites[i]
			}
		}
		return nil
	}
	r, _ := Proxies(true)
	for _, p := range r.Proxies {
		t.Logf("found %s running=%v editable=%v %s", p.Name, p.Running, p.Editable, p.Note)
	}
	for _, c := range []struct{ proxy, port, domain string }{{"nginx", "80", "app.test"}, {"caddy", "8081", "c.test"}, {"traefik", "8082", "t.test"}} {
		t.Run(c.proxy, func(t *testing.T) {
			spec := SiteSpec{Domains: []string{c.domain}, Upstream: "127.0.0.1:3000"}
			if err := ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "add", Spec: spec}); err != nil {
				t.Fatal("add: ", err)
			}
			if code, body := get(c.port, c.domain); code != 200 || !strings.Contains(body, "backend") {
				t.Fatalf("through the new site: %d %.80s", code, body)
			}
			for i := 0; i < 4; i++ {
				get(c.port, c.domain)
			}
			time.Sleep(1500 * time.Millisecond)
			s := find(c.proxy, c.domain)
			if s == nil || !s.Managed || !s.Enabled {
				t.Fatalf("listed: %+v", s)
			}
			if s.Traffic == nil || s.Traffic.Requests < 5 {
				t.Errorf("traffic: %+v %s", s.Traffic, s.TrafficNote)
			} else {
				t.Logf("traffic %d requests, %v", s.Traffic.Requests, s.Traffic.Statuses)
			}
			if err := ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "add", Spec: spec}); err == nil {
				t.Error("the same domain twice")
			}
			if err := ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "disable", Site: s.ID}); err != nil {
				t.Fatal("disable: ", err)
			}
			time.Sleep(time.Second)
			if code, body := get(c.port, c.domain); code == 200 && strings.Contains(body, "backend") {
				t.Fatal("still served while off")
			}
			off := find(c.proxy, c.domain)
			if off == nil || off.Enabled {
				t.Fatalf("listed as off: %+v", off)
			}
			if err := ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "enable", Site: off.ID}); err != nil {
				t.Fatal("enable: ", err)
			}
			if code, _ := get(c.port, c.domain); code != 200 {
				t.Fatal("back on")
			}
			s = find(c.proxy, c.domain)
			spec.Upstream = "127.0.0.1:3001"
			if err := ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "update", Site: s.ID, Spec: spec}); err != nil {
				t.Fatal("update: ", err)
			}
			time.Sleep(time.Second)
			if code, _ := get(c.port, c.domain); code != 502 {
				t.Errorf("forwards to the new (empty) port: %d", code)
			}
			// A change the proxy itself refuses: everything stays as it was.
			bad := SiteSpec{Domains: []string{"bad.test"}, Upstream: "http://no-such-host-apex.invalid:80"}
			err := ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "add", Spec: bad})
			t.Logf("refused change: %v", err)
			if c.proxy == "nginx" && err == nil {
				t.Error("nginx -t refuses an upstream that doesn't resolve")
			}
			if err != nil && find(c.proxy, "bad.test") != nil {
				t.Error("a refused site is gone again")
			}
			if b := find(c.proxy, "bad.test"); b != nil {
				ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "remove", Site: b.ID})
			}
			s = find(c.proxy, c.domain)
			if err := ProxyDo(ProxyChange{Proxy: c.proxy, Verb: "remove", Site: s.ID}); err != nil {
				t.Fatal("remove: ", err)
			}
			if find(c.proxy, c.domain) != nil {
				t.Fatal("removed")
			}
			if code, _ := get(c.port, "app.other"); code == 0 {
				t.Fatal("the proxy still answers after the last Apex site went")
			}
		})
	}
}
