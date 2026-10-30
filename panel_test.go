package main

import (
	"strings"
	"testing"
)

func TestParsePackageManagers(t *testing.T) {
	apt := `Listing...
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 arm64 [upgradable from: 3.0.13-0ubuntu3.1]
curl/noble-updates 8.5.0-2ubuntu10.5 arm64 [upgradable from: 8.5.0-2ubuntu10.4]`
	u := parseAptUpgradable(apt)
	if len(u) != 2 || u[0].Name != "openssl" || !u[0].Security || u[0].Current != "3.0.13-0ubuntu3.1" || u[1].Security {
		t.Fatalf("%+v", u)
	}
	dnf := `
Last metadata expiration check: 0:10:00 ago.
kernel.x86_64                    5.14.0-427.el9         baseos
openssl.x86_64                   1:3.0.7-28.el9         baseos
`
	d := parseDnfCheck(dnf, map[string]bool{"openssl": true})
	if len(d) != 2 || d[0].Name != "kernel" || d[1].New != "1:3.0.7-28.el9" || !d[1].Security {
		t.Fatalf("%+v", d)
	}
	a := parseApkVersion("Installed:                                Available:\nbusybox-1.36.1-r28               < 1.36.1-r29\nmusl-1.2.5-r0                    < 1.2.5-r1\n")
	if len(a) != 2 || a[0].Name != "busybox" || a[0].Current != "1.36.1-r28" || a[1].New != "1.2.5-r1" {
		t.Fatalf("%+v", a)
	}
	z := parseZypper("S | Repository | Name | Current Version | Available Version | Arch\n--+---\nv | Main | curl | 8.6.0-1 | 8.6.0-2 | x86_64\n")
	if len(z) != 1 || z[0].Name != "curl" || z[0].New != "8.6.0-2" {
		t.Fatalf("%+v", z)
	}
}

func TestParseFirewalls(t *testing.T) {
	ufw := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 443                        ALLOW IN    203.0.113.0/24
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
`
	on, r := parseUfw(ufw)
	if !on || len(r) != 3 || r[0].To != "22/tcp" || r[1].From != "203.0.113.0/24" || !r[2].V6 || r[2].To != "22/tcp" || r[1].ID != "2" {
		t.Fatalf("%v %+v", on, r)
	}
	fd := parseFirewalld(`public (active)
  target: default
  services: dhcpv6-client ssh
  ports: 7443/tcp 8000-8100/udp
`)
	if len(fd) != 4 || fd[0].ID != "service:dhcpv6-client" || fd[2].ID != "port:7443/tcp" {
		t.Fatalf("%+v", fd)
	}
}

func TestPanelChecks(t *testing.T) {
	for _, k := range []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@mac",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT"} {
		if !keyRE.MatchString(k) {
			t.Errorf("a key: %s", k[:20])
		}
	}
	for _, k := range []string{"ssh-ed25519 AAAA\ncommand=\"rm -rf /\" ssh-rsa AAAA", "not a key", `command="x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl`} {
		if keyRE.MatchString(k) {
			t.Errorf("not a plain key: %q", k)
		}
	}
	for _, p := range []string{"relative/path", "", "/etc/\x00x"} {
		if c, err := cleanPath(p); err == nil && p != "" {
			t.Errorf("%q -> %q", p, c)
		}
	}
	if c, _ := cleanPath("/etc/../etc/nginx/"); c != "/etc/nginx" {
		t.Fatal(c)
	}
	for _, n := range []string{"nginx", "libssl3", "python3.11", "g++"} {
		if !pkgName.MatchString(n) {
			t.Errorf("package %s", n)
		}
	}
	for _, n := range []string{"-y", "a b", "x;rm", "$(id)"} {
		if pkgName.MatchString(n) {
			t.Errorf("not a package %q", n)
		}
	}
	old := configDir
	configDir = t.TempDir()
	defer func() { configDir = old }()
	if _, err := PanelDo(PanelRequest{Op: "files.ls", Path: "/"}); err == nil || !strings.Contains(err.Error(), "allow panel") {
		t.Fatalf("panel mode off: %v", err)
	}
	if _, err := PanelDo(PanelRequest{Op: "status"}); err != nil {
		t.Fatal("status works without it")
	}
}
