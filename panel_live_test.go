package main

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// APEX_LIVE_PANEL=1, as root on a throwaway Ubuntu container with ufw and
// openssh-server: panel mode off then on, files, the terminal, packages,
// the firewall (and its lock-out guards), an SSH setting, users and keys.
func TestLivePanel(t *testing.T) {
	if os.Getenv("APEX_LIVE_PANEL") == "" {
		t.Skip("set APEX_LIVE_PANEL=1")
	}
	configDir = t.TempDir()
	saveJSON("config.json", Config{Port: 7443})
	do := func(r PanelRequest) any {
		t.Helper()
		res, err := PanelDo(r)
		if err != nil {
			t.Fatalf("%s: %v", r.Op, err)
		}
		return res
	}
	if _, err := PanelDo(PanelRequest{Op: "files.ls", Path: "/etc"}); err == nil {
		t.Fatal("off until allowed at the server")
	}
	saveJSON("config.json", Config{Port: 7443, Panel: true})

	// Files
	dir := "/root/apex-files"
	os.RemoveAll(dir)
	do(PanelRequest{Op: "files.mkdir", Path: dir})
	do(PanelRequest{Op: "files.write", Path: dir + "/a.txt", Data: base64.StdEncoding.EncodeToString([]byte("hello "))})
	do(PanelRequest{Op: "files.write", Path: dir + "/a.txt", Offset: 6, Data: base64.StdEncoding.EncodeToString([]byte("world"))})
	got := do(PanelRequest{Op: "files.read", Path: dir + "/a.txt"}).(map[string]any)
	if b, _ := base64.StdEncoding.DecodeString(got["data"].(string)); string(b) != "hello world" {
		t.Fatalf("read back %q", b)
	}
	do(PanelRequest{Op: "files.chmod", Path: dir + "/a.txt", Mode: "640"})
	do(PanelRequest{Op: "files.chown", Path: dir + "/a.txt", Owner: "nobody", Group: "nogroup"})
	ls := do(PanelRequest{Op: "files.ls", Path: dir}).(map[string]any)["entries"].([]FileEntry)
	if len(ls) != 1 || ls[0].Mode != "0640" || ls[0].Owner != "nobody" || ls[0].Group != "nogroup" {
		t.Fatalf("%+v", ls)
	}
	do(PanelRequest{Op: "files.write", Path: dir + "/a.txt", Data: base64.StdEncoding.EncodeToString([]byte("new"))})
	if fi, _ := os.Stat(dir + "/a.txt"); fi.Mode().Perm() != 0o640 {
		t.Fatal("replacing keeps the mode")
	}
	do(PanelRequest{Op: "files.rename", Path: dir + "/a.txt", To: dir + "/b.txt"})
	if _, err := PanelDo(PanelRequest{Op: "files.delete", Path: "/etc"}); err == nil {
		t.Fatal("won't delete a system folder")
	}
	do(PanelRequest{Op: "files.delete", Path: dir, All: true})
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("deleted")
	}

	// Terminal
	id := do(PanelRequest{Op: "term.open", Cols: 80, Rows: 24}).(map[string]any)["id"].(string)
	do(PanelRequest{Op: "term.write", ID: id, Data: base64.StdEncoding.EncodeToString([]byte("echo apex-$((40+2)); tput cols\n"))})
	var screen string
	var next int64
	for i := 0; i < 15 && !(strings.Contains(screen, "apex-42") && strings.Contains(screen, "\n80")); i++ {
		r := do(PanelRequest{Op: "term.read", ID: id, Since: next}).(map[string]any)
		b, _ := base64.StdEncoding.DecodeString(r["data"].(string))
		screen += string(b)
		next = r["next"].(int64)
	}
	if !strings.Contains(screen, "apex-42") || !strings.Contains(screen, "80") {
		t.Fatalf("terminal: %q", screen)
	}
	do(PanelRequest{Op: "term.resize", ID: id, Cols: 132, Rows: 40})
	do(PanelRequest{Op: "term.write", ID: id, Data: base64.StdEncoding.EncodeToString([]byte("tput cols; whoami\n"))})
	screen = ""
	for i := 0; i < 15 && !(strings.Contains(screen, "132") && strings.Contains(screen, "\nroot")); i++ {
		r := do(PanelRequest{Op: "term.read", ID: id, Since: next}).(map[string]any)
		b, _ := base64.StdEncoding.DecodeString(r["data"].(string))
		screen += string(b)
		next = r["next"].(int64)
	}
	if !strings.Contains(screen, "132") || !strings.Contains(screen, "root") {
		t.Fatalf("resized, as root: %q", screen)
	}
	do(PanelRequest{Op: "term.close", ID: id})
	t.Log("terminal ok")

	// Packages
	job := func(r PanelRequest) string {
		jid := do(r).(map[string]any)["job"].(string)
		for i := 0; i < 300; i++ {
			s := do(PanelRequest{Op: "job", ID: jid}).(map[string]any)
			if s["done"].(bool) {
				if s["failed"].(bool) {
					t.Fatalf("%s failed: %s", r.Op, s["text"])
				}
				return s["text"].(string)
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s took too long", r.Op)
		return ""
	}
	job(PanelRequest{Op: "pkg.refresh"})
	ups := do(PanelRequest{Op: "pkg.list"}).(map[string]any)
	t.Logf("%d updates, manager %s", len(ups["updates"].([]PkgUpdate)), ups["manager"])
	job(PanelRequest{Op: "pkg.install", Names: []string{"cowsay"}})
	if _, err := os.Stat("/usr/games/cowsay"); err != nil {
		t.Fatal("installed")
	}
	job(PanelRequest{Op: "pkg.remove", Names: []string{"cowsay"}})
	if _, err := PanelDo(PanelRequest{Op: "pkg.install", Names: []string{"-y; rm -rf /"}}); err == nil {
		t.Fatal("only package names")
	}

	// Firewall
	do(PanelRequest{Op: "fw.enable"})
	do(PanelRequest{Op: "fw.allow", Port: "443", Proto: "tcp"})
	do(PanelRequest{Op: "fw.allow", Port: "5432", Proto: "tcp", From: "10.0.0.0/8"})
	st := do(PanelRequest{Op: "fw.status"}).(map[string]any)
	rules := st["rules"].([]FwRule)
	t.Logf("firewall active %v, %d rules: %+v", st["active"], len(rules), rules)
	have22, have7443 := false, false
	for _, r := range rules {
		have22 = have22 || strings.HasPrefix(r.To, "22/")
		have7443 = have7443 || strings.HasPrefix(r.To, "7443/")
	}
	if !st["active"].(bool) || !have22 || !have7443 {
		t.Fatal("enabled with SSH and Apex kept open")
	}
	if _, err := PanelDo(PanelRequest{Op: "fw.deny", Port: "22"}); err == nil {
		t.Fatal("won't block SSH")
	}
	for _, r := range rules {
		if strings.HasPrefix(r.To, "22/") {
			if _, err := PanelDo(PanelRequest{Op: "fw.delete", Rule: r.ID}); err == nil {
				t.Fatal("won't delete the SSH rule")
			}
		}
	}
	for _, r := range rules {
		if strings.HasPrefix(r.To, "443") {
			do(PanelRequest{Op: "fw.delete", Rule: r.ID})
			break
		}
	}

	// SSH setting and keys
	do(PanelRequest{Op: "ssh.set", Setting: "PermitRootLogin", Value: "prohibit-password"})
	if s := sshStatus(); s["PermitRootLogin"] != "without-password" && s["PermitRootLogin"] != "prohibit-password" {
		t.Fatalf("ssh: %+v", s)
	}
	if _, err := PanelDo(PanelRequest{Op: "ssh.set", Setting: "PasswordAuthentication", Value: "no"}); err == nil {
		t.Fatal("no keys yet: passwords stay on")
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@apex"
	do(PanelRequest{Op: "keys.add", User: "root", Key: key})
	do(PanelRequest{Op: "ssh.set", Setting: "PasswordAuthentication", Value: "no"})
	if keys := do(PanelRequest{Op: "keys.list", User: "root"}).([]string); len(keys) != 1 {
		t.Fatal(keys)
	}
	do(PanelRequest{Op: "keys.remove", User: "root", Key: key})
	if _, err := PanelDo(PanelRequest{Op: "keys.add", User: "root", Key: "not a key"}); err == nil {
		t.Fatal("only keys")
	}
	t.Logf("users: %+v", do(PanelRequest{Op: "users.list"}))
}
