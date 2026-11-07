package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The 2026-11-07 security fixes, each tried the way an attacker would.

func TestComposeFilesNeedPanelMode(t *testing.T) {
	configDir = t.TempDir() // no config: panel mode is off
	for _, op := range []string{"file", "save"} {
		if !dockerNeedsPanel(op) {
			t.Fatal(op, "should need panel mode")
		}
		if _, err := DockerDo(DockerRequest{Op: op, Target: "demo", Text: "services: {}"}, nil); err != errPanelOff {
			t.Fatal(op, "ran with panel mode off:", err)
		}
	}
	for _, op := range []string{"list", "container", "stack", "logs"} {
		if dockerNeedsPanel(op) {
			t.Fatal(op, "shouldn't need panel mode")
		}
	}
}

func TestKeysAreNeverReadOrWrittenThroughALink(t *testing.T) {
	home, secret := t.TempDir(), filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(secret, []byte("root:SECRET\n"), 0o600)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.Symlink(secret, filepath.Join(home, ".ssh", "authorized_keys"))
	if keys := readKeys(home, os.Getuid()); len(keys) != 0 {
		t.Fatal("read through the link:", keys)
	}
	if _, err := safeRead(home, ".ssh", "authorized_keys", os.Getuid()); err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatal("a linked authorized_keys wasn't refused:", err)
	}
	// A linked .ssh folder is refused too, so nothing is written where it points.
	home2, elsewhere := t.TempDir(), t.TempDir()
	os.Symlink(elsewhere, filepath.Join(home2, ".ssh"))
	if err := safeReplace(home2, ".ssh", "authorized_keys", []byte("k\n"), 0o600, -1, -1); err == nil {
		t.Fatal("wrote through a linked .ssh")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("a file appeared where the link points")
	}
	if b, _ := os.ReadFile(secret); string(b) != "root:SECRET\n" {
		t.Fatal("the linked file changed")
	}
}

func TestKeysAreWrittenNormally(t *testing.T) {
	home := t.TempDir()
	if err := safeReplace(home, ".ssh", "authorized_keys", []byte("ssh-ed25519 AAAA test\n"), 0o600, -1, -1); err != nil {
		t.Fatal(err)
	}
	if keys := readKeys(home, os.Getuid()); len(keys) != 1 {
		t.Fatal(keys)
	}
	fi, _ := os.Stat(filepath.Join(home, ".ssh", "authorized_keys"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	if ents, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(ents) != 1 {
		t.Fatal("left a temporary file behind:", ents)
	}
}

func TestAFileSaveIgnoresAPlantedLink(t *testing.T) {
	dir, victim := t.TempDir(), filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("untouched"), 0o600)
	p := filepath.Join(dir, "notes.txt")
	os.WriteFile(p, []byte("old"), 0o640)
	os.Symlink(victim, p+".apex-tmp") // the old fixed name
	if err := writeFilePart(p, []byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatal("wrote through the planted link")
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatal("the save itself didn't happen:", string(b))
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatal("mode not kept", fi.Mode())
	}
	// The next part of an upload doesn't follow a link swapped in either.
	os.Remove(p)
	os.Symlink(victim, p)
	if err := writeFilePart(p, []byte("x"), 3); err == nil {
		t.Fatal("appended through a link")
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatal("the linked file changed")
	}
}

func TestARemovedDeviceStaysRemoved(t *testing.T) {
	configDir = t.TempDir()
	a := NewAuth()
	p, _ := a.NewPairing()
	gone, _ := a.Pair(p.Code, "Lost laptop", "1.1.1.1")
	p, _ = a.NewPairing()
	kept, _ := a.Pair(p.Code, "Desk", "1.1.1.2")
	// Both idle for a while, so the next request of each saves the list.
	for i := range a.devices {
		a.devices[i].LastSeen = a.devices[i].LastSeen.Add(-time10m)
	}
	saveJSON("devices.json", a.devices)
	// `apex-server devices remove`: another process edits the file.
	cli := NewAuth()
	keep := cli.devices[:0]
	for _, d := range cli.devices {
		if d.Name != "Lost laptop" {
			keep = append(keep, d)
		}
	}
	saveJSON("devices.json", keep)
	// Before the next reload, the server saves from requests and a sign-out.
	a.Check(kept)
	if a.Check(gone) {
		t.Fatal("the removed device's own request still passed after a save")
	}
	p, _ = a.NewPairing()
	a.Pair(p.Code, "New phone", "1.1.1.3")
	a.Reload()
	for _, d := range a.devices {
		if d.Name == "Lost laptop" {
			t.Fatal("the removed device came back")
		}
	}
	if !a.Check(kept) || len(a.devices) != 2 {
		t.Fatal("other devices were lost", a.devices)
	}
}

func TestInstallKeepsThePairingCodeOutOfTmp(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "/tmp/apex-server-welcome") {
		t.Fatal("install.sh still writes the welcome text to /tmp")
	}
	if !strings.Contains(string(b), `WELCOME=$("$BIN" setup`) {
		t.Fatal("setup output isn't kept in memory")
	}
}

const time10m = 10 * 60 * 1e9

// The real attack on Linux as root, with a real second user (a throwaway
// container only): APEX_ROOT_E2E=1.
func TestRootAddingAKeyForAUserWhoPlantedALink(t *testing.T) {
	if os.Getenv("APEX_ROOT_E2E") == "" || os.Getuid() != 0 {
		t.Skip("set APEX_ROOT_E2E=1, as root in a throwaway container")
	}
	victim := "/root/apex-canary"
	os.WriteFile(victim, []byte("root-only\n"), 0o600)
	home := "/home/u1"
	os.Remove(filepath.Join(home, ".ssh", "authorized_keys"))
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	if err := os.Symlink(victim, filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIApexTestKeyApexTestKeyApexTestKeyApexTestKe test"
	if _, err := usersDo(PanelRequest{Op: "keys.add", User: "u1", Key: key}); err == nil {
		t.Fatal("added a key through the planted link")
	}
	fi, _ := os.Stat(victim)
	if b, _ := os.ReadFile(victim); string(b) != "root-only\n" || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("root's file was changed or handed over")
	}
	os.Remove(filepath.Join(home, ".ssh", "authorized_keys"))
	if _, err := usersDo(PanelRequest{Op: "keys.add", User: "u1", Key: key}); err != nil {
		t.Fatal("a normal key add failed:", err)
	}
	fi, _ = os.Stat(filepath.Join(home, ".ssh", "authorized_keys"))
	if fi.Sys().(*syscall.Stat_t).Uid == 0 {
		t.Fatal("the new key file should belong to u1")
	}
}
