package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestDemuxLogs(t *testing.T) {
	frame := func(stream byte, s string) []byte {
		h := make([]byte, 8)
		h[0] = stream
		binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
		return append(h, s...)
	}
	b := append(frame(1, "2026-10-29T10:00:00Z started\n"), frame(2, "2026-10-29T10:00:01Z warning\n")...)
	if got := demuxLogs(b); got != "2026-10-29T10:00:00Z started\n2026-10-29T10:00:01Z warning\n" {
		t.Fatalf("%q", got)
	}
	if got := demuxLogs([]byte("plain tty output\n")); got != "plain tty output\n" {
		t.Fatalf("a terminal's logs come as they are: %q", got)
	}
}

func TestStacksAndManagers(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services: {}\n"), 0o644)
	label := func(project string) map[string]string {
		return map[string]string{"com.docker.compose.project": project, "com.docker.compose.project.working_dir": dir,
			"com.docker.compose.project.config_files": filepath.Join(dir, "compose.yaml")}
	}
	cs := []apiContainer{
		{ID: "a", Names: []string{"/web-1"}, State: "running", Labels: label("web")},
		{ID: "b", Names: []string{"/web-db-1"}, State: "exited", Labels: label("web")},
		{ID: "c", Names: []string{"/lonely"}, State: "running", Labels: map[string]string{}},
		{ID: "d", Names: []string{"/portainer"}, Image: "portainer/portainer-ce:2.21", State: "running",
			Ports: []struct {
				IP          string `json:"IP"`
				PrivatePort int    `json:"PrivatePort"`
				PublicPort  int    `json:"PublicPort"`
				Type        string `json:"Type"`
			}{{PrivatePort: 9443, PublicPort: 19443, Type: "tcp"}}},
	}
	st := buildStacks(cs[:3], "")
	if len(st) != 1 || st[0].Name != "web" || st[0].Total != 2 || st[0].Running != 1 || st[0].Manager != "compose" || !st[0].Editable {
		t.Fatalf("%+v", st)
	}
	m := findManagers(cs)
	if len(m) != 1 || m[0].Name != "Portainer" || m[0].URL != "https://:19443" || !m[0].Running {
		t.Fatalf("%+v", m)
	}
	d := toDContainer(cs[3], map[string]Container{"d": {ID: "d", CPU: "1.5%"}})
	if d.Name != "portainer" || d.Ports[0] != "19443→9443/tcp" || d.CPU != "1.5%" {
		t.Fatalf("%+v", d)
	}
}
