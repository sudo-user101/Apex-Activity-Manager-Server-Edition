package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// APEX_LIVE_DOCKER=1, as root with the Docker socket, docker + compose, a
// Dockge-style stack folder /opt/stacks/demo (compose.yaml with one
// service, never started), and a container named apex-loose: lists, finds
// the managers and stacks, brings the stack up, reads logs, stops /
// starts / restarts it, edits its file (a bad one refused), takes it down,
// and stops / starts the loose container.
func TestLiveDocker(t *testing.T) {
	if os.Getenv("APEX_LIVE_DOCKER") == "" {
		t.Skip("set APEX_LIVE_DOCKER=1")
	}
	list := func() DockerReport { return DockerList(nil) }
	stack := func(r DockerReport, n string) *DStack {
		for i := range r.Stacks {
			if r.Stacks[i].Name == n {
				return &r.Stacks[i]
			}
		}
		return nil
	}
	do := func(req DockerRequest) any {
		t.Helper()
		res, err := DockerDo(req, nil)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		return res
	}
	r := list()
	b, _ := json.MarshalIndent(r, "", " ")
	os.WriteFile("/tmp/docker-report.json", b, 0o644)
	if !r.Available || !r.Compose {
		t.Fatalf("available %v compose %v %s", r.Available, r.Compose, r.Problem)
	}
	var names []string
	for _, m := range r.Managers {
		names = append(names, m.Name)
	}
	t.Logf("managers %v", names)
	if !strings.Contains(strings.Join(names, ","), "Dockge") || !strings.Contains(strings.Join(names, ","), "Portainer") {
		t.Errorf("managers: %v", names)
	}
	s := stack(r, "demo")
	if s == nil || s.Manager != "dockge" || !s.Editable || s.Total != 0 {
		t.Fatalf("Dockge stack before it runs: %+v", s)
	}
	do(DockerRequest{Op: "stack", Verb: "up", Target: "demo"})
	r = list()
	if s = stack(r, "demo"); s == nil || s.Running != 1 || s.Manager != "dockge" {
		t.Fatalf("up: %+v", s)
	}
	var cid string
	for _, c := range r.Containers {
		if c.Project == "demo" {
			cid = c.ID
		}
	}
	time.Sleep(2 * time.Second)
	logs := do(DockerRequest{Op: "logs", Target: cid, Tail: 50}).(map[string]string)["text"]
	if !strings.Contains(logs, "hello from demo") {
		t.Errorf("logs: %q", logs)
	}
	do(DockerRequest{Op: "stack", Verb: "stop", Target: "demo"})
	if s = stack(list(), "demo"); s.Running != 0 || s.Total != 1 {
		t.Fatalf("stopped: %+v", s)
	}
	do(DockerRequest{Op: "stack", Verb: "start", Target: "demo"})
	do(DockerRequest{Op: "stack", Verb: "restart", Target: "demo"})
	if s = stack(list(), "demo"); s.Running != 1 {
		t.Fatalf("started: %+v", s)
	}
	f := do(DockerRequest{Op: "file", Target: "demo"}).(map[string]any)
	old := f["text"].(string)
	if _, err := DockerDo(DockerRequest{Op: "save", Target: "demo", Text: "services:\n  web: [not, valid\n"}, nil); err == nil {
		t.Error("a broken file is refused")
	}
	if now := do(DockerRequest{Op: "file", Target: "demo"}).(map[string]any)["text"]; now != old {
		t.Error("and the old one kept")
	}
	do(DockerRequest{Op: "save", Target: "demo", Text: strings.Replace(old, "hello from demo", "hello again", 1), Deploy: true})
	time.Sleep(2 * time.Second)
	for _, c := range list().Containers {
		if c.Project == "demo" {
			if l := do(DockerRequest{Op: "logs", Target: c.ID}).(map[string]string)["text"]; !strings.Contains(l, "hello again") {
				t.Errorf("redeployed with the new file: %q", l)
			}
		}
	}
	do(DockerRequest{Op: "save", Target: "demo", Text: old})
	do(DockerRequest{Op: "stack", Verb: "down", Target: "demo"})
	if s = stack(list(), "demo"); s == nil || s.Total != 0 {
		t.Fatalf("down, still listed from its folder: %+v", s)
	}
	do(DockerRequest{Op: "container", Verb: "stop", Target: "apex-loose"})
	do(DockerRequest{Op: "container", Verb: "start", Target: "apex-loose"})
	if _, err := DockerDo(DockerRequest{Op: "container", Verb: "stop", Target: "no-such"}, nil); err == nil {
		t.Error("unknown container refused")
	}
	if _, err := DockerDo(DockerRequest{Op: "network", Verb: "remove", Target: "bridge"}, nil); err == nil {
		t.Error("Docker's own network refused")
	}
	if _, err := DockerDo(DockerRequest{Op: "stack", Verb: "up", Target: "../etc"}, nil); err == nil {
		t.Error("only stacks it found")
	}
}
