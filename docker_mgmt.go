package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Docker Management: every container grouped by its stack (compose
// project) and the manager that runs it (Dockge, Portainer, Compose),
// images, volumes and networks, and the actions on them. Read from the
// Docker socket; stacks are brought up, down and updated with `docker
// compose`, using the folder and files Docker itself recorded for the
// stack (or Dockge's stacks folder), never a path sent by the app.

type DockerReport struct {
	Available  bool            `json:"available"`
	Problem    string          `json:"problem,omitempty"`
	Version    string          `json:"version,omitempty"`
	Compose    bool            `json:"compose"`
	Managers   []DockerManager `json:"managers"`
	Containers []DContainer    `json:"containers"`
	Stacks     []DStack        `json:"stacks"`
	Images     []DImage        `json:"images"`
	Volumes    []DVolume       `json:"volumes"`
	Networks   []DNetwork      `json:"networks"`
}

type DockerManager struct {
	Name      string `json:"name"` // Portainer, Dockge, Yacht, Komodo
	Container string `json:"container"`
	Running   bool   `json:"running"`
	URL       string `json:"url,omitempty"` // scheme://:port, the app adds the server's address
}

type DContainer struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Image    string   `json:"image"`
	ImageID  string   `json:"imageId"`
	State    string   `json:"state"`
	Status   string   `json:"status"`
	Created  int64    `json:"created"`
	Ports    []string `json:"ports"`
	Networks []string `json:"networks"`
	Volumes  []string `json:"volumes"`
	Project  string   `json:"project,omitempty"`
	Service  string   `json:"service,omitempty"`
	CPU      string   `json:"cpu,omitempty"`
	Memory   string   `json:"memory,omitempty"`
}

type DStack struct {
	Name     string   `json:"name"`
	Manager  string   `json:"manager"` // dockge, portainer, compose
	Dir      string   `json:"dir,omitempty"`
	Files    []string `json:"files"`
	Editable bool     `json:"editable"` // file can be changed and redeployed here
	Total    int      `json:"total"`
	Running  int      `json:"running"`
}

type DImage struct {
	ID      string   `json:"id"`
	Tags    []string `json:"tags"`
	Size    int64    `json:"size"`
	Created int64    `json:"created"`
	UsedBy  []string `json:"usedBy"`
}

type DVolume struct {
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Mountpoint string   `json:"mountpoint"`
	UsedBy     []string `json:"usedBy"`
	Anonymous  bool     `json:"anonymous"`
}

type DNetwork struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Scope      string   `json:"scope"`
	Containers []string `json:"containers"`
	Builtin    bool     `json:"builtin"`
}

type DockerRequest struct {
	Op     string `json:"op"`     // list, container, stack, logs, file, save, image, volume, network, prune
	Verb   string `json:"verb"`   // start, stop, restart, pause, unpause, remove, up, down, update…
	Target string `json:"target"` // container / image / volume / network id or name, stack name
	Tail   int    `json:"tail"`
	Text   string `json:"text"`   // save: the new compose file
	Deploy bool   `json:"deploy"` // save: bring the stack up after
	All    bool   `json:"all"`    // prune: every unused one, not only dangling / anonymous
}

// MARK: Reading

type apiContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
}

func dockerGet(sock, path string, v any) error {
	r, err := dockerClient(sock, 10*time.Second).Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		return dockerError(r)
	}
	return json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(v)
}

func dockerDo(sock, method, path string, timeout time.Duration) ([]byte, error) {
	req, _ := http.NewRequest(method, "http://docker"+path, nil)
	r, err := dockerClient(sock, timeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 && r.StatusCode != 304 {
		return nil, dockerError(r)
	}
	return io.ReadAll(io.LimitReader(r.Body, 8<<20))
}

func dockerError(r *http.Response) error {
	var e struct {
		Message string `json:"message"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&e)
	if e.Message == "" {
		e.Message = r.Status
	}
	return errors.New(e.Message)
}

// DockerList: everything, with CPU and memory from the latest reading.
func DockerList(stats []Container) DockerReport {
	rep := DockerReport{Managers: []DockerManager{}, Containers: []DContainer{}, Stacks: []DStack{}, Images: []DImage{}, Volumes: []DVolume{}, Networks: []DNetwork{}}
	sock := containerSocket()
	if sock == "" {
		rep.Problem = "Docker isn't installed or running on this server."
		return rep
	}
	var ver struct{ Version string }
	if err := dockerGet(sock, "/version", &ver); err != nil {
		rep.Problem = "Docker isn't answering: " + err.Error()
		return rep
	}
	rep.Available, rep.Version = true, ver.Version
	_, rep.Compose = composeCommand()

	var cs []apiContainer
	dockerGet(sock, "/containers/json?all=1", &cs)
	byID := map[string]Container{}
	for _, c := range stats {
		byID[c.ID] = c
	}
	for _, c := range cs {
		rep.Containers = append(rep.Containers, toDContainer(c, byID))
	}
	sort.Slice(rep.Containers, func(i, j int) bool { return rep.Containers[i].Name < rep.Containers[j].Name })
	rep.Managers = findManagers(cs)
	rep.Stacks = buildStacks(cs, sock)

	var imgs []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
		Size     int64    `json:"Size"`
		Created  int64    `json:"Created"`
	}
	dockerGet(sock, "/images/json", &imgs)
	for _, im := range imgs {
		d := DImage{ID: im.ID, Tags: []string{}, Size: im.Size, Created: im.Created, UsedBy: []string{}}
		for _, t := range im.RepoTags {
			if t != "<none>:<none>" {
				d.Tags = append(d.Tags, t)
			}
		}
		for _, c := range rep.Containers {
			if c.ImageID == im.ID {
				d.UsedBy = append(d.UsedBy, c.Name)
			}
		}
		rep.Images = append(rep.Images, d)
	}
	sort.Slice(rep.Images, func(i, j int) bool { return rep.Images[i].Size > rep.Images[j].Size })

	var vols struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Volumes"`
	}
	dockerGet(sock, "/volumes", &vols)
	for _, v := range vols.Volumes {
		d := DVolume{Name: v.Name, Driver: v.Driver, Mountpoint: v.Mountpoint, UsedBy: []string{}, Anonymous: v.Labels["com.docker.volume.anonymous"] != "" || len(v.Name) == 64 && isHex(v.Name)}
		for _, c := range rep.Containers {
			for _, n := range c.Volumes {
				if n == v.Name {
					d.UsedBy = append(d.UsedBy, c.Name)
				}
			}
		}
		rep.Volumes = append(rep.Volumes, d)
	}
	sort.Slice(rep.Volumes, func(i, j int) bool { return rep.Volumes[i].Name < rep.Volumes[j].Name })

	var nets []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Driver string `json:"Driver"`
		Scope  string `json:"Scope"`
	}
	dockerGet(sock, "/networks", &nets)
	for _, n := range nets {
		d := DNetwork{ID: n.ID, Name: n.Name, Driver: n.Driver, Scope: n.Scope, Containers: []string{},
			Builtin: n.Name == "bridge" || n.Name == "host" || n.Name == "none"}
		for _, c := range rep.Containers {
			for _, x := range c.Networks {
				if x == n.Name {
					d.Containers = append(d.Containers, c.Name)
				}
			}
		}
		rep.Networks = append(rep.Networks, d)
	}
	sort.Slice(rep.Networks, func(i, j int) bool { return rep.Networks[i].Name < rep.Networks[j].Name })
	return rep
}

func isHex(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func toDContainer(c apiContainer, stats map[string]Container) DContainer {
	d := DContainer{ID: c.ID, Image: c.Image, ImageID: c.ImageID, State: c.State, Status: c.Status, Created: c.Created,
		Ports: []string{}, Networks: []string{}, Volumes: []string{}, Project: c.Labels["com.docker.compose.project"], Service: c.Labels["com.docker.compose.service"]}
	if len(c.Names) > 0 {
		d.Name = strings.TrimPrefix(c.Names[0], "/")
	}
	for _, p := range c.Ports {
		if p.PublicPort > 0 {
			ip := p.IP
			if ip == "0.0.0.0" || ip == "::" || ip == "" {
				ip = ""
			} else {
				ip += ":"
			}
			d.Ports = mergeStrings(d.Ports, []string{fmt.Sprintf("%s%d→%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type)})
		}
	}
	for n := range c.NetworkSettings.Networks {
		d.Networks = append(d.Networks, n)
	}
	sort.Strings(d.Networks)
	for _, m := range c.Mounts {
		if m.Type == "volume" && m.Name != "" {
			d.Volumes = append(d.Volumes, m.Name)
		}
	}
	short := c.ID
	if len(short) > 12 {
		short = short[:12]
	}
	if s, ok := stats[short]; ok {
		d.CPU, d.Memory = s.CPU, s.Memory
	}
	return d
}

// MARK: Managers and stacks

var managerImages = []struct{ word, name, scheme, port string }{
	{"portainer/portainer", "Portainer", "https", "9443"},
	{"portainer/agent", "Portainer Agent", "", ""},
	{"louislam/dockge", "Dockge", "http", "5001"},
	{"selfhostedpro/yacht", "Yacht", "http", "8000"},
	{"komodo", "Komodo", "http", "9120"},
	{"dockpeek", "Dockpeek", "http", "3420"},
}

func findManagers(cs []apiContainer) []DockerManager {
	out := []DockerManager{}
	for _, c := range cs {
		img := strings.ToLower(c.Image)
		for _, m := range managerImages {
			if !strings.Contains(img, m.word) {
				continue
			}
			d := DockerManager{Name: m.name, Running: c.State == "running"}
			if len(c.Names) > 0 {
				d.Container = strings.TrimPrefix(c.Names[0], "/")
			}
			if m.port != "" {
				for _, p := range c.Ports { // the port it's published on
					if fmt.Sprint(p.PrivatePort) == m.port && p.PublicPort > 0 {
						d.URL = fmt.Sprintf("%s://:%d", m.scheme, p.PublicPort)
					}
				}
				if d.URL == "" && m.name == "Portainer" {
					for _, p := range c.Ports {
						if p.PrivatePort == 9000 && p.PublicPort > 0 {
							d.URL = fmt.Sprintf("http://:%d", p.PublicPort)
						}
					}
				}
			}
			out = append(out, d)
			break
		}
	}
	return out
}

// dockgeStacksDir: Dockge's stacks folder on the server (DOCKGE_STACKS_DIR, /opt/stacks by default).
func dockgeStacksDir(sock string, cs []apiContainer) string {
	for _, c := range cs {
		if !strings.Contains(strings.ToLower(c.Image), "louislam/dockge") {
			continue
		}
		var in dockerInspect
		var env struct {
			Config struct{ Env []string } `json:"Config"`
		}
		dockerGet(sock, "/containers/"+c.ID+"/json", &in)
		dockerGet(sock, "/containers/"+c.ID+"/json", &env)
		dir := "/opt/stacks"
		for _, e := range env.Config.Env {
			if v, ok := strings.CutPrefix(e, "DOCKGE_STACKS_DIR="); ok {
				dir = v
			}
		}
		if hp := in.hostPath(dir); hp != "" {
			return hp
		}
		return dir
	}
	return ""
}

func portainerData(sock string, cs []apiContainer) string {
	for _, c := range cs {
		if strings.Contains(strings.ToLower(c.Image), "portainer/portainer") {
			var in dockerInspect
			dockerGet(sock, "/containers/"+c.ID+"/json", &in)
			return in.hostPath("/data")
		}
	}
	return ""
}

var composeNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

func buildStacks(cs []apiContainer, sock string) []DStack {
	dockge, portainer := dockgeStacksDir(sock, cs), portainerData(sock, cs)
	byName := map[string]*DStack{}
	var order []string
	for _, c := range cs {
		p := c.Labels["com.docker.compose.project"]
		if p == "" {
			continue
		}
		s, ok := byName[p]
		if !ok {
			s = &DStack{Name: p, Manager: "compose", Files: []string{}, Dir: c.Labels["com.docker.compose.project.working_dir"]}
			for _, f := range strings.Split(c.Labels["com.docker.compose.project.config_files"], ",") {
				if f = strings.TrimSpace(f); f != "" {
					s.Files = append(s.Files, f)
				}
			}
			byName[p] = s
			order = append(order, p)
		}
		s.Total++
		if c.State == "running" {
			s.Running++
		}
	}
	// Dockge's stacks with nothing running (or never started).
	if dockge != "" {
		entries, _ := os.ReadDir(dockge)
		for _, e := range entries {
			if !e.IsDir() || byName[e.Name()] != nil {
				continue
			}
			for _, n := range composeNames {
				f := filepath.Join(dockge, e.Name(), n)
				if _, err := os.Stat(f); err == nil {
					byName[e.Name()] = &DStack{Name: e.Name(), Dir: filepath.Join(dockge, e.Name()), Files: []string{f}}
					order = append(order, e.Name())
					break
				}
			}
		}
	}
	out := []DStack{}
	for _, n := range order {
		s := byName[n]
		switch {
		case dockge != "" && strings.HasPrefix(s.Dir, strings.TrimSuffix(dockge, "/")+"/"):
			s.Manager = "dockge"
		case strings.HasPrefix(s.Dir, "/data/compose/") && portainer != "":
			s.Manager = "portainer"
		default:
			if s.Manager == "" {
				s.Manager = "compose"
			}
		}
		s.Editable = s.Manager != "portainer" && len(s.Files) > 0 && fileExists(s.Files[0])
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

// composeCommand: `docker compose` (the plugin) or `docker-compose`.
func composeCommand() ([]string, bool) {
	if have("docker") {
		if _, err := run(10*time.Second, "docker", "compose", "version"); err == nil {
			return []string{"docker", "compose"}, true
		}
	}
	if have("docker-compose") {
		return []string{"docker-compose"}, true
	}
	return nil, false
}

// MARK: Doing

func DockerDo(req DockerRequest, stats []Container) (any, error) {
	if req.Op == "list" {
		return DockerList(stats), nil
	}
	sock := containerSocket()
	if sock == "" {
		return nil, errors.New("Docker isn't running on this server")
	}
	var cs []apiContainer
	if err := dockerGet(sock, "/containers/json?all=1", &cs); err != nil {
		return nil, err
	}
	container := func() (*apiContainer, error) {
		for i, c := range cs {
			if c.ID == req.Target || len(c.Names) > 0 && strings.TrimPrefix(c.Names[0], "/") == req.Target {
				return &cs[i], nil
			}
		}
		return nil, fmt.Errorf("there's no container called %s", req.Target)
	}
	stack := func() (*DStack, error) {
		for _, s := range buildStacks(cs, sock) {
			if s.Name == req.Target {
				return &s, nil
			}
		}
		return nil, fmt.Errorf("there's no stack called %s", req.Target)
	}
	switch req.Op {
	case "container":
		c, err := container()
		if err != nil {
			return nil, err
		}
		return nil, containerVerb(sock, c.ID, req.Verb)
	case "logs":
		c, err := container()
		if err != nil {
			return nil, err
		}
		tail := req.Tail
		if tail <= 0 || tail > 5000 {
			tail = 300
		}
		b, err := dockerDo(sock, "GET", fmt.Sprintf("/containers/%s/logs?stdout=1&stderr=1&timestamps=1&tail=%d", c.ID, tail), 15*time.Second)
		if err != nil {
			return nil, err
		}
		return map[string]string{"text": demuxLogs(b)}, nil
	case "stack":
		s, err := stack()
		if err != nil {
			return nil, err
		}
		return stackVerb(sock, cs, s, req.Verb)
	case "file":
		s, err := stack()
		if err != nil {
			return nil, err
		}
		if len(s.Files) == 0 || s.Manager == "portainer" {
			return nil, errors.New("this stack's file is kept by Portainer: open it there")
		}
		b, err := os.ReadFile(s.Files[0])
		if err != nil {
			return nil, err
		}
		if len(b) > 1<<20 {
			return nil, errors.New("the file is too big to show here")
		}
		return map[string]any{"text": string(b), "path": s.Files[0], "editable": s.Editable}, nil
	case "save":
		s, err := stack()
		if err != nil {
			return nil, err
		}
		if !s.Editable {
			return nil, errors.New("this stack's file can't be changed here")
		}
		return saveCompose(s, req.Text, req.Deploy)
	case "image":
		if req.Verb != "remove" || !safeName.MatchString(req.Target) {
			return nil, errors.New("unknown action")
		}
		_, err := dockerDo(sock, "DELETE", "/images/"+url.PathEscape(req.Target), 60*time.Second)
		return nil, err
	case "volume":
		if req.Verb != "remove" || !safeName.MatchString(req.Target) {
			return nil, errors.New("unknown action")
		}
		_, err := dockerDo(sock, "DELETE", "/volumes/"+url.PathEscape(req.Target), 60*time.Second)
		return nil, err
	case "network":
		if req.Verb != "remove" || !safeName.MatchString(req.Target) || req.Target == "bridge" || req.Target == "host" || req.Target == "none" {
			return nil, errors.New("Docker's own networks can't be removed")
		}
		_, err := dockerDo(sock, "DELETE", "/networks/"+url.PathEscape(req.Target), 30*time.Second)
		return nil, err
	case "prune":
		return prune(sock, req.Target, req.All)
	}
	return nil, errors.New("unknown action")
}

func containerVerb(sock, id, verb string) error {
	var err error
	switch verb {
	case "start", "stop", "restart", "pause", "unpause":
		_, err = dockerDo(sock, "POST", "/containers/"+id+"/"+verb, 90*time.Second)
	case "remove":
		_, err = dockerDo(sock, "DELETE", "/containers/"+id+"?force=1", 90*time.Second)
	default:
		err = errors.New("unknown action")
	}
	return err
}

// stackVerb: start / stop / restart work on any stack (container by
// container); up / down / update need its compose file and `docker compose`.
func stackVerb(sock string, cs []apiContainer, s *DStack, verb string) (any, error) {
	switch verb {
	case "start", "stop", "restart":
		var failed []string
		for _, c := range cs {
			if c.Labels["com.docker.compose.project"] != s.Name {
				continue
			}
			if verb == "start" && c.State == "running" || verb == "stop" && c.State != "running" {
				continue
			}
			if err := containerVerb(sock, c.ID, verb); err != nil {
				failed = append(failed, strings.TrimPrefix(c.Names[0], "/")+": "+err.Error())
			}
		}
		if len(failed) > 0 {
			return nil, errors.New(strings.Join(failed, "; "))
		}
		return nil, nil
	case "up", "down", "update":
		if s.Manager == "portainer" {
			return nil, errors.New("Portainer keeps this stack's settings: deploy it from Portainer (start, stop and restart work here)")
		}
		if len(s.Files) == 0 || !fileExists(s.Files[0]) {
			return nil, errors.New("its compose file isn't on this server")
		}
		var out strings.Builder
		steps := [][]string{{"up", "-d", "--remove-orphans"}}
		if verb == "down" {
			steps = [][]string{{"down"}}
		} else if verb == "update" {
			steps = [][]string{{"pull"}, {"up", "-d", "--remove-orphans"}}
		}
		for _, st := range steps {
			o, err := compose(s, st...)
			out.WriteString(o)
			if err != nil {
				return map[string]string{"text": out.String()}, fmt.Errorf("docker compose %s didn't work: %s", st[0], lastLine(o))
			}
		}
		return map[string]string{"text": out.String()}, nil
	}
	return nil, errors.New("unknown action")
}

func compose(s *DStack, args ...string) (string, error) {
	cmd, ok := composeCommand()
	if !ok {
		return "", errors.New("Docker Compose isn't installed on this server")
	}
	full := append(append([]string{}, cmd[1:]...), "-p", s.Name)
	if s.Dir != "" {
		full = append(full, "--project-directory", s.Dir)
	}
	for _, f := range s.Files {
		full = append(full, "-f", f)
	}
	full = append(full, args...)
	return combined(10*time.Minute, cmd[0], full...)
}

// saveCompose: the new file is checked with `docker compose config`
// before it stays; a bad one is put back as it was.
func saveCompose(s *DStack, text string, deploy bool) (any, error) {
	if len(text) > 1<<20 || strings.TrimSpace(text) == "" {
		return nil, errors.New("that file is empty or too big")
	}
	file := s.Files[0]
	old := stateOf(file)
	if err := putState(file, fileState{exists: true, data: []byte(text), mode: old.mode | 0o600}); err != nil {
		return nil, err
	}
	if o, err := compose(s, "config", "-q"); err != nil {
		putState(file, old)
		return nil, fmt.Errorf("docker compose found a problem, so the file wasn't changed: %s", lastLine(o))
	}
	os.WriteFile(file+".apex-before", old.data, 0o600)
	if !deploy {
		return nil, nil
	}
	return stackVerb("", nil, s, "up")
}

func prune(sock, what string, all bool) (any, error) {
	var path string
	switch what {
	case "images":
		path = "/images/prune"
		if all {
			path += "?filters=" + url.QueryEscape(`{"dangling":["false"]}`)
		}
	case "volumes":
		path = "/volumes/prune"
		if all {
			path += "?filters=" + url.QueryEscape(`{"all":["true"]}`)
		}
	case "networks":
		path = "/networks/prune"
	case "containers":
		path = "/containers/prune"
	default:
		return nil, errors.New("unknown action")
	}
	b, err := dockerDo(sock, "POST", path, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	var r struct {
		SpaceReclaimed int64 `json:"SpaceReclaimed"`
	}
	json.Unmarshal(b, &r)
	return map[string]int64{"reclaimed": r.SpaceReclaimed}, nil
}

// demuxLogs: Docker's log stream (8-byte frame headers when the container
// has no terminal), as plain text.
func demuxLogs(b []byte) string {
	var out bytes.Buffer
	rest := b
	for len(rest) >= 8 && rest[0] <= 2 && rest[1] == 0 && rest[2] == 0 && rest[3] == 0 {
		n := int(binary.BigEndian.Uint32(rest[4:8]))
		if 8+n > len(rest) {
			break
		}
		out.Write(rest[8 : 8+n])
		rest = rest[8+n:]
	}
	if out.Len() == 0 {
		return string(b)
	}
	out.Write(rest)
	return out.String()
}

// MARK: HTTP

func (s *Server) docker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req DockerRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Bad request."})
		return
	}
	res, err := DockerDo(req, s.collector.Latest().Containers)
	if req.Op != "list" && req.Op != "logs" && req.Op != "file" {
		log.Printf("docker %s %s %s from %s: %s", req.Op, req.Verb, req.Target, clientIP(r), errText(err))
		go s.collector.RefreshSlow()
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": capitalize(strings.TrimSuffix(err.Error(), ".")) + ".", "result": res})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res})
}
