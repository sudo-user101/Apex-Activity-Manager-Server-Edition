package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Services, containers, signed-in users, GPUs, and the actions that change
// the server. Whatever the distribution has: systemd, OpenRC or SysV init;
// Docker or Podman.

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil && errb.Len() > 0 {
		err = errors.New(strings.TrimSpace(errb.String()))
	}
	return out.String(), err
}

func have(name string) bool {
	for _, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if st, err := os.Stat(filepath.Join(d, name)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// MARK: Services

func serviceManager() string {
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() && have("systemctl") {
		return "systemd"
	}
	if have("rc-status") && have("rc-service") {
		return "openrc"
	}
	if have("service") {
		return "sysv"
	}
	return ""
}

func listServices() ([]Service, string) {
	m := serviceManager()
	switch m {
	case "systemd":
		out, _ := run(10*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
		return parseSystemd(out), m
	case "openrc":
		out, _ := run(10*time.Second, "rc-status", "--all")
		return parseOpenRC(out), m
	case "sysv":
		out, _ := run(15*time.Second, "service", "--status-all")
		return parseSysV(out), m
	}
	return []Service{}, m
}

func parseSystemd(text string) []Service {
	out := []Service{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimLeft(line, "●* "))
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		v := Service{Name: strings.TrimSuffix(f[0], ".service"), Loaded: f[1], Active: f[2], Sub: f[3]}
		if len(f) > 4 {
			v.Description = strings.Join(f[4:], " ")
		}
		out = append(out, v)
	}
	return out
}

var openrcLine = regexp.MustCompile(`^\s*(\S+)\s+\[\s*([a-z ]+?)\s*\]`)

// parseOpenRC: " sshd   [  started  ]" under "Runlevel: …" headers.
func parseOpenRC(text string) []Service {
	out := []Service{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		m := openrcLine.FindStringSubmatch(line)
		if m == nil || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		st := strings.Fields(m[2])[0]
		v := Service{Name: m[1], Loaded: "loaded", Active: "inactive", Sub: st}
		switch st {
		case "started":
			v.Active, v.Sub = "active", "running"
		case "crashed":
			v.Active, v.Sub = "failed", "failed"
		case "stopped":
			v.Sub = "dead"
		}
		out = append(out, v)
	}
	return out
}

// parseSysV: " [ + ]  cron" (running), "[ - ]" stopped, "[ ? ]" unknown.
func parseSysV(text string) []Service {
	out := []Service{}
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if len(l) < 7 || l[0] != '[' {
			continue
		}
		mark, name := strings.TrimSpace(l[1:4]), strings.TrimSpace(l[6:])
		if name == "" {
			continue
		}
		v := Service{Name: name, Loaded: "loaded", Active: "inactive", Sub: "dead"}
		if mark == "+" {
			v.Active, v.Sub = "active", "running"
		} else if mark == "?" {
			v.Sub = "unknown"
		}
		out = append(out, v)
	}
	return out
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9@._:+-]{1,200}$`)

func serviceAction(verb, name string, known []Service) error {
	if verb != "start" && verb != "stop" && verb != "restart" {
		return errors.New("unknown action")
	}
	if !safeName.MatchString(name) {
		return errors.New("that isn't a service name")
	}
	found := false
	for _, v := range known {
		found = found || v.Name == name
	}
	if !found {
		return fmt.Errorf("there's no service called %s", name)
	}
	var err error
	switch serviceManager() {
	case "systemd":
		_, err = run(60*time.Second, "systemctl", verb, name+".service")
	case "openrc":
		_, err = run(60*time.Second, "rc-service", name, verb)
	case "sysv":
		_, err = run(60*time.Second, "service", name, verb)
	default:
		err = errors.New("this server has no service manager Apex knows")
	}
	return err
}

// MARK: Processes

// powerOff shuts the server down, with whatever init it has.
func powerOff() {
	for _, c := range [][]string{{"systemctl", "poweroff"}, {"poweroff"}, {"shutdown", "-h", "now"}} {
		if have(c[0]) {
			if _, err := run(30*time.Second, c[0], c[1:]...); err == nil {
				return
			}
		}
	}
}

func endProcess(pid int, force bool) error {
	if pid <= 1 || pid == os.Getpid() {
		return errors.New("that process can't be ended from Apex")
	}
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(pid, sig); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil // already gone
		}
		return err
	}
	return nil
}

// MARK: Containers (Docker or Podman, through their socket: no CLI needed)

func containerSocket() string {
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock"} {
		if st, err := os.Stat(p); err == nil && st.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return ""
}

// One connection pool per Docker socket, shared by every request. A new
// pool per request (as before 1.1) kept each one's connection open for
// good: over a day, thousands of open sockets on a server running Docker.
var (
	dockerPoolsMu sync.Mutex
	dockerPools   = map[string]*http.Transport{}
)

func dockerClient(sock string, timeout time.Duration) *http.Client {
	dockerPoolsMu.Lock()
	t, ok := dockerPools[sock]
	if !ok {
		t = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
			MaxIdleConns:        8,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     30 * time.Second,
		}
		dockerPools[sock] = t
	}
	dockerPoolsMu.Unlock()
	return &http.Client{Timeout: timeout, Transport: t}
}

type dockerContainer struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

type dockerStats struct {
	CPU struct {
		Usage struct {
			Total uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System uint64 `json:"system_cpu_usage"`
		Online int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPU struct {
		Usage struct {
			Total uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	Memory struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		Rx uint64 `json:"rx_bytes"`
		Tx uint64 `json:"tx_bytes"`
	} `json:"networks"`
	Blkio struct {
		Entries []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
}

func listContainers() []Container {
	sock := containerSocket()
	if sock == "" {
		return []Container{}
	}
	cl := dockerClient(sock, 5*time.Second)
	resp, err := cl.Get("http://docker/containers/json?all=1")
	if err != nil {
		return []Container{}
	}
	defer resp.Body.Close()
	var list []dockerContainer
	if json.NewDecoder(resp.Body).Decode(&list) != nil {
		return []Container{}
	}
	out := make([]Container, len(list))
	var wg sync.WaitGroup
	for i, d := range list {
		name := ""
		if len(d.Names) > 0 {
			name = strings.TrimPrefix(d.Names[0], "/")
		}
		id := d.ID
		if len(id) > 12 {
			id = id[:12]
		}
		out[i] = Container{ID: id, Name: name, Image: d.Image, State: d.State, Status: d.Status}
		if d.State != "running" {
			continue
		}
		wg.Add(1)
		go func(i int, full string) {
			defer wg.Done()
			r, err := dockerClient(sock, 6*time.Second).Get("http://docker/containers/" + full + "/stats?stream=false")
			if err != nil {
				return
			}
			defer r.Body.Close()
			var st dockerStats
			if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&st) == nil {
				out[i].CPU, out[i].Memory, out[i].Net, out[i].Block = formatStats(st)
			}
		}(i, d.ID)
	}
	wg.Wait()
	return out
}

// formatStats: the same text `docker stats` shows ("1.23%", "425.8MiB / 3.813GiB"). Pure: tested.
func formatStats(st dockerStats) (cpu, mem, netio, block string) {
	cpuDelta := float64(st.CPU.Usage.Total) - float64(st.PreCPU.Usage.Total)
	sysDelta := float64(st.CPU.System) - float64(st.PreCPU.System)
	pct := 0.0
	if cpuDelta > 0 && sysDelta > 0 {
		n := st.CPU.Online
		if n == 0 {
			n = 1
		}
		pct = cpuDelta / sysDelta * float64(n) * 100
	}
	used := st.Memory.Usage
	if c, ok := st.Memory.Stats["inactive_file"]; ok && c < used { // as docker CLI (cgroup v2)
		used -= c
	} else if c, ok := st.Memory.Stats["total_inactive_file"]; ok && c < used {
		used -= c
	}
	var rx, tx uint64
	for _, n := range st.Networks {
		rx += n.Rx
		tx += n.Tx
	}
	var rd, wr uint64
	for _, e := range st.Blkio.Entries {
		switch strings.ToLower(e.Op) {
		case "read":
			rd += e.Value
		case "write":
			wr += e.Value
		}
	}
	return fmt.Sprintf("%.2f%%", pct), binary1024(used) + " / " + binary1024(st.Memory.Limit), decimal(rx) + " / " + decimal(tx), decimal(rd) + " / " + decimal(wr)
}

func binary1024(b uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, i := float64(b), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%dB", b)
	}
	return fmt.Sprintf("%.4g%s", v, units[i])
}

func decimal(b uint64) string {
	units := []string{"B", "kB", "MB", "GB", "TB"}
	v, i := float64(b), 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%dB", b)
	}
	return fmt.Sprintf("%.3g%s", v, units[i])
}

func containerAction(verb, id string, known []Container) error {
	if verb != "start" && verb != "stop" && verb != "restart" && verb != "unpause" {
		return errors.New("unknown action")
	}
	found := false
	for _, c := range known {
		found = found || c.ID == id || c.Name == id
	}
	if !found || !safeName.MatchString(id) {
		return fmt.Errorf("there's no container called %s", id)
	}
	sock := containerSocket()
	if sock == "" {
		return errors.New("Docker isn't running on this server")
	}
	resp, err := dockerClient(sock, 60*time.Second).Post("http://docker/containers/"+id+"/"+verb, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != 304 {
		var e struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		if e.Message == "" {
			e.Message = resp.Status
		}
		return errors.New(e.Message)
	}
	return nil
}

// MARK: Signed-in users

// parseUtmp: who's signed in, from glibc's utmp records (384 bytes each). Pure: tested.
func parseUtmp(b []byte) []Session {
	out := []Session{}
	const size = 384
	for i := 0; i+size <= len(b); i += size {
		r := b[i : i+size]
		if binary.LittleEndian.Uint32(r[0:4]) != 7 { // USER_PROCESS
			continue
		}
		user, line, host := cstr(r[44:76]), cstr(r[8:40]), cstr(r[76:332])
		if user != "" {
			out = append(out, Session{User: user, Terminal: line, From: host})
		}
	}
	return out
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func listSessions() []Session {
	for _, p := range []string{"/run/utmp", "/var/run/utmp"} {
		if b, err := os.ReadFile(p); err == nil && len(b) >= 384 {
			return parseUtmp(b)
		}
	}
	// Distributions without utmp (newer systemd ones): logind's sessions.
	if have("loginctl") {
		out, _ := run(5*time.Second, "loginctl", "list-sessions", "--no-legend")
		s := []Session{}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				tty := ""
				if len(f) >= 5 {
					tty = f[4]
				}
				s = append(s, Session{User: f[2], Terminal: tty})
			}
		}
		return s
	}
	return []Session{}
}

// MARK: GPUs (NVIDIA through nvidia-smi; AMD from sysfs)

func listGPUs() []GPU {
	out := []GPU{}
	if have("nvidia-smi") {
		text, _ := run(5*time.Second, "nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu", "--format=csv,noheader,nounits")
		for _, line := range strings.Split(text, "\n") {
			f := strings.Split(line, ",")
			if len(f) == 5 {
				out = append(out, GPU{Name: strings.TrimSpace(f[0]), Utilization: atof(f[1]), MemoryUsed: int64(atof(f[2]) * 1048576),
					MemoryTotal: int64(atof(f[3]) * 1048576), Temperature: atof(f[4])})
			}
		}
	}
	cards, _ := filepath.Glob(filepath.Join(sysRoot, "class/drm/card[0-9]*/device/gpu_busy_percent"))
	for _, busyFile := range cards {
		dev := filepath.Dir(busyFile)
		g := GPU{Name: "AMD GPU", Utilization: atof(readText(busyFile)),
			MemoryUsed: atoi(readText(filepath.Join(dev, "mem_info_vram_used"))), MemoryTotal: atoi(readText(filepath.Join(dev, "mem_info_vram_total")))}
		if temps, _ := filepath.Glob(filepath.Join(dev, "hwmon/hwmon*/temp1_input")); len(temps) > 0 {
			g.Temperature = float64(atoi(readText(temps[0]))) / 1000
		}
		out = append(out, g)
	}
	return out
}
