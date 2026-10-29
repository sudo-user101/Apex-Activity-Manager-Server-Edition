package main

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Collector reads the server every couple of seconds (slower when nobody is
// looking) and keeps the latest reading. Slow sources (services, containers,
// signed-in users, GPUs) have their own, slower loops.
type Collector struct {
	mu   sync.RWMutex
	last Snapshot

	// Previous readings, for rates.
	prevTime  time.Time
	prevCPU   []cpuTimes
	prevNet   map[string][2]int64
	prevDisk  map[string][3]int64
	prevProc  map[int]procPrev
	clk       float64
	pageSize  int64
	users     map[int]string
	usersRead time.Time
	model     string

	slow struct {
		sync.RWMutex
		services   []Service
		manager    string
		containers []Container
		sessions   []Session
		gpus       []GPU
	}
	lastAsked time.Time
	askedMu   sync.Mutex
}

type procPrev struct {
	ticks       uint64
	start       uint64
	read, write int64
}

func NewCollector() *Collector {
	c := &Collector{prevProc: map[int]procPrev{}, pageSize: int64(os.Getpagesize())}
	auxv, _ := os.ReadFile(filepath.Join(procRoot, "self/auxv"))
	c.clk = float64(clockTicks(auxv))
	c.model = parseCPUModel(readText(filepath.Join(procRoot, "cpuinfo")))
	return c
}

// Latest reading; marks that someone is watching (sampling speeds up).
func (c *Collector) Latest() Snapshot {
	c.askedMu.Lock()
	c.lastAsked = time.Now()
	c.askedMu.Unlock()
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last
}

func (c *Collector) watched() bool {
	c.askedMu.Lock()
	defer c.askedMu.Unlock()
	return time.Since(c.lastAsked) < time.Minute
}

// Run samples forever: every 2 s while someone is watching, every 15 s otherwise.
func (c *Collector) Run() {
	go c.slowLoop()
	c.Sample()
	for {
		wait := 15 * time.Second
		if c.watched() {
			wait = 2 * time.Second
		}
		time.Sleep(wait)
		c.Sample()
	}
}

func (c *Collector) slowLoop() {
	for {
		services, manager := listServices()
		containers := listContainers()
		sessions := listSessions()
		gpus := listGPUs()
		c.slow.Lock()
		c.slow.services, c.slow.manager, c.slow.containers, c.slow.sessions, c.slow.gpus = services, manager, containers, sessions, gpus
		c.slow.Unlock()
		wait := 60 * time.Second
		if c.watched() {
			wait = 5 * time.Second
		}
		time.Sleep(wait)
	}
}

// RefreshSlow re-reads services and containers now (after an action).
func (c *Collector) RefreshSlow() {
	services, manager := listServices()
	containers := listContainers()
	c.slow.Lock()
	c.slow.services, c.slow.manager, c.slow.containers = services, manager, containers
	c.slow.Unlock()
}

func (c *Collector) Sample() {
	now := time.Now()
	dt := now.Sub(c.prevTime).Seconds()
	first := c.prevTime.IsZero()
	if first || dt <= 0 {
		dt = 1
	}
	s := Snapshot{Agent: 2, Edition: "server", Version: version, Taken: now.UnixMilli(), InContainer: inContainer()}
	// Empty lists, never null: the app reads them as lists.
	s.Disks, s.Network, s.Processes, s.GPUs, s.Containers = []Disk{}, []Net{}, []Process{}, []GPU{}, []Container{}
	s.FailedServices, s.Services, s.Sessions, s.WebServers, s.Sensors = []string{}, []Service{}, []Session{}, []string{}, []Sensor{}
	s.CPU.PerCore, s.CPU.Load = []float64{}, []float64{}
	s.Host, _ = os.Hostname()
	osr := parseOSRelease(readText(filepath.Join(etcRoot, "os-release")))
	if osr["PRETTY_NAME"] == "" {
		osr = parseOSRelease(readText("/usr/lib/os-release"))
	}
	s.OS = osr["PRETTY_NAME"]
	if s.OS == "" {
		s.OS = "Linux"
	}
	s.Kernel = strings.TrimSpace(readText(filepath.Join(procRoot, "sys/kernel/osrelease")))
	if f := strings.Fields(readText(filepath.Join(procRoot, "uptime"))); len(f) > 0 {
		s.Uptime = atof(f[0])
	}

	// CPU
	cpu := parseStat(readText(filepath.Join(procRoot, "stat")))
	if len(cpu) > 0 {
		if len(c.prevCPU) == len(cpu) {
			s.CPU.Total = busy(c.prevCPU[0], cpu[0])
			for i := 1; i < len(cpu); i++ {
				s.CPU.PerCore = append(s.CPU.PerCore, busy(c.prevCPU[i], cpu[i]))
			}
		} else {
			s.CPU.PerCore = make([]float64, len(cpu)-1)
		}
		s.CPU.Cores = len(cpu) - 1
		c.prevCPU = cpu
	}
	s.CPU.Model = c.model
	for _, v := range strings.Fields(readText(filepath.Join(procRoot, "loadavg"))) {
		if len(s.CPU.Load) < 3 {
			s.CPU.Load = append(s.CPU.Load, atof(v))
		}
	}

	// Memory
	m := parseMeminfo(readText(filepath.Join(procRoot, "meminfo")))
	avail := m["MemAvailable"]
	if avail == 0 { // kernels before 3.14
		avail = m["MemFree"] + m["Buffers"] + m["Cached"]
	}
	s.Memory = Memory{Total: m["MemTotal"], Available: avail, Cached: m["Cached"], SwapTotal: m["SwapTotal"], SwapFree: m["SwapFree"]}

	// Network
	nd := parseNetDev(readText(filepath.Join(procRoot, "net/dev")))
	addrs := interfaceAddresses()
	names := make([]string, 0, len(nd))
	for n := range nd {
		if !skipInterface(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		v := nd[n]
		e := Net{Name: n, Received: v[0], Sent: v[1], Addresses: addrs[n], MAC: strings.TrimSpace(readText("/sys/class/net/" + n + "/address"))}
		if p, ok := c.prevNet[n]; ok && !first {
			e.InPerSec, e.OutPerSec = rate(v[0]-p[0], dt), rate(v[1]-p[1], dt)
		}
		s.Network = append(s.Network, e)
	}
	c.prevNet = nd
	s.Connections = countEstablished(readText(filepath.Join(procRoot, "net/tcp"))) + countEstablished(readText(filepath.Join(procRoot, "net/tcp6")))

	// Disks
	ds := parseDiskstats(readText(filepath.Join(procRoot, "diskstats")))
	for _, mt := range realMounts(parseMountinfo(readText(filepath.Join(procRoot, "self/mountinfo")))) {
		var st syscall.Statfs_t
		if syscall.Statfs(mt.target, &st) != nil || st.Blocks == 0 {
			continue
		}
		bs := int64(st.Bsize)
		d := Disk{Device: mt.source, Mount: mt.target, FSType: mt.fstype,
			Total: int64(st.Blocks) * bs, Free: int64(st.Bavail) * bs, Used: int64(st.Blocks-st.Bfree) * bs}
		dev := filepath.Base(mt.source)
		if r, err := filepath.EvalSymlinks(mt.source); err == nil { // /dev/mapper/x → dm-0
			dev = filepath.Base(r)
		}
		if now, ok := ds[dev]; ok {
			if p, ok := c.prevDisk[dev]; ok && !first {
				d.ReadPerSec, d.WritePerSec = rate(now[0]-p[0], dt), rate(now[1]-p[1], dt)
				d.ActivePercent = round1(minf(100, float64(now[2]-p[2])/(dt*10)))
			}
		}
		s.Disks = append(s.Disks, d)
	}
	c.prevDisk = ds

	// Processes
	if time.Since(c.usersRead) > time.Minute || c.users == nil {
		c.users = parsePasswd(readText(filepath.Join(etcRoot, "passwd")))
		c.usersRead = time.Now()
	}
	s.Processes = c.processes(dt, first, s.Uptime, s.Memory.Total)

	// Web servers, by program name.
	for _, w := range []string{"nginx", "apache2", "httpd", "caddy", "traefik", "haproxy", "node", "gunicorn", "uwsgi", "php-fpm", "java"} {
		for _, p := range s.Processes {
			if strings.HasPrefix(p.Name, w) {
				s.WebServers = append(s.WebServers, w)
				break
			}
		}
	}
	s.Sensors = sensors()

	c.slow.RLock()
	if c.slow.services != nil {
		s.Services, s.ServiceManager = c.slow.services, c.slow.manager
	}
	if c.slow.containers != nil {
		s.Containers = c.slow.containers
	}
	if c.slow.sessions != nil {
		s.Sessions = c.slow.sessions
	}
	if c.slow.gpus != nil {
		s.GPUs = c.slow.gpus
	}
	c.slow.RUnlock()
	for _, v := range s.Services {
		if v.Active == "failed" {
			s.FailedServices = append(s.FailedServices, v.Name)
		}
	}

	c.prevTime = now
	c.mu.Lock()
	c.last = s
	c.mu.Unlock()
}

func (c *Collector) processes(dt float64, first bool, uptime float64, memTotal int64) []Process {
	entries, _ := os.ReadDir(procRoot)
	next := make(map[int]procPrev, len(entries))
	out := make([]Process, 0, len(entries))
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		st, ok := parsePidStat(readText(filepath.Join(dir, "stat")))
		if !ok {
			continue
		}
		p := Process{PID: pid, PPID: st.ppid, Name: st.comm, State: st.state, Threads: st.threads}
		if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
			p.Command = cmdline(b)
		}
		if p.Command == "" { // kernel threads
			p.Command = "[" + st.comm + "]"
		}
		if uid, ok := parseUID(readText(filepath.Join(dir, "status"))); ok {
			if n, ok := c.users[uid]; ok {
				p.User = n
			} else {
				p.User = strconv.Itoa(uid)
			}
		}
		p.Memory = st.rssPages * c.pageSize
		if memTotal > 0 {
			p.MemPercent = round1(float64(p.Memory) * 100 / float64(memTotal))
		}
		p.Seconds = int64(uptime - float64(st.starttime)/c.clk)
		ticks := st.utime + st.stime
		r, w := parseIO(readText(filepath.Join(dir, "io")))
		if prev, ok := c.prevProc[pid]; ok && prev.start == st.starttime && !first {
			if ticks >= prev.ticks {
				p.CPU = round1(float64(ticks-prev.ticks) / c.clk / dt * 100)
			}
			p.ReadPerSec, p.WritePerSec = rate(r-prev.read, dt), rate(w-prev.write, dt)
		}
		next[pid] = procPrev{ticks: ticks, start: st.starttime, read: r, write: w}
		if pid == self {
			p.Name = "apex-server"
		}
		out = append(out, p)
	}
	c.prevProc = next
	sort.Slice(out, func(i, j int) bool {
		if out[i].CPU != out[j].CPU {
			return out[i].CPU > out[j].CPU
		}
		return out[i].Memory > out[j].Memory
	})
	return out
}

func rate(delta int64, dt float64) float64 {
	if delta < 0 {
		return 0
	}
	return float64(int64(float64(delta)/dt + 0.5))
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func interfaceAddresses() map[string][]string {
	out := map[string][]string{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		as, _ := i.Addrs()
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				out[i.Name] = append(out[i.Name], ipn.IP.String())
			}
		}
	}
	return out
}

// sensors: temperatures from hwmon (CPU package, NVMe, …), in °C.
func sensors() []Sensor {
	var out []Sensor
	dirs, _ := filepath.Glob(filepath.Join(sysRoot, "class/hwmon/hwmon*"))
	for _, d := range dirs {
		name := strings.TrimSpace(readText(filepath.Join(d, "name")))
		inputs, _ := filepath.Glob(filepath.Join(d, "temp*_input"))
		for _, in := range inputs {
			v := atoi(readText(in))
			if v <= 0 || v > 150000 {
				continue
			}
			label := strings.TrimSpace(readText(strings.TrimSuffix(in, "_input") + "_label"))
			n := name
			if label != "" {
				n += " " + label
			}
			out = append(out, Sensor{Name: n, Celsius: round1(float64(v) / 1000)})
		}
	}
	return out
}
