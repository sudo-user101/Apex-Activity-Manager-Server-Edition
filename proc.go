package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Parsers for /proc and /sys. Pure (text in, values out) so they're tested
// on real files from several distributions; reading lives in collect.go.

var (
	procRoot = "/proc"
	sysRoot  = "/sys"
	etcRoot  = "/etc"
)

func readText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func atoi(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return v
}

func atof(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v
}

// cpuTimes: one entry per "cpu" line (the total first), total and idle ticks.
type cpuTimes struct{ total, idle uint64 }

func parseStat(text string) []cpuTimes {
	var out []cpuTimes
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		var t cpuTimes
		// user nice system idle iowait irq softirq steal (guest is already in user).
		for i := 1; i < len(f) && i <= 8; i++ {
			v, _ := strconv.ParseUint(f[i], 10, 64)
			t.total += v
			if i == 4 || i == 5 {
				t.idle += v
			}
		}
		out = append(out, t)
	}
	return out
}

func busy(a, b cpuTimes) float64 {
	if b.total <= a.total {
		return 0
	}
	total, idle := float64(b.total-a.total), float64(b.idle-a.idle)
	return round1(100 * (total - idle) / total)
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// parseMeminfo: bytes by key ("MemTotal" → …).
func parseMeminfo(text string) map[string]int64 {
	m := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n := atoi(f[0])
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		m[k] = n
	}
	return m
}

// parseNetDev: received and sent bytes by interface.
func parseNetDev(text string) map[string][2]int64 {
	out := map[string][2]int64{}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		name, data, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(data)
		if len(f) < 9 {
			continue
		}
		out[strings.TrimSpace(name)] = [2]int64{atoi(f[0]), atoi(f[8])}
	}
	return out
}

// Interfaces that aren't the server's own network (loopback, container bridges).
func skipInterface(name string) bool {
	for _, p := range []string{"veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "lxc"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return name == "lo"
}

// parseDiskstats: read bytes, written bytes and ms busy by device name.
func parseDiskstats(text string) map[string][3]int64 {
	out := map[string][3]int64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		out[f[2]] = [3]int64{atoi(f[5]) * 512, atoi(f[9]) * 512, atoi(f[12])}
	}
	return out
}

type mount struct{ source, target, fstype string }

// parseMountinfo: what's mounted where (unescaping "\040" for spaces).
func parseMountinfo(text string) []mount {
	var out []mount
	for _, line := range strings.Split(text, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		a, b := strings.Fields(pre), strings.Fields(post)
		if len(a) < 5 || len(b) < 2 {
			continue
		}
		out = append(out, mount{source: unescape(b[1]), target: unescape(a[4]), fstype: b[0]})
	}
	return out
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// File systems that hold the server's data (not /proc, tmpfs, snaps…).
var diskTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "jfs": true,
	"reiserfs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "nfs": true, "nfs4": true,
	"cifs": true, "smb3": true, "bcachefs": true, "fuseblk": true, "9p": true, "virtiofs": true, "ceph": true, "glusterfs": true,
}

// realMounts: one entry per device (bind mounts and repeated subvolumes left
// out), plus a container's own root when it's an overlay.
func realMounts(ms []mount) []mount {
	var out []mount
	seen := map[string]bool{}
	for _, m := range ms {
		ok := diskTypes[m.fstype] || (m.fstype == "overlay" && m.target == "/")
		if !ok || strings.HasPrefix(m.target, "/snap/") || strings.HasPrefix(m.target, "/var/lib/docker/") ||
			strings.HasPrefix(m.target, "/run/") || strings.HasPrefix(m.target, "/proc") || strings.HasPrefix(m.target, "/sys") {
			continue
		}
		key := m.source
		if m.fstype == "btrfs" || m.fstype == "zfs" || m.fstype == "overlay" {
			key = m.source + "|" + m.target // subvolumes / datasets show their own size
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].target < out[j].target })
	return out
}

// pidStat: the fields of /proc/<pid>/stat Apex uses.
type pidStat struct {
	comm         string
	state        string
	ppid         int
	utime, stime uint64
	threads      int
	starttime    uint64
	rssPages     int64
}

// parsePidStat: the name is in parentheses and may itself hold spaces or ")".
func parsePidStat(text string) (pidStat, bool) {
	open, close := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if open < 0 || close < open {
		return pidStat{}, false
	}
	f := strings.Fields(text[close+1:])
	if len(f) < 22 {
		return pidStat{}, false
	}
	u, _ := strconv.ParseUint(f[11], 10, 64)
	s, _ := strconv.ParseUint(f[12], 10, 64)
	st, _ := strconv.ParseUint(f[19], 10, 64)
	return pidStat{comm: text[open+1 : close], state: f[0], ppid: int(atoi(f[1])), utime: u, stime: s,
		threads: int(atoi(f[17])), starttime: st, rssPages: atoi(f[21])}, true
}

// parseUID: the real user id from /proc/<pid>/status.
func parseUID(text string) (int, bool) {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line[4:])
			if len(f) > 0 {
				return int(atoi(f[0])), true
			}
		}
	}
	return 0, false
}

// parseIO: bytes read and written by a process (root only).
func parseIO(text string) (int64, int64) {
	var r, w int64
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(line, "read_bytes:"); ok {
			r = atoi(v)
		} else if v, ok := strings.CutPrefix(line, "write_bytes:"); ok {
			w = atoi(v)
		}
	}
	return r, w
}

// parsePasswd: user names by id.
func parsePasswd(text string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 {
			out[int(atoi(f[2]))] = f[0]
		}
	}
	return out
}

func parseOSRelease(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return out
}

// parseCPUModel: x86 "model name", ARM "Model" / "Hardware" / the CPU part.
func parseCPUModel(text string) string {
	keys := []string{"model name", "Model", "Hardware", "cpu model", "Processor"}
	vals := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if _, seen := vals[k]; !seen {
			vals[k] = strings.TrimSpace(v)
		}
	}
	for _, k := range keys {
		if v := vals[k]; v != "" {
			return v
		}
	}
	return ""
}

// countEstablished: TCP connections in the ESTABLISHED state (st 01).
func countEstablished(text string) int {
	n := 0
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if i > 0 && len(f) > 3 && f[3] == "01" {
			n++
		}
	}
	return n
}

// clockTicks from the kernel's auxiliary vector (AT_CLKTCK); 100 on nearly every system.
func clockTicks(auxv []byte) uint64 {
	for i := 0; i+16 <= len(auxv); i += 16 {
		k := binary.LittleEndian.Uint64(auxv[i:])
		v := binary.LittleEndian.Uint64(auxv[i+8:])
		if k == 17 && v > 0 {
			return v
		}
		if k == 0 {
			break
		}
	}
	return 100
}

// inContainer: running inside Docker, Podman, LXC or Kubernetes.
func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	c := readText(filepath.Join(procRoot, "1/cgroup"))
	for _, w := range []string{"docker", "containerd", "kubepods", "lxc", "libpod"} {
		if strings.Contains(c, w) {
			return true
		}
	}
	return strings.Contains(readText(filepath.Join(procRoot, "1/environ")), "container=")
}

// cmdline: the command with its arguments (NULs to spaces).
func cmdline(b []byte) string {
	b = bytes.TrimRight(b, "\x00")
	return string(bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
}
