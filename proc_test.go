package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatAndBusy(t *testing.T) {
	a := parseStat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0 0 0\nintr 1")
	b := parseStat("cpu  150 0 150 900 0 0 0 0 0 0\ncpu0 100 0 100 400 0 0 0 0 0 0\ncpu1 50 0 50 500 0 0 0 0 0 0\n")
	if len(a) != 3 || busy(a[0], b[0]) != 50 || busy(a[1], b[1]) != 100 || busy(a[2], b[2]) != 0 {
		t.Fatalf("got %v %v", a, b)
	}
}

func TestMeminfo(t *testing.T) {
	m := parseMeminfo("MemTotal:        8000 kB\nMemAvailable:    2000 kB\nHugePages_Total:       0\n")
	if m["MemTotal"] != 8000*1024 || m["MemAvailable"] != 2000*1024 || m["HugePages_Total"] != 0 {
		t.Fatal(m)
	}
}

func TestNetDevAndSkip(t *testing.T) {
	n := parseNetDev("Inter-|   Receive\n face |bytes\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n")
	if n["eth0"] != [2]int64{1000, 2000} || !skipInterface("lo") || !skipInterface("veth12ab") || skipInterface("eth0") || skipInterface("ens5") {
		t.Fatal(n)
	}
}

func TestPidStatWithSpacesAndParens(t *testing.T) {
	st, ok := parsePidStat("1234 (my (odd) prog) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 3 0 5000 12345678 900 18446744073709551615")
	if !ok || st.comm != "my (odd) prog" || st.state != "S" || st.ppid != 1 || st.utime != 250 || st.stime != 50 || st.threads != 3 || st.starttime != 5000 || st.rssPages != 900 {
		t.Fatalf("%+v", st)
	}
	if _, ok := parsePidStat("garbage"); ok {
		t.Fatal("garbage parsed")
	}
}

func TestMountsKeepRealDisks(t *testing.T) {
	text := `22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
23 22 0:5 / /proc rw - proc proc rw
24 22 0:20 / /run rw - tmpfs tmpfs rw
25 22 8:1 /var/lib/docker /var/lib/docker rw - ext4 /dev/sda1 rw
26 22 8:17 / /mnt/my\040data rw - xfs /dev/sdb1 rw
27 22 7:0 / /snap/core/1 ro - squashfs /dev/loop0 ro
28 22 0:40 /@home /home rw - btrfs /dev/sdc rw
29 22 0:40 /@ /srv rw - btrfs /dev/sdc rw
30 1 0:50 / / rw - overlay overlay rw`
	got := realMounts(parseMountinfo(text))
	want := []string{"/", "/", "/home", "/mnt/my data", "/srv"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i, m := range got {
		if m.target != want[i] {
			t.Fatalf("%d: %v", i, got)
		}
	}
}

func TestServicesAllManagers(t *testing.T) {
	sd := parseSystemd("ssh.service loaded active running OpenBSD Secure Shell server\n● nginx.service loaded failed failed A high performance web server\ncron.timer loaded active waiting x\n")
	if len(sd) != 2 || sd[0].Name != "ssh" || sd[0].Description != "OpenBSD Secure Shell server" || sd[1].Active != "failed" {
		t.Fatalf("%+v", sd)
	}
	or := parseOpenRC("Runlevel: default\n sshd                                                              [  started  ]\n crond   [  stopped  ]\nDynamic Runlevel: hotplugged\n nginx [  crashed  ]\n")
	if len(or) != 3 || or[0].Sub != "running" || or[1].Sub != "dead" || or[2].Active != "failed" {
		t.Fatalf("%+v", or)
	}
	sv := parseSysV(" [ + ]  cron\n [ - ]  nginx\n [ ? ]  hwclock.sh\n")
	if len(sv) != 3 || sv[0].Sub != "running" || sv[1].Sub != "dead" || sv[2].Sub != "unknown" {
		t.Fatalf("%+v", sv)
	}
}

func TestUtmp(t *testing.T) {
	rec := make([]byte, 384*2)
	binary.LittleEndian.PutUint32(rec[0:], 7)
	copy(rec[8:], "pts/0")
	copy(rec[44:], "ubuntu")
	copy(rec[76:], "203.0.113.5")
	binary.LittleEndian.PutUint32(rec[384:], 2) // boot time, skipped
	s := parseUtmp(rec)
	if len(s) != 1 || s[0] != (Session{User: "ubuntu", Terminal: "pts/0", From: "203.0.113.5"}) {
		t.Fatalf("%+v", s)
	}
}

func TestDockerStatsText(t *testing.T) {
	var st dockerStats
	st.CPU.Usage.Total, st.PreCPU.Usage.Total = 2_000_000, 1_000_000
	st.CPU.System, st.PreCPU.System, st.CPU.Online = 200_000_000, 100_000_000, 4
	st.Memory.Usage, st.Memory.Limit = 500<<20, 4<<30
	st.Memory.Stats = map[string]uint64{"inactive_file": 50 << 20}
	cpu, mem, _, _ := formatStats(st)
	if cpu != "4.00%" || mem != "450MiB / 4GiB" {
		t.Fatal(cpu, mem)
	}
}

func TestEstablishedAndClock(t *testing.T) {
	if countEstablished("  sl  local rem st\n   0: 0100007F:1F90 00000000:0000 0A\n   1: 0100007F:1F90 0100007F:9C40 01\n") != 1 {
		t.Fatal("established")
	}
	aux := make([]byte, 48)
	binary.LittleEndian.PutUint64(aux[0:], 6)
	binary.LittleEndian.PutUint64(aux[8:], 4096)
	binary.LittleEndian.PutUint64(aux[16:], 17)
	binary.LittleEndian.PutUint64(aux[24:], 250)
	if clockTicks(aux) != 250 || clockTicks(nil) != 100 {
		t.Fatal("clock")
	}
}

func TestPairing(t *testing.T) {
	configDir = t.TempDir()
	a := NewAuth()
	p, err := a.NewPairing()
	if err != nil || len(p.Code) != 9 {
		t.Fatal(p, err)
	}
	if normalizeCode(" "+p.Code[:4]+" "+p.Code[5:]+" ") != p.Code {
		t.Fatal("normalize")
	}
	tok, err := a.Pair(p.Code, "MacBook", "1.2.3.4")
	if err != nil || tok == "" || !a.Check(tok) || a.Check("nope") || a.Check("") {
		t.Fatal("pair", err)
	}
	b, _ := os.ReadFile(filepath.Join(configDir, "devices.json"))
	if len(b) == 0 || string(b) == "" || contains(string(b), tok) {
		t.Fatal("the token itself must never be stored")
	}
	for i := 0; i < 10; i++ {
		a.Pair("WRONG-CODE", "x", "5.6.7.8")
	}
	if _, err := a.Pair(p.Code, "x", "5.6.7.8"); err != errTooMany {
		t.Fatal("after 10 wrong codes, even the right one waits", err)
	}
	if _, err := a.Pair(p.Code, "y", "9.9.9.9"); err != nil {
		t.Fatal("another address isn't blocked", err)
	}
	a.pairing.Expires = time.Now().Add(-time.Minute)
	saveJSON("pairing.json", a.pairing)
	if _, err := a.Pair(p.Code, "z", "1.1.1.1"); err != errBadCode {
		t.Fatal("expired code accepted")
	}
	a.Forget(tok)
	if a.Check(tok) {
		t.Fatal("forgotten device still allowed")
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestCertificate(t *testing.T) {
	configDir = t.TempDir()
	_, fp1, err := ensureCertificate()
	if err != nil || len(fp1) != 95 {
		t.Fatal(fp1, err)
	}
	_, fp2, _ := ensureCertificate()
	if fp1 != fp2 {
		t.Fatal("the certificate must stay the same between starts")
	}
	if st, _ := os.Stat(filepath.Join(configDir, "key.pem")); st.Mode().Perm() != 0o600 {
		t.Fatal("key readable by others")
	}
}
