package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Updates: once a day it asks GitHub for the newest release, downloads it,
// checks its SHA-256 and its Ed25519 signature (made with the release key,
// whose public half is below), and swaps the program. The swap runs outside
// the service (a transient systemd unit, or a detached process), restarts
// it, waits for the new version to answer, and puts the old one back if it
// doesn't. Settings, port and paired devices are untouched.

// releaseKey verifies release signatures. Its private half never leaves the
// release Mac; a release without a valid signature is never installed.
const releaseKey = "7D60HnjsidpCYJbfcWvI3WIvYwU+IyKCbjL62AGzFrE="

const releaseRepo = "sudo-user101/Apex-Activity-Manager-Server-Edition"

const binPath = "/usr/local/bin/apex-server"

// updateSource: GitHub, or (tests only) another address serving the same files.
func updateSource() (api, files string) {
	if u := os.Getenv("APEX_UPDATE_SOURCE"); u != "" && os.Getenv("APEX_SERVER_CONFIG") != "" {
		return u + "/latest.json", u
	}
	return "https://api.github.com/repos/" + releaseRepo + "/releases/latest", "https://github.com/" + releaseRepo + "/releases/download"
}

type UpdateState struct {
	Checked    time.Time `json:"checked,omitempty"`
	Latest     string    `json:"latest,omitempty"`
	Problem    string    `json:"problem,omitempty"` // the last check or install that failed, in plain words
	Installed  string    `json:"installed,omitempty"`
	When       time.Time `json:"when,omitempty"`
	From       string    `json:"from,omitempty"`
	RolledBack bool      `json:"rolledBack,omitempty"`
}

func autoUpdates() bool { c := loadConfig(); return c.AutoUpdate == nil || *c.AutoUpdate }

func setAutoUpdates(on bool) error {
	c := loadConfig()
	c.AutoUpdate = &on
	return saveJSON("config.json", c)
}

func loadUpdateState() UpdateState { var s UpdateState; loadJSON("update.json", &s); return s }

// newer: is a (like "1.3.0" or "v1.3.0") a later version than b? Pure: tested.
func newer(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func versionParts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v = strings.SplitN(v, "-", 2)[0]
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

var httpc = &http.Client{Timeout: 2 * time.Minute}

func fetch(url string, limit int64) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "apex-server/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't reach GitHub (%v)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub answered %d for %s", resp.StatusCode, filepath.Base(url))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("the download is larger than a release can be")
	}
	return b, nil
}

// checkLatest asks GitHub for the newest release's version.
func checkLatest() (string, error) {
	api, _ := updateSource()
	b, err := fetch(api, 1<<20)
	if err != nil {
		return "", err
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if json.Unmarshal(b, &r) != nil || versionParts(r.Tag) == [3]int{} {
		return "", errors.New("GitHub's answer had no version in it")
	}
	return strings.TrimPrefix(r.Tag, "v"), nil
}

// verifyRelease: the tarball matches its .sha256 and its .sig. Pure: tested.
func verifyRelease(tarball, sumFile, sig []byte, pub ed25519.PublicKey) error {
	want := strings.Fields(string(sumFile))
	got := sha256.Sum256(tarball)
	if len(want) == 0 || !strings.EqualFold(want[0], hex.EncodeToString(got[:])) {
		return errors.New("the download's checksum doesn't match")
	}
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, tarball, s) {
		return errors.New("the download isn't signed with the Apex release key")
	}
	return nil
}

// trustedKey: the release key (tests use their own).
var trustedKey = publicKey()

func publicKey() ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(releaseKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return b
}

// programFrom takes this machine's program out of a release tarball. Pure: tested.
func programFrom(tarball []byte, ver, arch string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	want := "apex-server-" + ver + "/apex-server-linux-" + arch
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("the release has no program for %s", arch)
		}
		if err != nil {
			return nil, err
		}
		if h.Name == want && h.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 64<<20))
		}
	}
}

var updateMu sync.Mutex

// downloadUpdate gets, checks and stages version ver; it returns the staged program.
func downloadUpdate(ver string) (string, error) {
	_, files := updateSource()
	name := "apex-server-" + ver + "-linux.tar.gz"
	base := files + "/v" + ver + "/" + name
	tarball, err := fetch(base, 64<<20)
	if err != nil {
		return "", err
	}
	sum, err := fetch(base+".sha256", 4096)
	if err != nil {
		return "", err
	}
	sig, err := fetch(base+".sig", 4096)
	if err != nil {
		return "", errors.New("this release has no signature, so it isn't installed automatically; update by hand")
	}
	if err := verifyRelease(tarball, sum, sig, trustedKey); err != nil {
		return "", err
	}
	prog, err := programFrom(tarball, ver, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	dir := path("update")
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	staged := filepath.Join(dir, "apex-server-"+ver)
	if err := os.WriteFile(staged, prog, 0o700); err != nil {
		return "", err
	}
	return staged, nil
}

// busyNow: an update restarts the service, so it waits while someone is
// using a terminal or a package job is running.
func busyNow() bool {
	termsMu.Lock()
	n := len(terms)
	termsMu.Unlock()
	if n > 0 {
		return true
	}
	jobsMu.Lock()
	defer jobsMu.Unlock()
	for _, j := range jobs {
		j.mu.Lock()
		running := !j.done
		j.mu.Unlock()
		if running {
			return true
		}
	}
	return false
}

// checkNow asks GitHub and records the answer.
func checkNow() (string, error) {
	st := loadUpdateState()
	latest, err := checkLatest()
	st.Checked = time.Now()
	if err != nil {
		st.Problem = capitalize(err.Error()) + "."
	} else {
		st.Latest, st.Problem = latest, ""
	}
	saveJSON("update.json", st)
	return latest, err
}

// Update checks and, if there's a newer release, stages it and starts the
// swap (force: even while a terminal or job is open). Returns what happened in plain words.
func Update(force bool) (string, error) {
	if !updateMu.TryLock() {
		return "", errors.New("an update is already being checked")
	}
	defer updateMu.Unlock()
	latest, err := checkNow()
	if err != nil {
		return "", err
	}
	st := loadUpdateState()
	if !newer(latest, version) {
		return "Up to date (" + version + ").", nil
	}
	if !force && busyNow() {
		return "Version " + latest + " is ready; it installs when the terminal and update jobs are closed.", nil
	}
	staged, err := downloadUpdate(latest)
	if err != nil {
		st.Problem = capitalize(err.Error()) + "."
		saveJSON("update.json", st)
		return "", err
	}
	log.Printf("update: %s → %s, verified; installing", version, latest)
	if err := startSwap(staged); err != nil {
		return "", err
	}
	return "Installing " + latest + ". Apex Server Edition restarts in a few seconds.", nil
}

// startSwap runs the staged program's "apply-update" outside this service, so
// it can replace the program and outlive the restart.
func startSwap(staged string) error {
	if _, err := os.Stat("/run/systemd/system"); err == nil && have("systemd-run") {
		_, err := run(30*time.Second, "systemd-run", "--unit=apex-server-update-"+strconv.FormatInt(time.Now().Unix(), 10),
			"--collect", "--quiet", staged, "apply-update", version)
		return err
	}
	cmd := exec.Command(staged, "apply-update", version)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// applyUpdate runs as the new program, outside the service: swap, restart,
// confirm, or put the old program back.
func applyUpdate(from string) {
	time.Sleep(time.Second)
	self, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	st := loadUpdateState()
	prev := binPath + ".previous"
	logf := func(f string, a ...any) { log.Printf("update: "+f, a...); appendLog(fmt.Sprintf(f, a...)) }
	if err := copyFile(binPath, prev); err != nil {
		logf("couldn't keep the old program (%v); nothing changed", err)
		return
	}
	if err := installProgram(self, binPath); err != nil {
		logf("couldn't install %s (%v); nothing changed", version, err)
		return
	}
	restartService()
	if answering(version, 30*time.Second) {
		st.Installed, st.When, st.From, st.RolledBack, st.Problem = version, time.Now(), from, false, ""
		saveJSON("update.json", st)
		logf("updated %s → %s", from, version)
		os.RemoveAll(filepath.Dir(self))
		return
	}
	installProgram(prev, binPath)
	restartService()
	st.RolledBack, st.When = true, time.Now()
	st.Problem = "Version " + version + " didn't start, so " + from + " was put back."
	saveJSON("update.json", st)
	logf("%s didn't answer; put %s back", version, from)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

// installProgram: written beside, then renamed (a running program is never half-written).
func installProgram(src, dst string) error {
	if err := copyFile(src, dst+".new"); err != nil {
		return err
	}
	return os.Rename(dst+".new", dst)
}

func restartService() {
	switch {
	case fileExists("/etc/systemd/system/apex-server.service"):
		run(60*time.Second, "systemctl", "restart", "apex-server")
	case have("rc-service") && fileExists("/etc/init.d/apex-server"):
		run(60*time.Second, "rc-service", "apex-server", "restart")
	case fileExists("/etc/init.d/apex-server"):
		// Init scripts from before 1.3 find the program by its path, which reads
		// "… (deleted)" once it's been replaced, so they'd leave it running.
		stopReplaced()
		run(60*time.Second, "/etc/init.d/apex-server", "restart")
	}
}

// stopReplaced ends the old program still running from a replaced file.
func stopReplaced() {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		if exe, _ := os.Readlink("/proc/" + e.Name() + "/exe"); exe == binPath+" (deleted)" {
			syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	time.Sleep(time.Second)
}

// answering: the service on this machine says it's version want.
func answering(want string, within time.Duration) bool {
	port := loadConfig().Port
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // its own address, only asking its version
	for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(time.Second) {
		resp, err := c.Get(fmt.Sprintf("https://127.0.0.1:%d/api/hello", port))
		if err != nil {
			continue
		}
		var h struct {
			Version string `json:"version"`
		}
		json.NewDecoder(resp.Body).Decode(&h)
		resp.Body.Close()
		if h.Version == want {
			return true
		}
	}
	return false
}

// appendLog: the swap runs outside the service, so it also writes the service's log file where there is one.
func appendLog(line string) {
	if f, err := os.OpenFile("/var/log/apex-server.log", os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%s update: %s\n", time.Now().Format("2006/01/02 15:04:05"), line)
		f.Close()
	}
}

// updateLoop: 10 minutes after starting, then every 24 hours.
func updateLoop() {
	time.Sleep(10 * time.Minute)
	for {
		if autoUpdates() {
			if msg, err := Update(false); err != nil {
				log.Printf("update check: %v", err)
			} else if !strings.HasPrefix(msg, "Up to date") {
				log.Printf("update: %s", msg)
			}
		}
		time.Sleep(24 * time.Hour)
	}
}

// MARK: HTTP

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Op string `json:"op"` // check, install
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
		var msg string
		var err error
		switch req.Op {
		case "check":
			var latest string
			if latest, err = checkNow(); err == nil {
				msg = map[bool]string{true: "Version " + latest + " is available.", false: "Up to date."}[newer(latest, version)]
			}
		case "install":
			msg, err = Update(true)
		default:
			err = errors.New("unknown action")
		}
		log.Printf("update %s from %s: %s", req.Op, clientIP(r), errText(err))
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": capitalize(err.Error()) + "."})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg, "status": updateStatus()})
		return
	}
	writeJSON(w, http.StatusOK, updateStatus())
}

func updateStatus() map[string]any {
	st := loadUpdateState()
	out := map[string]any{"current": version, "auto": autoUpdates(), "latest": st.Latest,
		"available": st.Latest != "" && newer(st.Latest, version), "problem": st.Problem, "rolledBack": st.RolledBack}
	if !st.Checked.IsZero() {
		out["checked"] = st.Checked.UnixMilli()
	}
	if st.Installed != "" {
		out["installed"] = map[string]any{"version": st.Installed, "from": st.From, "when": st.When.UnixMilli()}
	}
	return out
}

// MARK: CLI

func updatesCLI(args []string) {
	if len(args) > 0 && (args[0] == "on" || args[0] == "off") {
		if err := setAutoUpdates(args[0] == "on"); err != nil {
			log.Fatal(err)
		}
		if args[0] == "on" {
			fmt.Println("Automatic updates are on: it checks once a day and installs signed releases.")
		} else {
			fmt.Println("Automatic updates are off. Update by hand with: sudo apex-server update")
		}
		return
	}
	st := loadUpdateState()
	fmt.Printf("Version %s. Automatic updates: %s\n", version, map[bool]string{true: "on", false: "off"}[autoUpdates()])
	if !st.Checked.IsZero() {
		fmt.Printf("Last checked %s: newest is %s\n", st.Checked.Format(time.DateTime), st.Latest)
	}
	if st.Installed != "" {
		fmt.Printf("Last update: %s → %s on %s\n", st.From, st.Installed, st.When.Format(time.DateTime))
	}
	if st.Problem != "" {
		fmt.Println(st.Problem)
	}
}

func updateNowCLI() {
	fmt.Println("Checking for a newer version…")
	msg, err := Update(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, capitalize(err.Error())+". Nothing was changed.")
		os.Exit(1)
	}
	fmt.Println(msg)
	if strings.HasPrefix(msg, "Installing") {
		latest := loadUpdateState().Latest
		if answering(latest, 60*time.Second) {
			fmt.Println("Updated to " + latest + ".")
		} else {
			fmt.Println("It didn't answer as " + latest + " within a minute; see sudo apex-server updates.")
		}
	}
}
