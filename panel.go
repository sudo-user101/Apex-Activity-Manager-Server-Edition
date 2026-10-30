package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Panel: root work on the server from the app, like a hosting control
// panel: files, a terminal, package updates, the firewall, users and SSH
// keys. Anything that reads private files or changes the server needs
// panel mode, switched on at the server itself (`sudo apex-server allow
// panel`), never from the app: a paired device alone can't get a root
// shell. Viewing updates and the firewall works without it. Every change
// is logged with where it came from.

type PanelRequest struct {
	Op      string   `json:"op"`
	Path    string   `json:"path"`
	To      string   `json:"to"`
	Data    string   `json:"data"` // base64
	Offset  int64    `json:"offset"`
	Length  int64    `json:"length"`
	Mode    string   `json:"mode"` // octal, "0644"
	Owner   string   `json:"owner"`
	Group   string   `json:"group"`
	All     bool     `json:"all"`
	Names   []string `json:"names"`
	ID      string   `json:"id"`
	Since   int64    `json:"since"`
	Cols    int      `json:"cols"`
	Rows    int      `json:"rows"`
	Port    string   `json:"port"`
	Proto   string   `json:"proto"`
	From    string   `json:"from"`
	Rule    string   `json:"rule"`
	Jail    string   `json:"jail"`
	IP      string   `json:"ip"`
	User    string   `json:"user"`
	Key     string   `json:"key"`
	Setting string   `json:"setting"`
	Value   string   `json:"value"`
}

func panelOn() bool { return loadConfig().Panel }

var errPanelOff = errors.New("full root features are off on this server. Switch them on at the server with: sudo apex-server allow panel")

// MARK: Jobs (long commands: updates, installs)

type job struct {
	mu     sync.Mutex
	out    []byte
	done   bool
	failed bool
	title  string
	start  time.Time
}

var (
	jobsMu sync.Mutex
	jobs   = map[string]*job{}
)

func (j *job) Write(p []byte) (int, error) {
	j.mu.Lock()
	j.out = append(j.out, p...)
	if len(j.out) > 4<<20 {
		j.out = j.out[len(j.out)-(4<<20):]
	}
	j.mu.Unlock()
	return len(p), nil
}

// startJob runs a command in the background; its output is read with op "job".
func startJob(title string, env []string, name string, args ...string) string {
	id := randomID()
	j := &job{title: title, start: time.Now()}
	jobsMu.Lock()
	jobs[id] = j
	jobsMu.Unlock()
	go func() {
		cmd := exec.Command(name, args...)
		cmd.Env = append(append(os.Environ(), "LC_ALL=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"), env...)
		cmd.Stdout, cmd.Stderr = j, j
		err := cmd.Run()
		j.mu.Lock()
		j.done, j.failed = true, err != nil
		if err != nil {
			j.out = append(j.out, []byte("\n"+err.Error()+"\n")...)
		}
		j.mu.Unlock()
		log.Printf("job %s (%s): %s", id, title, errText(err))
	}()
	return id
}

func jobState(id string, since int64) (map[string]any, error) {
	jobsMu.Lock()
	j := jobs[id]
	jobsMu.Unlock()
	if j == nil {
		return nil, errors.New("that job isn't there any more")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if since < 0 || since > int64(len(j.out)) {
		since = 0
	}
	return map[string]any{"title": j.title, "text": string(j.out[since:]), "next": len(j.out), "done": j.done, "failed": j.failed}, nil
}

func randomID() string {
	b := make([]byte, 12)
	f, _ := os.Open("/dev/urandom")
	if f != nil {
		io.ReadFull(f, b)
		f.Close()
	}
	return fmt.Sprintf("%x", b)
}

// MARK: Files

type FileEntry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Dir    bool   `json:"dir"`
	Link   string `json:"link,omitempty"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"` // "0644"
	Perm   string `json:"perm"` // "-rw-r--r--"
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	MTime  int64  `json:"mtime"`
	Hidden bool   `json:"hidden"`
}

func cleanPath(p string) (string, error) {
	if p == "" {
		p = "/"
	}
	if !filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
		return "", errors.New("give a full path, like /etc/nginx")
	}
	return filepath.Clean(p), nil
}

var nameCache sync.Map

func lookupName(id uint32, group bool) string {
	key := fmt.Sprintf("%v:%d", group, id)
	if v, ok := nameCache.Load(key); ok {
		return v.(string)
	}
	name := strconv.Itoa(int(id))
	if group {
		if g, err := user.LookupGroupId(name); err == nil {
			name = g.Name
		}
	} else if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	nameCache.Store(key, name)
	return name
}

func entryFor(path string, fi os.FileInfo) FileEntry {
	e := FileEntry{Name: fi.Name(), Path: path, Dir: fi.IsDir(), Size: fi.Size(), Mode: fmt.Sprintf("%04o", unixMode(fi.Mode())),
		Perm: fi.Mode().String(), MTime: fi.ModTime().Unix(), Hidden: strings.HasPrefix(fi.Name(), ".")}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.Owner, e.Group = lookupName(st.Uid, false), lookupName(st.Gid, true)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		e.Link, _ = os.Readlink(path)
		if t, err := os.Stat(path); err == nil && t.IsDir() {
			e.Dir = true
		}
	}
	return e
}

// unixMode: permission bits plus setuid, setgid and sticky, as chmod writes them.
func unixMode(m os.FileMode) uint32 {
	v := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		v |= 0o1000
	}
	return v
}

func listDir(p string) (map[string]any, error) {
	des, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(des))
	for _, d := range des {
		full := filepath.Join(p, d.Name())
		fi, err := os.Lstat(full)
		if err != nil {
			continue
		}
		out = append(out, entryFor(full, fi))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return map[string]any{"path": p, "entries": out}, nil
}

const chunk = 4 << 20

func readFilePart(p string, offset, length int64) (map[string]any, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, errors.New("that's a folder")
	}
	if length <= 0 || length > chunk {
		length = chunk
	}
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return map[string]any{"data": base64.StdEncoding.EncodeToString(buf[:n]), "size": fi.Size(), "offset": offset, "eof": offset+int64(n) >= fi.Size()}, nil
}

// writeFilePart: offset 0 replaces the file (written beside it, then renamed,
// keeping its mode and owner); a later offset appends the next part of an upload.
func writeFilePart(p string, data []byte, offset int64) error {
	if offset > 0 {
		f, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteAt(data, offset)
		return err
	}
	mode, uid, gid := os.FileMode(0o644), -1, -1
	if fi, err := os.Stat(p); err == nil {
		if fi.IsDir() {
			return errors.New("that's a folder")
		}
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	}
	tmp := p + ".apex-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if uid >= 0 {
		os.Chown(tmp, uid, gid)
	}
	return os.Rename(tmp, p)
}

func filesDo(r PanelRequest) (any, error) {
	p, err := cleanPath(r.Path)
	if err != nil {
		return nil, err
	}
	switch r.Op {
	case "files.ls":
		return listDir(p)
	case "files.stat":
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		return entryFor(p, fi), nil
	case "files.read":
		return readFilePart(p, r.Offset, r.Length)
	case "files.write":
		data, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil, errors.New("bad data")
		}
		return nil, writeFilePart(p, data, r.Offset)
	case "files.mkdir":
		return nil, os.MkdirAll(p, 0o755)
	case "files.rename":
		to, err := cleanPath(r.To)
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(to); err == nil {
			return nil, fmt.Errorf("%s already exists", to)
		}
		return nil, os.Rename(p, to)
	case "files.delete":
		if p == "/" || len(strings.Split(strings.Trim(p, "/"), "/")) < 2 && isSystemDir(p) {
			return nil, fmt.Errorf("Apex won't delete %s", p)
		}
		if r.All {
			return nil, os.RemoveAll(p)
		}
		return nil, os.Remove(p)
	case "files.chmod":
		m, err := strconv.ParseUint(r.Mode, 8, 32)
		if err != nil || m > 0o7777 {
			return nil, errors.New("give the permissions as numbers, like 644 or 0755")
		}
		return nil, chmodUnix(p, uint32(m))
	case "files.chown":
		uid, gid := -1, -1
		if r.Owner != "" {
			u, err := user.Lookup(r.Owner)
			if err != nil {
				return nil, fmt.Errorf("there's no user called %s", r.Owner)
			}
			uid, _ = strconv.Atoi(u.Uid)
		}
		if r.Group != "" {
			g, err := user.LookupGroup(r.Group)
			if err != nil {
				return nil, fmt.Errorf("there's no group called %s", r.Group)
			}
			gid, _ = strconv.Atoi(g.Gid)
		}
		if r.All {
			return nil, filepath.Walk(p, func(q string, _ os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				return os.Lchown(q, uid, gid)
			})
		}
		return nil, os.Lchown(p, uid, gid)
	}
	return nil, errors.New("unknown action")
}

func chmodUnix(p string, m uint32) error {
	mode := os.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return os.Chmod(p, mode)
}

func isSystemDir(p string) bool {
	switch p {
	case "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var":
		return true
	}
	return false
}

// MARK: The API

// panelReadOnly: ops that work without panel mode (nothing private, nothing changed).
var panelReadOnly = map[string]bool{"status": true, "job": true, "pkg.list": true, "fw.status": true, "f2b.status": true, "ssh.status": true, "users.list": true}

func PanelDo(r PanelRequest) (any, error) {
	if !panelReadOnly[r.Op] && !panelOn() {
		return nil, errPanelOff
	}
	switch {
	case r.Op == "status":
		return panelStatus(), nil
	case r.Op == "job":
		return jobState(r.ID, r.Since)
	case strings.HasPrefix(r.Op, "files."):
		return filesDo(r)
	case strings.HasPrefix(r.Op, "term."):
		return termDo(r)
	case strings.HasPrefix(r.Op, "pkg."):
		return packagesDo(r)
	case strings.HasPrefix(r.Op, "fw."), strings.HasPrefix(r.Op, "f2b."), strings.HasPrefix(r.Op, "ssh."):
		return securityDo(r)
	case strings.HasPrefix(r.Op, "users."), strings.HasPrefix(r.Op, "keys."):
		return usersDo(r)
	}
	return nil, errors.New("unknown action")
}

func panelStatus() map[string]any {
	pm, _ := packageManager()
	return map[string]any{"panel": panelOn(), "packages": pm, "firewall": firewallTool(), "fail2ban": have("fail2ban-client"),
		"terminal": termSupported(), "shell": loginShell()}
}

func (s *Server) panel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req PanelRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Bad request."})
		return
	}
	res, err := PanelDo(req)
	if !quietOps[req.Op] {
		target := req.Path
		if target == "" {
			target = strings.TrimSpace(strings.Join(append([]string{req.Port, req.Proto, req.From, req.Rule, req.Jail, req.IP, req.User, req.Setting}, req.Names...), " "))
		}
		log.Printf("panel %s %s from %s: %s", req.Op, target, clientIP(r), errText(err))
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": capitalize(strings.TrimSuffix(err.Error(), ".")) + "."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res})
}

// quietOps: reads that would flood the log (a terminal reads every second).
var quietOps = map[string]bool{"status": true, "job": true, "term.read": true, "term.write": true, "term.resize": true, "files.ls": true, "files.stat": true,
	"pkg.list": true, "fw.status": true, "f2b.status": true, "ssh.status": true, "users.list": true, "keys.list": true}

// MARK: Switching panel mode on (at the server only)

const panelDropIn = `# Written by "apex-server allow panel": full root features (files, terminal,
# updates, firewall) need the whole system. "apex-server deny panel" removes it.
[Service]
ProtectSystem=no
ProtectHome=no
PrivateTmp=no
NoNewPrivileges=no
ReadWritePaths=
`

const dropInPath = "/etc/systemd/system/apex-server.service.d/panel.conf"

func setPanel(on bool) error {
	cfg := loadConfig()
	cfg.Panel = on
	if err := saveJSON("config.json", cfg); err != nil {
		return err
	}
	if _, err := os.Stat("/etc/systemd/system/apex-server.service"); err == nil {
		if on {
			os.MkdirAll(filepath.Dir(dropInPath), 0o755)
			if err := os.WriteFile(dropInPath, []byte(panelDropIn), 0o644); err != nil {
				return err
			}
		} else {
			os.Remove(dropInPath)
		}
		run(30*time.Second, "systemctl", "daemon-reload")
		run(30*time.Second, "systemctl", "restart", "apex-server")
		return nil
	}
	for _, c := range [][]string{{"rc-service", "apex-server", "restart"}, {"service", "apex-server", "restart"}} {
		if have(c[0]) {
			run(30*time.Second, c[0], c[1:]...)
			break
		}
	}
	return nil
}
