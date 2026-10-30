package main

import (
	"encoding/base64"
	"errors"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

// The root terminal: a login shell on a pseudo-terminal. The app writes
// keys (term.write), reads what came out since its last read (term.read
// waits up to a second for something new), and tells it the window size.
// A session nobody reads for 30 minutes is closed.

type termSession struct {
	mu      sync.Mutex
	cond    *sync.Cond
	master  *os.File
	cmd     *exec.Cmd
	out     []byte
	base    int64 // how much was dropped from the front of out
	closed  bool
	touched time.Time
}

var (
	termsMu sync.Mutex
	terms   = map[string]*termSession{}
)

func loginShell() string {
	for _, s := range []string{"/bin/bash", "/usr/bin/bash", "/bin/zsh", "/bin/ash", "/bin/sh"} {
		if _, err := os.Stat(s); err == nil {
			return s
		}
	}
	return "/bin/sh"
}

func termOpen(cols, rows int) (string, error) {
	if !termSupported() {
		return "", errors.New("the terminal needs Linux pseudo-terminals")
	}
	master, slave, err := openPTY()
	if err != nil {
		return "", err
	}
	if cols <= 0 || rows <= 0 {
		cols, rows = 100, 30
	}
	setWinSize(master, cols, rows)
	shell := loginShell()
	cmd := exec.Command(shell, "-l")
	home := "/root"
	cmd.Dir = home
	cmd.Env = []string{"TERM=xterm-256color", "HOME=" + home, "USER=root", "LOGNAME=root", "SHELL=" + shell, "LANG=C.UTF-8",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = ttyAttrs()
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		return "", err
	}
	slave.Close()
	t := &termSession{master: master, cmd: cmd, touched: time.Now()}
	t.cond = sync.NewCond(&t.mu)
	id := randomID()
	termsMu.Lock()
	terms[id] = t
	termsMu.Unlock()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := master.Read(buf)
			t.mu.Lock()
			if n > 0 {
				t.out = append(t.out, buf[:n]...)
				if len(t.out) > 2<<20 { // keep the last 2 MB
					drop := len(t.out) - (1 << 20)
					t.out = t.out[drop:]
					t.base += int64(drop)
				}
			}
			if err != nil {
				t.closed = true
			}
			t.cond.Broadcast()
			t.mu.Unlock()
			if err != nil {
				break
			}
		}
		cmd.Wait()
		master.Close()
	}()
	log.Printf("terminal %s opened (%s)", id[:6], shell)
	return id, nil
}

func termGet(id string) (*termSession, error) {
	termsMu.Lock()
	defer termsMu.Unlock()
	t := terms[id]
	if t == nil {
		return nil, errors.New("that terminal was closed; open a new one")
	}
	return t, nil
}

func termDo(r PanelRequest) (any, error) {
	if r.Op == "term.open" {
		id, err := termOpen(r.Cols, r.Rows)
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id}, nil
	}
	t, err := termGet(r.ID)
	if err != nil {
		return nil, err
	}
	switch r.Op {
	case "term.write":
		data, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil, errors.New("bad data")
		}
		t.mu.Lock()
		t.touched = time.Now()
		t.mu.Unlock()
		_, err = t.master.Write(data)
		return nil, err
	case "term.read":
		t.mu.Lock()
		t.touched = time.Now()
		end := t.base + int64(len(t.out))
		if r.Since >= end && !t.closed { // wait up to a second for something new
			timer := time.AfterFunc(time.Second, func() { t.mu.Lock(); t.cond.Broadcast(); t.mu.Unlock() })
			t.cond.Wait()
			timer.Stop()
			end = t.base + int64(len(t.out))
		}
		since := r.Since
		if since < t.base || since > end {
			since = t.base
		}
		data := t.out[since-t.base:]
		closed := t.closed
		t.mu.Unlock()
		return map[string]any{"data": base64.StdEncoding.EncodeToString(data), "next": end, "closed": closed}, nil
	case "term.resize":
		setWinSize(t.master, r.Cols, r.Rows)
		return nil, nil
	case "term.close":
		termClose(r.ID)
		return nil, nil
	}
	return nil, errors.New("unknown action")
}

func termClose(id string) {
	termsMu.Lock()
	t := terms[id]
	delete(terms, id)
	termsMu.Unlock()
	if t != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.master.Close()
		log.Printf("terminal %s closed", id[:min(6, len(id))])
	}
}

// reapTerminals closes sessions nobody has read for 30 minutes.
func reapTerminals() {
	for range time.Tick(time.Minute) {
		termsMu.Lock()
		var old []string
		for id, t := range terms {
			t.mu.Lock()
			if time.Since(t.touched) > 30*time.Minute || t.closed && time.Since(t.touched) > time.Minute {
				old = append(old, id)
			}
			t.mu.Unlock()
		}
		termsMu.Unlock()
		for _, id := range old {
			termClose(id)
		}
	}
}
