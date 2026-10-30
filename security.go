package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Firewall (ufw or firewalld), fail2ban, SSH settings, users and their SSH
// keys. Changes never shut out SSH or Apex itself: their ports are kept
// open, and an SSH setting is checked with `sshd -t` and put back if refused.

// MARK: Firewall

func firewallTool() string {
	switch {
	case have("ufw"):
		return "ufw"
	case have("firewall-cmd"):
		return "firewalld"
	}
	return ""
}

type FwRule struct {
	ID     string `json:"id"` // ufw: number; firewalld: "port:80/tcp" / "service:http"
	To     string `json:"to"`
	Action string `json:"action"`
	From   string `json:"from"`
	V6     bool   `json:"v6"`
}

var ufwRuleRE = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?: IN| OUT| FWD)?\s+(.+)$`)

// parseUfw: `ufw status numbered`. Pure: tested.
func parseUfw(out string) (bool, []FwRule) {
	active := strings.Contains(out, "Status: active")
	var rules []FwRule
	for _, l := range strings.Split(out, "\n") {
		if m := ufwRuleRE.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			to := strings.TrimSpace(m[2])
			rules = append(rules, FwRule{ID: m[1], To: strings.TrimSuffix(to, " (v6)"), Action: m[3], From: strings.TrimSuffix(strings.TrimSpace(m[4]), " (v6)"), V6: strings.Contains(l, "(v6)")})
		}
	}
	return active, rules
}

// parseFirewalld: `firewall-cmd --list-all`. Pure: tested.
func parseFirewalld(out string) []FwRule {
	var rules []FwRule
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		for _, x := range strings.Fields(v) {
			switch k {
			case "services":
				rules = append(rules, FwRule{ID: "service:" + x, To: x, Action: "ALLOW", From: "Anywhere"})
			case "ports":
				rules = append(rules, FwRule{ID: "port:" + x, To: x, Action: "ALLOW", From: "Anywhere"})
			}
		}
	}
	return rules
}

func sshPort() string {
	if out, err := run(10*time.Second, "sshd", "-T"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "port" {
				return f[1]
			}
		}
	}
	return "22"
}

// protectedPorts: never closed from the app (SSH, and Apex's own port).
func protectedPorts() []string { return []string{sshPort(), strconv.Itoa(loadConfig().Port)} }

var portRE = regexp.MustCompile(`^\d{1,5}(:\d{1,5})?$`)

func fwStatus() (map[string]any, error) {
	tool := firewallTool()
	res := map[string]any{"tool": tool, "active": false, "rules": []FwRule{}, "protected": protectedPorts()}
	switch tool {
	case "ufw":
		out, err := combined(15*time.Second, "ufw", "status", "numbered")
		if err != nil {
			return nil, errors.New(lastLine(out))
		}
		active, rules := parseUfw(out)
		res["active"] = active
		if rules != nil {
			res["rules"] = rules
		}
	case "firewalld":
		state, _ := run(10*time.Second, "firewall-cmd", "--state")
		res["active"] = strings.TrimSpace(state) == "running"
		if out, err := run(15*time.Second, "firewall-cmd", "--list-all"); err == nil {
			if r := parseFirewalld(out); r != nil {
				res["rules"] = r
			}
		}
	}
	return res, nil
}

func fwDo(r PanelRequest) (any, error) {
	tool := firewallTool()
	if tool == "" {
		return nil, errors.New("no firewall tool (ufw or firewalld) is installed. Install ufw: it's the simplest")
	}
	proto := strings.ToLower(r.Proto)
	if proto != "" && proto != "tcp" && proto != "udp" {
		return nil, errors.New("the protocol is tcp or udp")
	}
	from := strings.TrimSpace(r.From)
	if from != "" {
		if _, _, err := net.ParseCIDR(from); err != nil && net.ParseIP(from) == nil {
			return nil, errors.New("from is an address or a range, like 203.0.113.7 or 10.0.0.0/8")
		}
	}
	ufw := func(args ...string) error {
		out, err := combined(30*time.Second, "ufw", args...)
		if err != nil {
			return errors.New(lastLine(out))
		}
		return nil
	}
	fwc := func(args ...string) error {
		out, err := combined(30*time.Second, "firewall-cmd", args...)
		if err != nil {
			return errors.New(lastLine(out))
		}
		_, err = combined(30*time.Second, "firewall-cmd", "--reload")
		return err
	}
	keepOpen := func() {
		for _, p := range protectedPorts() {
			if tool == "ufw" {
				ufw("allow", p+"/tcp")
			} else {
				fwc("--permanent", "--add-port="+p+"/tcp")
			}
		}
	}
	switch r.Op {
	case "fw.allow", "fw.deny":
		if !portRE.MatchString(r.Port) {
			return nil, errors.New("give a port, like 443, or a range, like 8000:8100")
		}
		allow := r.Op == "fw.allow"
		if !allow {
			for _, p := range protectedPorts() {
				if r.Port == p {
					return nil, fmt.Errorf("port %s is how you reach this server (SSH or Apex): Apex won't block it", p)
				}
			}
		}
		if tool == "ufw" {
			verb := map[bool]string{true: "allow", false: "deny"}[allow]
			if from != "" {
				args := []string{verb, "from", from, "to", "any", "port", r.Port}
				if proto != "" {
					args = append(args, "proto", proto)
				}
				return nil, ufw(args...)
			}
			spec := r.Port
			if proto != "" {
				spec += "/" + proto
			}
			return nil, ufw(verb, spec)
		}
		if proto == "" {
			proto = "tcp"
		}
		port := strings.ReplaceAll(r.Port, ":", "-")
		if !allow {
			return nil, fwc("--permanent", "--remove-port="+port+"/"+proto)
		}
		if from != "" {
			return nil, fwc("--permanent", fmt.Sprintf(`--add-rich-rule=rule family="ipv4" source address="%s" port port="%s" protocol="%s" accept`, from, port, proto))
		}
		return nil, fwc("--permanent", "--add-port="+port+"/"+proto)
	case "fw.delete":
		st, err := fwStatus()
		if err != nil {
			return nil, err
		}
		for _, rule := range st["rules"].([]FwRule) {
			if rule.ID != r.Rule {
				continue
			}
			for _, p := range protectedPorts() {
				if strings.HasPrefix(rule.To, p+"/") || rule.To == p || rule.To == "OpenSSH" || rule.To == "ssh" {
					if rule.Action == "ALLOW" {
						return nil, fmt.Errorf("that rule lets you reach this server (SSH or Apex): Apex won't delete it")
					}
				}
			}
			if tool == "ufw" {
				return nil, ufw("--force", "delete", rule.ID)
			}
			kind, val, _ := strings.Cut(rule.ID, ":")
			return nil, fwc("--permanent", "--remove-"+kind+"="+val)
		}
		return nil, errors.New("that rule isn't there any more")
	case "fw.enable":
		keepOpen()
		if tool == "ufw" {
			return nil, ufw("--force", "enable")
		}
		_, err := combined(30*time.Second, "systemctl", "enable", "--now", "firewalld")
		keepOpen()
		return nil, err
	case "fw.disable":
		if tool == "ufw" {
			return nil, ufw("disable")
		}
		_, err := combined(30*time.Second, "systemctl", "disable", "--now", "firewalld")
		return nil, err
	}
	return nil, errors.New("unknown action")
}

// MARK: fail2ban

func f2bStatus() (map[string]any, error) {
	if !have("fail2ban-client") {
		return map[string]any{"installed": false, "jails": []any{}}, nil
	}
	out, err := combined(15*time.Second, "fail2ban-client", "status")
	if err != nil {
		return map[string]any{"installed": true, "running": false, "jails": []any{}, "problem": lastLine(out)}, nil
	}
	var jails []map[string]any
	for _, l := range strings.Split(out, "\n") {
		if _, list, ok := strings.Cut(l, "Jail list:"); ok {
			for _, j := range strings.Split(list, ",") {
				j = strings.TrimSpace(j)
				if j == "" {
					continue
				}
				s, _ := combined(15*time.Second, "fail2ban-client", "status", j)
				banned, total := []string{}, 0
				for _, sl := range strings.Split(s, "\n") {
					if _, v, ok := strings.Cut(sl, "Banned IP list:"); ok {
						banned = append(banned, strings.Fields(v)...)
					}
					if _, v, ok := strings.Cut(sl, "Total banned:"); ok {
						total, _ = strconv.Atoi(strings.TrimSpace(v))
					}
				}
				jails = append(jails, map[string]any{"name": j, "banned": banned, "total": total})
			}
		}
	}
	if jails == nil {
		jails = []map[string]any{}
	}
	return map[string]any{"installed": true, "running": true, "jails": jails}, nil
}

// MARK: SSH settings

var sshSettings = map[string][]string{"PasswordAuthentication": {"yes", "no"}, "PermitRootLogin": {"yes", "no", "prohibit-password"}}

func sshStatus() map[string]any {
	res := map[string]any{"port": sshPort()}
	if out, err := run(10*time.Second, "sshd", "-T"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) == 2 {
				switch f[0] {
				case "passwordauthentication":
					res["PasswordAuthentication"] = f[1]
				case "permitrootlogin":
					res["PermitRootLogin"] = f[1]
				}
			}
		}
	}
	return res
}

// setSSH: one setting, in its own file in sshd_config.d when the main file
// includes it (else in sshd_config itself), checked with sshd -t and put
// back if refused, then reloaded. Refuses to turn passwords off when root
// has no SSH key (you could lock yourself out).
func setSSH(setting, value string) error {
	ok := false
	for _, v := range sshSettings[setting] {
		ok = ok || v == value
	}
	if !ok {
		return errors.New("that SSH setting or value isn't one Apex changes")
	}
	if setting == "PasswordAuthentication" && value == "no" && !anyKeys() {
		return errors.New("no one has an SSH key on this server yet: turning passwords off would lock everyone out. Add a key first")
	}
	main := "/etc/ssh/sshd_config"
	b, _ := os.ReadFile(main)
	var edits []edit
	if strings.Contains(string(b), "sshd_config.d/") {
		edits = []edit{writeFile("/etc/ssh/sshd_config.d/00-apex-"+strings.ToLower(setting)+".conf", fmt.Sprintf("# Set in Apex\n%s %s\n", setting, value))}
	} else {
		lines := strings.Split(string(b), "\n")
		found := false
		for i, l := range lines {
			if f := strings.Fields(l); len(f) > 0 && strings.EqualFold(f[0], setting) {
				lines[i] = setting + " " + value
				found = true
			}
		}
		if !found {
			lines = append([]string{setting + " " + value}, lines...)
		}
		st := stateOf(main)
		edits = []edit{{main, fileState{exists: true, data: []byte(strings.Join(lines, "\n")), mode: st.mode | 0o600}}}
	}
	check := func() error {
		out, err := combined(15*time.Second, "sshd", "-t")
		if err != nil {
			return errors.New(lastLine(out))
		}
		return nil
	}
	reload := func() error {
		for _, unit := range []string{"ssh", "sshd"} {
			if _, err := run(20*time.Second, "systemctl", "reload", unit); err == nil {
				return nil
			}
		}
		if _, err := run(20*time.Second, "service", "ssh", "reload"); err == nil {
			return nil
		}
		_, err := run(20*time.Second, "rc-service", "sshd", "reload")
		return err
	}
	return apply(edits, check, reload)
}

func anyKeys() bool {
	for _, u := range systemUsers() {
		if len(readKeys(u["home"].(string))) > 0 {
			return true
		}
	}
	return false
}

// MARK: Users and SSH keys

func systemUsers() []map[string]any {
	var out []map[string]any
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return out
	}
	defer f.Close()
	admins := map[string]bool{}
	if g, err := os.ReadFile("/etc/group"); err == nil {
		for _, l := range strings.Split(string(g), "\n") {
			p := strings.Split(l, ":")
			if len(p) == 4 && (p[0] == "sudo" || p[0] == "wheel" || p[0] == "admin") {
				for _, m := range strings.Split(p[3], ",") {
					admins[m] = true
				}
			}
		}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(p[2])
		shell := p[6]
		if uid != 0 && (uid < 1000 || uid >= 65534) || strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
			continue
		}
		out = append(out, map[string]any{"name": p[0], "uid": uid, "home": p[5], "shell": shell, "admin": uid == 0 || admins[p[0]], "keys": len(readKeys(p[5]))})
	}
	return out
}

func readKeys(home string) []string {
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		return nil
	}
	var keys []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	return keys
}

var keyRE = regexp.MustCompile(`^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/=]{40,}( [^\n\r]{0,200})?$`)

func usersDo(r PanelRequest) (any, error) {
	if r.Op == "users.list" {
		return systemUsers(), nil
	}
	var home, name string
	for _, u := range systemUsers() {
		if u["name"] == r.User {
			home, name = u["home"].(string), u["name"].(string)
		}
	}
	if home == "" {
		return nil, fmt.Errorf("there's no user called %s who can sign in", r.User)
	}
	file := filepath.Join(home, ".ssh", "authorized_keys")
	switch r.Op {
	case "keys.list":
		keys := readKeys(home)
		if keys == nil {
			keys = []string{}
		}
		return keys, nil
	case "keys.add", "keys.remove":
		key := strings.TrimSpace(r.Key)
		if r.Op == "keys.add" && !keyRE.MatchString(key) {
			return nil, errors.New("that isn't an SSH public key (it starts with ssh-ed25519, ssh-rsa or ecdsa-…)")
		}
		keys := readKeys(home)
		var out []string
		for _, k := range keys {
			if k != key {
				out = append(out, k)
			}
		}
		if r.Op == "keys.add" {
			out = append(out, key)
		} else if len(out) == len(keys) {
			return nil, errors.New("that key isn't there")
		}
		u, err := user.Lookup(name)
		if err != nil {
			return nil, err
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		os.MkdirAll(filepath.Dir(file), 0o700)
		os.Chown(filepath.Dir(file), uid, gid)
		if err := os.WriteFile(file, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
			return nil, err
		}
		return nil, os.Chown(file, uid, gid)
	}
	return nil, errors.New("unknown action")
}

func securityDo(r PanelRequest) (any, error) {
	switch r.Op {
	case "fw.status":
		return fwStatus()
	case "f2b.status":
		return f2bStatus()
	case "f2b.unban":
		if net.ParseIP(r.IP) == nil || !safeName.MatchString(r.Jail) {
			return nil, errors.New("give a jail and an address")
		}
		out, err := combined(15*time.Second, "fail2ban-client", "set", r.Jail, "unbanip", r.IP)
		if err != nil {
			return nil, errors.New(lastLine(out))
		}
		return nil, nil
	case "ssh.status":
		return sshStatus(), nil
	case "ssh.set":
		return nil, setSSH(r.Setting, r.Value)
	}
	return fwDo(r)
}
