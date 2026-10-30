package main

import (
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Updates and packages with the system's own package manager: apt, dnf or
// yum, apk, zypper. Listing works without panel mode; refreshing,
// upgrading, installing and removing run as background jobs.

type PkgUpdate struct {
	Name     string `json:"name"`
	Current  string `json:"current,omitempty"`
	New      string `json:"new"`
	Security bool   `json:"security"`
}

func packageManager() (string, bool) {
	for _, m := range []string{"apt-get", "dnf", "yum", "apk", "zypper"} {
		if have(m) {
			return strings.TrimSuffix(m, "-get"), true
		}
	}
	return "", false
}

var pkgName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:@-]{0,127}$`)

var aptUpgradableRE = regexp.MustCompile(`^([^/\s]+)/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from: ([^\]]+)\])?`)

// parseAptUpgradable: `apt list --upgradable`. Pure: tested.
func parseAptUpgradable(out string) []PkgUpdate {
	var u []PkgUpdate
	for _, l := range strings.Split(out, "\n") {
		if m := aptUpgradableRE.FindStringSubmatch(l); m != nil {
			u = append(u, PkgUpdate{Name: m[1], New: m[3], Current: m[4], Security: strings.Contains(m[2], "security")})
		}
	}
	return u
}

// parseDnfCheck: `dnf check-update` (name.arch version repo). Pure: tested.
func parseDnfCheck(out string, security map[string]bool) []PkgUpdate {
	var u []PkgUpdate
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(l, " ") || !strings.Contains(f[0], ".") || strings.HasPrefix(f[0], "Last") {
			continue
		}
		if l == "Obsoleting Packages" {
			break
		}
		name := f[0][:strings.LastIndex(f[0], ".")]
		u = append(u, PkgUpdate{Name: name, New: f[1], Security: security[name]})
	}
	return u
}

var apkRE = regexp.MustCompile(`^(\S+?)-(\d\S*)\s+<\s+(\S+)`)

// parseApkVersion: `apk version -l '<'`. Pure: tested.
func parseApkVersion(out string) []PkgUpdate {
	var u []PkgUpdate
	for _, l := range strings.Split(out, "\n") {
		if m := apkRE.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			u = append(u, PkgUpdate{Name: m[1], Current: m[2], New: m[3]})
		}
	}
	return u
}

// parseZypper: `zypper -q lu` table rows (v | repo | name | current | new | arch). Pure: tested.
func parseZypper(out string) []PkgUpdate {
	var u []PkgUpdate
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, "|")
		if len(f) < 6 || strings.TrimSpace(f[0]) != "v" {
			continue
		}
		u = append(u, PkgUpdate{Name: strings.TrimSpace(f[2]), Current: strings.TrimSpace(f[3]), New: strings.TrimSpace(f[4])})
	}
	return u
}

func rebootRequired() bool {
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return true
	}
	if have("needs-restarting") {
		if _, err := run(20*time.Second, "needs-restarting", "-r"); err != nil {
			return true
		}
	}
	return false
}

func listUpdates() (map[string]any, error) {
	pm, ok := packageManager()
	if !ok {
		return nil, errors.New("no package manager Apex knows (apt, dnf, yum, apk, zypper) is installed")
	}
	var ups []PkgUpdate
	switch pm {
	case "apt":
		out, _ := combined(60*time.Second, "apt", "list", "--upgradable")
		ups = parseAptUpgradable(out)
	case "dnf", "yum":
		out, _ := combined(120*time.Second, pm, "-q", "check-update")
		sec := map[string]bool{}
		if s, err := combined(120*time.Second, pm, "-q", "updateinfo", "list", "--security"); err == nil {
			for _, l := range strings.Split(s, "\n") {
				if f := strings.Fields(l); len(f) >= 3 {
					n := f[2]
					if i := strings.LastIndex(n, "-"); i > 0 {
						if j := strings.LastIndex(n[:i], "-"); j > 0 {
							n = n[:j]
						}
					}
					sec[n] = true
				}
			}
		}
		ups = parseDnfCheck(out, sec)
	case "apk":
		out, _ := combined(60*time.Second, "apk", "version", "-l", "<")
		ups = parseApkVersion(out)
	case "zypper":
		out, _ := combined(120*time.Second, "zypper", "-q", "--non-interactive", "lu")
		ups = parseZypper(out)
	}
	if ups == nil {
		ups = []PkgUpdate{}
	}
	sort.Slice(ups, func(i, j int) bool {
		if ups[i].Security != ups[j].Security {
			return ups[i].Security
		}
		return ups[i].Name < ups[j].Name
	})
	var checked int64
	for _, p := range []string{"/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists", "/var/cache/dnf", "/var/cache/apk"} {
		if fi, err := os.Stat(p); err == nil {
			checked = fi.ModTime().Unix()
			break
		}
	}
	return map[string]any{"manager": pm, "updates": ups, "rebootRequired": rebootRequired(), "checked": checked}, nil
}

var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"}
var aptKeep = []string{"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}

func packagesDo(r PanelRequest) (any, error) {
	if r.Op == "pkg.list" {
		return listUpdates()
	}
	pm, ok := packageManager()
	if !ok {
		return nil, errors.New("no package manager Apex knows is installed")
	}
	for _, n := range r.Names {
		if !pkgName.MatchString(n) {
			return nil, errors.New(n + " isn't a package name")
		}
	}
	var name string
	var args []string
	var env []string
	title := r.Op
	switch r.Op {
	case "pkg.refresh":
		title = "Checking for updates"
		switch pm {
		case "apt":
			name, args, env = "apt-get", []string{"update"}, aptEnv
		case "dnf", "yum":
			name, args = pm, []string{"-q", "makecache"}
		case "apk":
			name, args = "apk", []string{"update"}
		case "zypper":
			name, args = "zypper", []string{"--non-interactive", "refresh"}
		}
	case "pkg.upgrade":
		title = "Installing updates"
		switch pm {
		case "apt":
			env = aptEnv
			if len(r.Names) > 0 {
				name, args = "apt-get", append(append([]string{"-y"}, aptKeep...), append([]string{"install", "--only-upgrade"}, r.Names...)...)
			} else {
				name, args = "apt-get", append(append([]string{"-y"}, aptKeep...), "full-upgrade")
			}
		case "dnf", "yum":
			name, args = pm, append([]string{"-y", "upgrade"}, r.Names...)
			if r.All && len(r.Names) == 0 && r.Setting == "security" {
				args = []string{"-y", "upgrade", "--security"}
			}
		case "apk":
			name, args = "apk", append([]string{"upgrade"}, r.Names...)
		case "zypper":
			name, args = "zypper", append([]string{"--non-interactive", "update"}, r.Names...)
		}
	case "pkg.install", "pkg.remove":
		if len(r.Names) == 0 {
			return nil, errors.New("name a package")
		}
		install := r.Op == "pkg.install"
		title = map[bool]string{true: "Installing ", false: "Removing "}[install] + strings.Join(r.Names, ", ")
		switch pm {
		case "apt":
			env = aptEnv
			name, args = "apt-get", append(append([]string{"-y"}, aptKeep...), append([]string{map[bool]string{true: "install", false: "remove"}[install]}, r.Names...)...)
		case "dnf", "yum":
			name, args = pm, append([]string{"-y", map[bool]string{true: "install", false: "remove"}[install]}, r.Names...)
		case "apk":
			name, args = "apk", append([]string{map[bool]string{true: "add", false: "del"}[install]}, r.Names...)
		case "zypper":
			name, args = "zypper", append([]string{"--non-interactive", map[bool]string{true: "install", false: "remove"}[install]}, r.Names...)
		}
	case "pkg.reboot":
		title = "Restarting the server"
		go func() {
			time.Sleep(time.Second)
			run(30*time.Second, "systemctl", "reboot")
			run(30*time.Second, "reboot")
		}()
		return nil, nil
	default:
		return nil, errors.New("unknown action")
	}
	return map[string]any{"job": startJob(title, env, name, args...)}, nil
}
