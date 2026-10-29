package main

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Traffic for each site: the end of its access log (the last 2 MB), the
// last 10 minutes of it. Reads nginx's and Apache's combined format, Nginx
// Proxy Manager's, Traefik's common format (with the router's name), and
// Caddy's and Traefik's JSON.

type SiteTraffic struct {
	Requests   int            `json:"requests"`
	Window     float64        `json:"window"` // seconds the numbers cover
	PerMinute  float64        `json:"perMinute"`
	Bytes      int64          `json:"bytes"`
	Statuses   map[string]int `json:"statuses"` // 2xx, 3xx, 4xx, 5xx
	TopPaths   []Count        `json:"topPaths"`
	TopClients []Count        `json:"topClients"`
}

type Count struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type hit struct {
	t                  time.Time
	ip, host, path, rt string
	status             int
	bytes              int64
}

const trafficWindow = 10 * time.Minute
const tailBytes = 2 << 20

var (
	combinedRE = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(?:\S+ (\S+)[^"]*|[^"]*)" (\d{3}) (\d+|-)(?: "[^"]*" "[^"]*" \d+ "([^"]*)")?`)
	npmRE      = regexp.MustCompile(`^\[([^\]]+)\] \S+ \S+ (\d{3}) - \S+ \S+ (\S+) "([^"]*)" \[Client ([^\]]+)\] \[Length (\d+)\]`)
)

const clfTime = "02/Jan/2006:15:04:05 -0700"

// parseHit: one access log line in any of the formats, or false.
func parseHit(line string) (hit, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		return parseJSONHit(line)
	}
	if m := npmRE.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(clfTime, m[1])
		if err != nil {
			return hit{}, false
		}
		st, _ := strconv.Atoi(m[2])
		b, _ := strconv.ParseInt(m[6], 10, 64)
		return hit{t: t, status: st, host: m[3], path: m[4], ip: m[5], bytes: b}, true
	}
	if m := combinedRE.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(clfTime, m[2])
		if err != nil {
			return hit{}, false
		}
		st, _ := strconv.Atoi(m[4])
		b, _ := strconv.ParseInt(m[5], 10, 64)
		return hit{t: t, ip: m[1], path: m[3], status: st, bytes: b, rt: m[6]}, true
	}
	return hit{}, false
}

func parseJSONHit(line string) (hit, bool) {
	var j map[string]any
	if json.Unmarshal([]byte(line), &j) != nil {
		return hit{}, false
	}
	var h hit
	num := func(v any) float64 { f, _ := v.(float64); return f }
	str := func(v any) string { s, _ := v.(string); return s }
	if req, ok := j["request"].(map[string]any); ok { // Caddy
		h.ip, h.host, h.path = str(req["remote_ip"]), str(req["host"]), str(req["uri"])
		if h.ip == "" {
			h.ip, _, _ = strings.Cut(str(req["remote_addr"]), ":")
		}
		h.status, h.bytes = int(num(j["status"])), int64(num(j["size"]))
		if ts := num(j["ts"]); ts > 0 {
			h.t = time.Unix(int64(ts), int64((ts-float64(int64(ts)))*1e9))
		} else if t, err := time.Parse(time.RFC3339Nano, str(j["ts"])); err == nil {
			h.t = t
		}
	} else if j["RequestHost"] != nil || j["DownstreamStatus"] != nil { // Traefik
		h.ip, h.host, h.path, h.rt = str(j["ClientHost"]), str(j["RequestHost"]), str(j["RequestPath"]), str(j["RouterName"])
		h.status, h.bytes = int(num(j["DownstreamStatus"])), int64(num(j["DownstreamContentSize"]))
		for _, k := range []string{"StartUTC", "time", "StartLocal"} {
			if t, err := time.Parse(time.RFC3339Nano, str(j[k])); err == nil {
				h.t = t
				break
			}
		}
	} else {
		return hit{}, false
	}
	if h.t.IsZero() || h.status == 0 {
		return hit{}, false
	}
	h.host = strings.ToLower(strings.Split(h.host, ":")[0])
	return h, true
}

// readHits: the log's last 2 MB, the lines from the last 10 minutes, and
// how many seconds they cover (less when the 2 MB start inside the window).
func readHits(path string, now time.Time) ([]hit, float64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, false
	}
	start := st.Size() - tailBytes
	cut := start > 0
	if !cut {
		start = 0
	}
	f.Seek(start, io.SeekStart)
	b, _ := io.ReadAll(f)
	lines := strings.Split(string(b), "\n")
	if cut && len(lines) > 0 {
		lines = lines[1:] // the first one is cut in half
	}
	from := now.Add(-trafficWindow)
	var hits []hit
	var oldest time.Time
	for _, l := range lines {
		h, ok := parseHit(l)
		if !ok {
			continue
		}
		if oldest.IsZero() || h.t.Before(oldest) {
			oldest = h.t
		}
		if !h.t.Before(from) && !h.t.After(now.Add(time.Minute)) {
			hits = append(hits, h)
		}
	}
	window := trafficWindow.Seconds()
	if cut && !oldest.IsZero() && oldest.After(from) {
		window = now.Sub(oldest).Seconds()
	}
	return hits, window, true
}

func summarize(hits []hit, window float64) *SiteTraffic {
	t := &SiteTraffic{Requests: len(hits), Window: window, Statuses: map[string]int{}, TopPaths: []Count{}, TopClients: []Count{}}
	paths, ips := map[string]int{}, map[string]int{}
	for _, h := range hits {
		t.Bytes += h.bytes
		if h.status >= 200 && h.status < 600 {
			t.Statuses[strconv.Itoa(h.status/100)+"xx"]++
		}
		p, _, _ := strings.Cut(h.path, "?")
		if p != "" {
			paths[p]++
		}
		if h.ip != "" {
			ips[h.ip]++
		}
	}
	if window > 0 {
		t.PerMinute = float64(len(hits)) / (window / 60)
	}
	t.TopPaths, t.TopClients = top(paths, 5), top(ips, 5)
	return t
}

func top(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// addTraffic: each site's own log; a log several sites share is split by
// the host name or router it records, or not at all when it records neither.
func addTraffic(sites []Site, kinds []proxyKind) {
	now := time.Now()
	type logData struct {
		hits   []hit
		window float64
		ok     bool
	}
	cache := map[string]logData{}
	read := func(p string) logData {
		if d, ok := cache[p]; ok {
			return d
		}
		h, w, ok := readHits(p, now)
		cache[p] = logData{h, w, ok}
		return cache[p]
	}
	users := map[string]int{}
	for _, s := range sites {
		for _, l := range s.logs {
			users[l]++
		}
	}
	shared := map[string][]string{} // Caddy's and Traefik's own logs, by proxy
	for _, k := range kinds {
		switch p := k.(type) {
		case *caddyProxy:
			shared["caddy"] = p.logFiles
		case *traefikProxy:
			if p.accessLog != "" {
				shared["traefik"] = []string{p.accessLog}
			}
		}
	}
	for i := range sites {
		s := &sites[i]
		if !s.Enabled {
			continue
		}
		var hits []hit
		window := 0.0
		found := false
		for _, l := range s.logs {
			d := read(l)
			if !d.ok {
				continue
			}
			found = true
			window = maxf(window, d.window)
			for _, h := range d.hits {
				if users[l] == 1 || matches(*s, h) {
					hits = append(hits, h)
				}
			}
		}
		sharedRead := false
		if !found {
			for _, l := range shared[s.Proxy] {
				d := read(l)
				if !d.ok {
					continue
				}
				sharedRead = true
				for _, h := range d.hits {
					if matches(*s, h) {
						hits = append(hits, h)
						found = true
					}
				}
				window = maxf(window, d.window)
			}
		}
		switch {
		case found:
			s.Traffic = summarize(hits, window)
		case sharedRead:
			s.TrafficNote = "Nothing for this site in the proxy's log in the last 10 minutes (or the proxy doesn't log it)."
		case len(s.logs) > 0:
			s.TrafficNote = "Its access log can't be read: " + s.logs[0]
		default:
			s.TrafficNote = "This site has no access log of its own, so its traffic can't be told apart."
		}
	}
}

// matches: a line from a shared log belongs to the site (by router or host).
func matches(s Site, h hit) bool {
	if s.router != "" && h.rt != "" {
		return h.rt == s.router
	}
	if h.host == "" {
		return false
	}
	for _, d := range s.Domains {
		if d == h.host || strings.HasPrefix(d, "*.") && strings.HasSuffix(h.host, d[1:]) {
			return true
		}
	}
	return false
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
