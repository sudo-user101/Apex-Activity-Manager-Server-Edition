package main

// One reading of the whole server, in the same shape the Apex Mac app
// already reads from its SSH connection (its ServerSnapshot), plus fields
// only the Server Edition has (the app ignores what it doesn't know). Change
// a field's name or type only together with the app.

type Snapshot struct {
	Agent          int         `json:"agent"`
	Edition        string      `json:"edition"`
	Version        string      `json:"version"`
	Host           string      `json:"host"`
	OS             string      `json:"os"`
	Kernel         string      `json:"kernel"`
	InContainer    bool        `json:"inContainer"`
	Uptime         float64     `json:"uptime"`
	CPU            CPU         `json:"cpu"`
	Memory         Memory      `json:"memory"`
	Disks          []Disk      `json:"disks"`
	Network        []Net       `json:"network"`
	Processes      []Process   `json:"processes"`
	GPUs           []GPU       `json:"gpus"`
	Containers     []Container `json:"containers"`
	FailedServices []string    `json:"failedServices"`
	Services       []Service   `json:"services"`
	ServiceManager string      `json:"serviceManager"` // systemd, openrc, sysv, or ""
	Sessions       []Session   `json:"sessions"`
	WebServers     []string    `json:"webServers"`
	Connections    int         `json:"connections"`
	Sensors        []Sensor    `json:"sensors"`
	Taken          int64       `json:"taken"` // Unix ms
}

type CPU struct {
	Total   float64   `json:"total"`
	PerCore []float64 `json:"perCore"`
	Cores   int       `json:"cores"`
	Model   string    `json:"model"`
	Load    []float64 `json:"load"`
}

type Memory struct {
	Total     int64 `json:"total"`
	Available int64 `json:"available"`
	Cached    int64 `json:"cached"`
	SwapTotal int64 `json:"swapTotal"`
	SwapFree  int64 `json:"swapFree"`
}

type Disk struct {
	Device        string  `json:"device"`
	Mount         string  `json:"mount"`
	FSType        string  `json:"fsType"`
	Total         int64   `json:"total"`
	Used          int64   `json:"used"`
	Free          int64   `json:"free"`
	ReadPerSec    float64 `json:"readPerSec"`
	WritePerSec   float64 `json:"writePerSec"`
	ActivePercent float64 `json:"activePercent"`
}

type Net struct {
	Name      string   `json:"name"`
	InPerSec  float64  `json:"inPerSec"`
	OutPerSec float64  `json:"outPerSec"`
	Received  int64    `json:"received"`
	Sent      int64    `json:"sent"`
	Addresses []string `json:"addresses"`
	MAC       string   `json:"mac,omitempty"` // for Wake-on-LAN from the app
}

type Process struct {
	PID         int     `json:"pid"`
	PPID        int     `json:"ppid"`
	User        string  `json:"user"`
	CPU         float64 `json:"cpu"`
	MemPercent  float64 `json:"memPercent"`
	Memory      int64   `json:"memory"`
	Seconds     int64   `json:"seconds"`
	Name        string  `json:"name"`
	Command     string  `json:"command"`
	State       string  `json:"state"`
	Threads     int     `json:"threads"`
	ReadPerSec  float64 `json:"readPerSec"`
	WritePerSec float64 `json:"writePerSec"`
}

type GPU struct {
	Name        string  `json:"name"`
	Utilization float64 `json:"utilization"`
	MemoryUsed  int64   `json:"memoryUsed"`
	MemoryTotal int64   `json:"memoryTotal"`
	Temperature float64 `json:"temperature"`
}

type Container struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	State  string `json:"state"`
	Status string `json:"status"`
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Net    string `json:"net"`
	Block  string `json:"block"`
}

type Service struct {
	Name        string `json:"name"`
	Loaded      string `json:"loaded"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

type Session struct {
	User     string `json:"user"`
	Terminal string `json:"terminal"`
	From     string `json:"from"`
}

type Sensor struct {
	Name    string  `json:"name"`
	Celsius float64 `json:"celsius"`
}
