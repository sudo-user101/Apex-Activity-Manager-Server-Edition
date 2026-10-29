package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Apex Activity Manager Server Edition: a task manager for a Linux server.
// It reads the whole server (as root) and serves it, encrypted, to the Apex
// app on a Mac and to a browser, on its own port (7443 by default).
//
//	apex-server run                 the service (installed by install.sh)
//	apex-server setup [--port N]    first-time setup: certificate, port, pairing code
//	apex-server pair                a new pairing code (valid 24 hours)
//	apex-server devices [remove ID] paired Macs and browsers
//	apex-server status              address, port, fingerprint, devices
//	apex-server snapshot            one reading as JSON (for checking by hand)
//	apex-server sites               reverse proxies and their sites as JSON
//	apex-server version

var version = "1.1.0"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if d := os.Getenv("APEX_SERVER_CONFIG"); d != "" { // tests
		configDir = d
	}
	switch os.Args[1] {
	case "run":
		mustRoot()
		mustSetup()
		cfg := loadConfig()
		cert, fp, err := ensureCertificate()
		if err != nil {
			log.Fatalf("certificate: %v", err)
		}
		c := NewCollector()
		go c.Run()
		log.Printf("Apex Activity Manager Server Edition %s on port %d (certificate %s)", version, cfg.Port, fp)
		if err := Serve(c, NewAuth(), cfg, cert); err != nil {
			log.Fatalf("server: %v", err)
		}
	case "setup":
		mustRoot()
		fs := flag.NewFlagSet("setup", flag.ExitOnError)
		port := fs.Int("port", 0, "port to listen on (default 7443)")
		fs.Parse(os.Args[2:])
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			log.Fatal(err)
		}
		cfg := loadConfig()
		if *port > 0 && *port < 65536 {
			cfg.Port = *port
		}
		if err := saveJSON("config.json", cfg); err != nil {
			log.Fatal(err)
		}
		if _, _, err := ensureCertificate(); err != nil {
			log.Fatal(err)
		}
		p, err := NewAuth().NewPairing()
		if err != nil {
			log.Fatal(err)
		}
		printWelcome(cfg, p)
	case "pair":
		mustRoot()
		mustSetup()
		p, err := NewAuth().NewPairing()
		if err != nil {
			log.Fatal(err)
		}
		printWelcome(loadConfig(), p)
	case "devices":
		mustRoot()
		a := NewAuth()
		if len(os.Args) >= 4 && os.Args[2] == "remove" {
			n := len(a.devices)
			keep := a.devices[:0]
			for _, d := range a.devices {
				if d.ID != os.Args[3] {
					keep = append(keep, d)
				}
			}
			a.devices = keep
			saveJSON("devices.json", a.devices)
			if len(keep) == n {
				fmt.Println("No device with that id.")
			} else {
				fmt.Println("Removed. It can't connect any more (within 30 seconds).")
			}
			return
		}
		if len(a.devices) == 0 {
			fmt.Println("No paired devices yet. Pair one with the code from `sudo apex-server pair`.")
		}
		for _, d := range a.devices {
			fmt.Printf("%s  %-30s paired %s, last seen %s\n", d.ID, d.Name, d.Created.Format("2006-01-02"), d.LastSeen.Format(time.DateTime))
		}
	case "status":
		mustRoot()
		cfg := loadConfig()
		_, fp, err := ensureCertificate()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Apex Activity Manager Server Edition %s\n", version)
		fmt.Printf("Port %d\nFingerprint %s\n", cfg.Port, fp)
		for _, a := range addresses() {
			fmt.Printf("  https://%s\n", net.JoinHostPort(a, fmt.Sprint(cfg.Port)))
		}
		fmt.Printf("%d paired device(s)\n", len(NewAuth().devices))
	case "snapshot":
		c := NewCollector()
		c.Sample()
		time.Sleep(time.Second)
		c.Sample()
		json.NewEncoder(os.Stdout).Encode(c.Latest())
	case "sites":
		mustRoot()
		r, _ := Proxies(true)
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(r)
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Apex Activity Manager Server Edition `+version+`

  apex-server run                  run the service (install.sh sets this up)
  apex-server setup [--port 7443]  certificate, port and a pairing code
  apex-server pair                 a new pairing code (valid 24 hours)
  apex-server devices              paired devices
  apex-server devices remove ID    unpair one
  apex-server status               addresses, port, certificate fingerprint
  apex-server snapshot             one reading as JSON
  apex-server sites                reverse proxies, their sites and traffic, as JSON`)
}

func mustRoot() {
	if os.Geteuid() != 0 && os.Getenv("APEX_SERVER_CONFIG") == "" {
		fmt.Fprintln(os.Stderr, "Run it as root (sudo): Apex needs root to see every process and to manage services.")
		os.Exit(1)
	}
}

func mustSetup() {
	if _, err := os.Stat(path("config.json")); err != nil {
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			log.Fatal(err)
		}
		saveJSON("config.json", Config{Port: 7443})
	}
}

// addresses: this server's own IP addresses (not loopback or container
// bridges such as docker0), IPv4 first, for the welcome message.
func addresses() []string {
	var v4, v6 []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || skipInterface(i.Name) {
			continue
		}
		as, _ := i.Addrs()
		for _, a := range as {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if ipn.IP.To4() != nil {
				v4 = append(v4, ipn.IP.String())
			} else {
				v6 = append(v6, ipn.IP.String())
			}
		}
	}
	return append(v4, v6...)
}

func printWelcome(cfg Config, p Pairing) {
	_, fp, _ := ensureCertificate()
	fmt.Println()
	fmt.Println("  Apex Activity Manager Server Edition")
	fmt.Println()
	fmt.Println("  In Apex on your Mac: This Mac menu › Add Server…, choose Server Edition, and enter:")
	for _, a := range addresses() {
		fmt.Printf("      Address  %s   Port  %d\n", a, cfg.Port)
	}
	fmt.Printf("      Pairing code  %s   (valid until %s)\n", p.Code, p.Expires.Format("2 Jan 15:04"))
	fmt.Println()
	fmt.Println("  Or in a browser:")
	for _, a := range addresses() {
		fmt.Printf("      https://%s\n", net.JoinHostPort(a, fmt.Sprint(cfg.Port)))
	}
	fmt.Println("      (the browser warns about the certificate the first time: it's this server's own;")
	fmt.Println("       check that its SHA-256 fingerprint matches the one below, then continue)")
	fmt.Println()
	fmt.Printf("  Certificate fingerprint\n      %s\n", fp)
	fmt.Println()
	fmt.Println("  A new code any time: sudo apex-server pair")
	fmt.Println()
}
