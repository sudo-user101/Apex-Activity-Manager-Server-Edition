package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Everything that keeps the Server Edition private:
//   - its own TLS certificate (made on first start; the app remembers its
//     fingerprint, so nobody can stand in for the server),
//   - a pairing code, shown when it's installed (or by `apex-server pair`),
//     valid for 24 hours, that a Mac or browser swaps once for its own token,
//   - tokens (only their SHA-256 is stored), one per device, removable,
//   - a limit on wrong codes: 10 a quarter of an hour per address.

var configDir = "/etc/apex-server"

type Config struct {
	Port int    `json:"port"`
	Bind string `json:"bind"` // "" = every address
}

type Device struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"lastSeen"`
}

type Pairing struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}

func path(name string) string { return filepath.Join(configDir, name) }

func loadJSON(name string, v any) error {
	b, err := os.ReadFile(path(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// saveJSON: written beside, then renamed (never half a file), root only.
func saveJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path(name + ".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(name))
}

func loadConfig() Config {
	c := Config{Port: 7443}
	loadJSON("config.json", &c)
	if c.Port <= 0 || c.Port > 65535 {
		c.Port = 7443
	}
	return c
}

// MARK: Certificate

func ensureCertificate() (tls.Certificate, string, error) {
	certPath, keyPath := path("cert.pem"), path("key.pem")
	if _, err := os.Stat(certPath); err != nil {
		if err := makeCertificate(certPath, keyPath); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, fingerprint(cert.Certificate[0]), nil
}

func makeCertificate(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	t := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Apex Activity Manager Server Edition"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host, "localhost"},
	}
	for _, a := range localIPs() {
		t.IPAddresses = append(t.IPAddresses, a)
	}
	der, err := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// fingerprint: SHA-256 of the certificate, as the app shows it ("AB:CD:…").
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func localIPs() []net.IP {
	var out []net.IP
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		as, _ := i.Addrs()
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				out = append(out, ipn.IP)
			}
		}
	}
	return out
}

// MARK: Pairing and devices

// Letters and digits that can't be mistaken for each other (no 0/O, 1/I/L).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func newCode() string {
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

// normalizeCode: "abcd efgh", "ABCD-EFGH" → "ABCD-EFGH". Pure: tested.
func normalizeCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if strings.ContainsRune(codeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	v := b.String()
	if len(v) != 8 {
		return v
	}
	return v[:4] + "-" + v[4:]
}

type Auth struct {
	mu       sync.Mutex
	devices  []Device
	pairing  Pairing
	failures map[string][]time.Time
}

func NewAuth() *Auth {
	a := &Auth{failures: map[string][]time.Time{}}
	loadJSON("devices.json", &a.devices)
	loadJSON("pairing.json", &a.pairing)
	return a
}

// NewPairing makes a fresh code, valid for 24 hours.
func (a *Auth) NewPairing() (Pairing, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pairing = Pairing{Code: newCode(), Expires: time.Now().Add(24 * time.Hour)}
	return a.pairing, saveJSON("pairing.json", a.pairing)
}

var errTooMany = errors.New("too many wrong codes from this address; wait 15 minutes")
var errBadCode = errors.New("that pairing code is wrong or has expired. Run `sudo apex-server pair` on the server for a new one")

// Pair swaps the pairing code for a new device token.
func (a *Auth) Pair(code, device, from string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Re-read: `apex-server pair` may have made a new code since this started.
	loadJSON("pairing.json", &a.pairing)
	now := time.Now()
	recent := a.failures[from][:0]
	for _, t := range a.failures[from] {
		if now.Sub(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	a.failures[from] = recent
	if len(recent) >= 10 {
		return "", errTooMany
	}
	want := a.pairing.Code
	if want == "" || now.After(a.pairing.Expires) || subtle.ConstantTimeCompare([]byte(normalizeCode(code)), []byte(want)) != 1 {
		a.failures[from] = append(a.failures[from], now)
		return "", errBadCode
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	idb := make([]byte, 4)
	rand.Read(idb)
	name := strings.TrimSpace(device)
	if name == "" {
		name = "Unnamed device"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	a.devices = append(a.devices, Device{ID: hex.EncodeToString(idb), Name: name, Hash: hashToken(token), Created: now, LastSeen: now})
	return token, saveJSON("devices.json", a.devices)
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

// Check: is this a paired device's token? Notes when it was last seen.
func (a *Auth) Check(token string) bool {
	if token == "" {
		return false
	}
	h := hashToken(token)
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, d := range a.devices {
		if subtle.ConstantTimeCompare([]byte(d.Hash), []byte(h)) == 1 {
			if time.Since(d.LastSeen) > 5*time.Minute {
				a.devices[i].LastSeen = time.Now()
				saveJSON("devices.json", a.devices)
			}
			return true
		}
	}
	return false
}

// Reload picks up devices removed with `apex-server devices remove`.
func (a *Auth) Reload() {
	a.mu.Lock()
	defer a.mu.Unlock()
	var d []Device
	if loadJSON("devices.json", &d) == nil {
		a.devices = d
	}
}

func (a *Auth) Forget(token string) {
	h := hashToken(token)
	a.mu.Lock()
	defer a.mu.Unlock()
	keep := a.devices[:0]
	for _, d := range a.devices {
		if d.Hash != h {
			keep = append(keep, d)
		}
	}
	a.devices = keep
	saveJSON("devices.json", a.devices)
}
