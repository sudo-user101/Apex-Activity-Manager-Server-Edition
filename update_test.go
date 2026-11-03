package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.3.0", "1.2.0", true}, {"v1.3.0", "1.3.0", false}, {"1.10.0", "1.9.9", true},
		{"1.2.0", "1.3.0", false}, {"2.0.0", "1.99.99", true}, {"1.3.1", "1.3.0", true}, {"", "1.0.0", false},
	}
	for _, c := range cases {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestEmbeddedReleaseKey(t *testing.T) {
	if len(publicKey()) != ed25519.PublicKeySize {
		t.Fatal("the release public key in update.go isn't a valid Ed25519 key")
	}
}

func fakeRelease(t *testing.T, ver string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, a := range []string{"amd64", "arm64"} {
		body := []byte("program for " + a)
		tw.WriteHeader(&tar.Header{Name: "apex-server-" + ver + "/apex-server-linux-" + a, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func sums(b []byte) []byte {
	h := sha256.Sum256(b)
	return []byte(hex.EncodeToString(h[:]) + "  apex-server.tar.gz\n")
}

func TestVerifyRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	tgz := fakeRelease(t, "9.9.9")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, tgz)))
	if err := verifyRelease(tgz, sums(tgz), sig, pub); err != nil {
		t.Fatalf("good release refused: %v", err)
	}
	if err := verifyRelease(tgz, sums([]byte("other")), sig, pub); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("wrong checksum accepted: %v", err)
	}
	if err := verifyRelease(tgz, sums(tgz), sig, other); err == nil || !strings.Contains(err.Error(), "signed") {
		t.Errorf("another key accepted: %v", err)
	}
	bad := append([]byte{}, tgz...)
	bad[len(bad)-1] ^= 1
	if err := verifyRelease(bad, sums(bad), sig, pub); err == nil {
		t.Error("changed file with a matching checksum accepted (signature must catch it)")
	}
	if err := verifyRelease(tgz, sums(tgz), []byte("not base64!"), pub); err == nil {
		t.Error("garbage signature accepted")
	}
}

func TestProgramFrom(t *testing.T) {
	tgz := fakeRelease(t, "9.9.9")
	b, err := programFrom(tgz, "9.9.9", "arm64")
	if err != nil || string(b) != "program for arm64" {
		t.Fatalf("got %q, %v", b, err)
	}
	if _, err := programFrom(tgz, "9.9.9", "riscv64"); err == nil {
		t.Error("missing architecture not reported")
	}
}

// The whole check → download → verify → stage path against a local server
// serving a release the way GitHub does.
func TestDownloadUpdate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APEX_SERVER_CONFIG", dir)
	old := configDir
	configDir = dir
	defer func() { configDir = old }()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldKey := trustedKey
	trustedKey = pub
	defer func() { trustedKey = oldKey }()

	tgz := fakeRelease(t, "9.9.9")
	signed := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/v9.9.9/apex-server-9.9.9-linux.tar.gz"
		switch r.URL.Path {
		case "/latest.json":
			w.Write([]byte(`{"tag_name":"v9.9.9"}`))
		case base:
			w.Write(tgz)
		case base + ".sha256":
			w.Write(sums(tgz))
		case base + ".sig":
			if !signed {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, tgz))))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("APEX_UPDATE_SOURCE", srv.URL)

	latest, err := checkNow()
	if err != nil || latest != "9.9.9" {
		t.Fatalf("check: %q %v", latest, err)
	}
	if st := updateStatus(); st["available"] != true || st["current"] != version {
		t.Errorf("status: %v", st)
	}
	staged, err := downloadUpdate("9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(staged)
	if string(b) != "program for "+runtime.GOARCH {
		t.Errorf("staged %q", b)
	}

	signed = false
	if _, err := downloadUpdate("9.9.9"); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Errorf("unsigned release accepted: %v", err)
	}
	trustedKey, _, _ = ed25519.GenerateKey(rand.Reader)
	signed = true
	if _, err := downloadUpdate("9.9.9"); err == nil {
		t.Error("release signed with another key accepted")
	}
}

func TestAutoUpdatesDefaultOn(t *testing.T) {
	dir := t.TempDir()
	old := configDir
	configDir = dir
	defer func() { configDir = old }()
	if !autoUpdates() {
		t.Error("should be on when never set")
	}
	setAutoUpdates(false)
	if autoUpdates() {
		t.Error("off didn't stick")
	}
	setAutoUpdates(true)
	if !autoUpdates() {
		t.Error("on didn't stick")
	}
}
