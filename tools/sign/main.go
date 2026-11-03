// sign: makes the release key, or signs a release file with it.
//
//	go run ./tools/sign -genkey KEYFILE   prints the public key for update.go
//	go run ./tools/sign KEYFILE FILE      writes FILE.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-genkey" {
		if _, err := os.Stat(os.Args[2]); err == nil {
			fail("%s already exists; not replacing a release key", os.Args[2])
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		check(err)
		check(os.WriteFile(os.Args[2], []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600))
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return
	}
	if len(os.Args) != 3 {
		fail("usage: sign -genkey KEYFILE | sign KEYFILE FILE")
	}
	k, err := os.ReadFile(os.Args[1])
	check(err)
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(k)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		fail("%s isn't a release key", os.Args[1])
	}
	data, err := os.ReadFile(os.Args[2])
	check(err)
	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	check(os.WriteFile(os.Args[2]+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644))
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(f string, a ...any) { fmt.Fprintf(os.Stderr, "sign: "+f+"\n", a...); os.Exit(1) }
