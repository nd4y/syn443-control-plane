// Local pilot delivery role. TLS termination and production enrollment are separate gates.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func run() error {
	listen := os.Getenv("SYN443_POLICY_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8081"
	}
	host, _, e := net.SplitHostPort(listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("pilot API must bind an explicit loopback IP")
	}
	path := os.Getenv("SYN443_POLICY_PUBLICATION_FILE")
	info, e := os.Stat(path)
	if e != nil || info.IsDir() || info.Size() > policy.MaxBundle+4096 || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("owner-only publication file required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	var manifest struct {
		Device      string `json:"device"`
		TokenSHA256 string `json:"tokenSHA256"`
		Bundle      string `json:"bundle"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&manifest); e != nil {
		return fmt.Errorf("invalid publication manifest")
	}
	hash, e := hex.DecodeString(manifest.TokenSHA256)
	if e != nil || len(hash) != sha256.Size {
		return fmt.Errorf("invalid delivery authorization")
	}
	p := policy.Publication{Device: manifest.Device, Bundle: manifest.Bundle}
	copy(p.BearerHash[:], hash)
	rootPath := os.Getenv("SYN443_POLICY_ROOTS_FILE")
	rootInfo, e := os.Stat(rootPath)
	if e != nil || rootInfo.IsDir() || rootInfo.Size() > 4096 || rootInfo.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("operator-owned read-only publication roots required")
	}
	rootBytes, e := os.ReadFile(rootPath)
	if e != nil {
		return e
	}
	var encoded map[string]string
	if json.Unmarshal(rootBytes, &encoded) != nil || len(encoded) < 1 || len(encoded) > 4 {
		return fmt.Errorf("invalid publication roots")
	}
	p.Roots = map[string]*ecdsa.PublicKey{}
	for kid, encodedKey := range encoded {
		der, err := base64.StdEncoding.Strict().DecodeString(encodedKey)
		if err != nil {
			return fmt.Errorf("invalid publication public key")
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return fmt.Errorf("invalid publication public key")
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("EC publication root required")
		}
		p.Roots[kid] = key
	}
	if _, e = policy.Verify(p.Bundle, p.Roots, p.Device, time.Now()); e != nil {
		return fmt.Errorf("invalid publication")
	}
	server := http.Server{Addr: listen, Handler: policy.Delivery(p), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4096}
	return server.ListenAndServe()
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
