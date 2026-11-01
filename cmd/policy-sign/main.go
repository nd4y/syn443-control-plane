// Offline/operator role only. No network or general signing RPC.
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"io"
	"os"
	"strconv"
	"time"
)

func run() error {
	path := os.Getenv("SYN443_POLICY_SIGNING_KEY_FILE")
	info, e := os.Stat(path)
	if e != nil || info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private signing file must have owner-only permissions")
	}
	bytes, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return fmt.Errorf("PKCS8 signing key required")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return fmt.Errorf("invalid signing key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("EC signing key required")
	}
	revision, e := strconv.ParseInt(os.Getenv("SYN443_POLICY_REVISION"), 10, 64)
	if e != nil {
		return fmt.Errorf("explicit publication revision required")
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, policy.MaxBundle+1))
	if e != nil {
		return e
	}
	payload, e := policy.Decode(raw, time.Now())
	if e != nil {
		return fmt.Errorf("publication rejected")
	}
	operation := os.Getenv("SYN443_POLICY_OPERATION")
	if operation == "" {
		operation = "configure"
	}
	if payload.Operation != operation {
		return fmt.Errorf("publication operation not authorized")
	}
	signed, e := policy.Sign(raw, os.Getenv("SYN443_POLICY_KEY_ID"), key, os.Getenv("SYN443_POLICY_DEVICE"), revision, time.Now())
	if e != nil {
		return fmt.Errorf("publication rejected")
	}
	_, e = fmt.Fprintln(os.Stdout, signed)
	return e
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
