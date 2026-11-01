package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnerCLIPrivateExportAndFailurePreserveSnapshot(t *testing.T) {
	dir := t.TempDir()
	token := "synthetic-owner-token-only"
	expiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	var status atomic.Int32
	status.Store(200)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("owner credential missing")
		}
		w.Header().Set("Content-Type", "application/json")
		currentStatus := status.Load()
		w.WriteHeader(int(currentStatus))
		if currentStatus != 200 {
			return
		}
		if r.URL.Path == "/api/users/42" {
			fmt.Fprintf(w, `{"response":{"id":42,"shortUuid":"fixture","status":"ACTIVE","expireAt":%q}}`, expiry)
		} else if r.URL.Path == "/api/subscriptions/by-id/42" {
			fmt.Fprintf(w, `{"response":{"isFound":true,"user":{"shortUuid":"fixture","isActive":true,"userStatus":"ACTIVE","expiresAt":%q,"trafficUsedBytes":"1","trafficLimitBytes":"0"},"links":["https://proxy.example.invalid/sensitive-profile"]}}`, expiry)
		} else {
			t.Error("unexpected route")
		}
	}))
	defer s.Close()
	cert := filepath.Join(dir, "ca.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0644)
	secret := filepath.Join(dir, "credential")
	os.WriteFile(secret, []byte(token), 0600)
	config := filepath.Join(dir, "resource.json")
	raw, _ := json.Marshal(map[string]any{"fixtureLoopback": true, "resourceId": "panel-a", "providerType": "panel.remnawave", "apiVersion": "3.4", "endpoint": s.URL, "enabled": true, "credentialFile": secret, "certificateAuthorityFile": cert, "allowedNetworks": []string{"127.0.0.1/32"}})
	os.WriteFile(config, raw, 0600)
	call := func(extra ...string) (int, string) {
		var out bytes.Buffer
		args := append([]string{"-config", config, "-user-id", "42"}, extra...)
		n := run(context.Background(), args, &out)
		return n, out.String()
	}
	n, out := call()
	if n != 0 || !strings.Contains(out, `"profileCount":1`) {
		t.Fatal("owner summary failed")
	}
	for _, private := range []string{token, s.URL, "sensitive-profile", secret} {
		if strings.Contains(out, private) {
			t.Fatal("ordinary output leaked provider information")
		}
	}
	file := filepath.Join(dir, "snapshot.json")
	n, out = call("-private-output", file)
	if n != 0 {
		t.Fatal("private export failed")
	}
	snapshot, _ := os.ReadFile(file)
	info, _ := os.Stat(file)
	if !strings.Contains(string(snapshot), "sensitive-profile") || info.Mode().Perm() != 0600 {
		t.Fatal("private snapshot not protected")
	}
	n, _ = call("-private-output", file)
	if n == 0 {
		t.Fatal("existing snapshot replaced")
	}
	status.Store(503)
	n, out = call("-private-output", file)
	if n == 0 || !strings.Contains(out, `"provider_unavailable"`) {
		t.Fatal("provider failure hidden")
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(snapshot, after) {
		t.Fatal("provider outage changed last good snapshot")
	}
	status.Store(200)
	for _, tc := range []struct {
		name   string
		change func()
		undo   func()
	}{
		{"public-secret", func() { os.Chmod(secret, 0644) }, func() { os.Chmod(secret, 0600) }},
		{"duplicate-json", func() { os.WriteFile(config, []byte(`{"resourceId":"a","resourceId":"b"}`), 0600) }, func() { os.WriteFile(config, raw, 0600) }},
		{"symlink-config", func() { os.Rename(config, config+".real"); os.Symlink(config+".real", config) }, func() { os.Remove(config); os.Rename(config+".real", config) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.change()
			defer tc.undo()
			n, out := call()
			if n == 0 || strings.Contains(out, token) {
				t.Fatal("untrusted owner file accepted or leaked")
			}
		})
	}
	var bad bytes.Buffer
	if run(context.Background(), []string{"-unknown", token}, &bad) == 0 || strings.Contains(bad.String(), token) {
		t.Fatal("argument rejection leaked input")
	}
}
