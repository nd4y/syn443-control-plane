//go:build keycloak

package keycloak_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/chatweb"
)

// Both modes use the same OIDC flows. The release job substitutes the packaged
// server for the in-process handler, including its embedded PatternFly assets.
func startWebFrontend(t *testing.T, ui *httptest.Server, c chatweb.Config) {
	t.Helper()
	image := os.Getenv("SYN443_TEST_WEB_IMAGE")
	if image == "" {
		handler, err := chatweb.New(t.Context(), c, nil)
		if err != nil {
			t.Fatal("web initialization")
		}
		t.Cleanup(handler.Close)
		ui.Config.Handler = handler
		ui.Start()
		t.Cleanup(ui.Close)
		return
	}
	c.Listen = ui.Listener.Addr().String()
	if err := ui.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "fixture.json")
	if err = os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	mount := t.TempDir()
	if err = os.Chmod(mount, 0755); err != nil {
		t.Fatal(err)
	}
	if err = exec.CommandContext(t.Context(), "sudo", "-n", "install", "-m", "0400", "-o", "65532", "-g", "65532", "--", source, filepath.Join(mount, "config.json")).Run(); err != nil {
		t.Fatal("could not assign the private synthetic configuration")
	}
	name := "syn443-web-test-" + strings.ToLower(random()[:12])
	// Only the ephemeral runner's Keycloak and synthetic API listen on loopback.
	args := []string{"run", "-d", "--pull=never", "--name", name, "--network", "host", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
		"--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--health-interval", "1s", "--health-timeout", "5s", "--mount", "type=bind,source=" + mount + ",target=/run/syn443/web,readonly", image}
	if err = exec.CommandContext(t.Context(), "docker", args...).Run(); err != nil {
		t.Fatal("could not start web image")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, "docker", "rm", "-f", name).Run() != nil {
			t.Error("could not remove the web test container")
		}
	})
	if !t.Run("packaged_web_readiness_and_embedded_assets", func(t *testing.T) {
		deadline := time.Now().Add(20 * time.Second)
		for {
			raw, err := exec.CommandContext(t.Context(), "docker", "inspect", "--format", "{{.State.Health.Status}}", name).Output()
			if err != nil {
				t.Fatal("web image inspection failed")
			}
			if strings.TrimSpace(string(raw)) == "healthy" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("web image health check did not pass")
			}
			time.Sleep(200 * time.Millisecond)
		}
		client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		paths := map[string]string{"/": "text/html", "/app.js": "text/javascript"}
		if c.ControlConsole {
			paths = map[string]string{"/": "text/html", "/ui/console.js": "text/javascript", "/ui/console.css": "text/css"}
		}
		for path, mime := range paths {
			res, err := client.Get(c.Origin + path)
			if err != nil {
				t.Fatal("web asset missing", path)
			}
			prefix, readErr := io.ReadAll(io.LimitReader(res.Body, 1024))
			res.Body.Close()
			if readErr != nil || res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), mime) || len(prefix) < 64 {
				t.Fatal("invalid embedded web asset", path)
			}
			if path == "/" && c.ControlConsole && !strings.Contains(string(prefix), "console-root") {
				t.Fatal("incorrect console entrypoint")
			}
			if res.Header.Get("Set-Cookie") != "" || res.Header.Get("Content-Security-Policy") == "" {
				t.Fatal("unexpected asset session or policy")
			}
		}
		req, err := http.NewRequest(http.MethodPost, c.Origin+"/session", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", c.Origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Syn443-CSRF", "1")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("session check unavailable")
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatal("private session available before login")
		}
	}) {
		t.FailNow()
	}
}
