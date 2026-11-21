//go:build postgres

package enrollment

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func startTelemetryImage(t *testing.T, image, config, database string) func() {
	t.Helper()
	files := t.TempDir()
	if err := os.Chmod(files, 0755); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"config.json": config, "database": database} {
		err := exec.CommandContext(t.Context(), "sudo", "-n", "install", "-m", "0400", "-o", "65532", "-g", "65532", "--", source, filepath.Join(files, name)).Run()
		if err != nil {
			t.Fatal("could not assign an owner-readable synthetic file", name)
		}
	}
	name := "syn443-ingest-test-" + random()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := exec.CommandContext(ctx, "docker", "rm", "-f", name).Run(); err != nil {
				t.Error("could not remove the isolated telemetry fixture")
			}
		})
	}
	// The disposable SQL fixture and its test client both listen on runner loopback.
	cmd := exec.CommandContext(t.Context(), "docker", "run", "-d", "--pull=never", "--name", name, "--network", "host",
		"--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64",
		"--health-interval", "1s", "--health-timeout", "5s", "--mount", "type=bind,source="+files+",target=/run/syn443/telemetry,readonly", image)
	if err := cmd.Run(); err != nil {
		t.Fatal("could not start the packaged telemetry listener")
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(t.Context(), "docker", "inspect", "--format", "{{.State.Health.Status}}", name).Output()
		if err != nil {
			t.Fatal("could not inspect the disposable container")
		}
		if strings.TrimSpace(string(out)) == "healthy" {
			return stop
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("packaged telemetry listener did not pass its own health check")
	return stop
}
