//go:build capacity

package configuration

import (
	"context"
	"os"
	"testing"
)

// Only the separate disposable load job consumes this public synthetic engine.
func TestExportCapacityEngineFrom500CompiledProfiles(t *testing.T) {
	plan, profiles := adaptiveCompilerFixture(t, 500, "NON_RU")
	result, err := CompileNetworkPlan(context.Background(), plan, adaptiveCompilerResolver(profiles))
	if err != nil {
		t.Fatal(err)
	}
	_, _, catalogue := adaptiveCompilerOutput(t, result)
	if len(catalogue) != 500 || ValidateAdaptiveIssuedEngine(result.EngineConfig) != nil {
		t.Fatal("incomplete capacity catalogue")
	}
	f, err := os.OpenFile(os.Getenv("SYN443_CAPACITY_ENGINE"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(result.EngineConfig); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
