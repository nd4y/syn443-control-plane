package main

import (
	"errors"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestTelemetryHourCommandsDispatchToTheirOwnHandler(t *testing.T) {
	want := time.Date(2024, time.February, 29, 16, 0, 0, 0, time.UTC)
	for _, name := range []string{"telemetry-aggregate", "telemetry-summary"} {
		t.Run(name, func(t *testing.T) {
			var called string
			var hour time.Time
			witness := errors.New("synthetic_handler_result")
			count := 0
			handler := func(command string) func(time.Time) error {
				return func(value time.Time) error {
					count++
					called, hour = command, value
					return witness
				}
			}
			err := runArguments([]string{name, "2024-02-29T16:00Z"},
				handler("telemetry-aggregate"), handler("telemetry-summary"))
			if !errors.Is(err, witness) || count != 1 || called != name || hour != want {
				t.Fatal("valid hour did not reach its dedicated handler exactly once")
			}
		})
	}
}

func TestTelemetryHourCommandsRejectNoncanonicalArityAndHoursBeforeIO(t *testing.T) {
	blocked := func(time.Time) error {
		t.Fatal("invalid arguments reached a telemetry handler")
		return nil
	}
	for _, command := range []string{"telemetry-aggregate", "telemetry-summary"} {
		for _, hours := range [][]string{
			nil,
			{"2024-02-29T16:00Z", "extra"},
			{"2023-02-29T16:00Z"},
			{"2024-02-29T16:00:00Z"},
			{"2024-02-29T16:01Z"},
			{"2024-02-29T16:00+00:00"},
			{"2024-02-29T16:00Z "},
		} {
			if err := runArguments(append([]string{command}, hours...), blocked, blocked); !errors.Is(err, identity.ErrInvalid) {
				t.Fatal("noncanonical hour or argument count was accepted")
			}
		}
	}
}

func TestTelemetryHourDispatchDoesNotWidenOtherOperatorCommands(t *testing.T) {
	blocked := func(time.Time) error {
		t.Fatal("non-hour command reached a telemetry handler")
		return nil
	}
	for _, args := range [][]string{
		nil, {"fingerprint-grants", "--config"}, {"bootstrap-profile", "extra"},
		{"telemetry-prune", "2024-02-29T16:00Z"}, {"configuration-migrate", "extra"},
		{"unknown-command", "2024-02-29T16:00Z"},
	} {
		if err := runArguments(args, blocked, blocked); !errors.Is(err, identity.ErrInvalid) {
			t.Fatal("legacy argument boundary changed")
		}
	}
}
