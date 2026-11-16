package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type loopWorker struct {
	now  func(context.Context, time.Time) (time.Time, error)
	step func(context.Context, time.Time) error
}

func (w loopWorker) Now(ctx context.Context, wall time.Time) (time.Time, error) {
	return w.now(ctx, wall)
}
func (w loopWorker) RunOnce(ctx context.Context, now time.Time) error { return w.step(ctx, now) }

func TestConfigurationWorkerLoopUsesOnlyBoundedDatabaseClockAndSerialTicks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	var sequence []string
	stepContexts := make([]context.Context, 0, 2)
	now := time.Unix(1_800_000_001, 0).UTC()
	worker := loopWorker{
		now: func(step context.Context, wall time.Time) (time.Time, error) {
			deadline, ok := step.Deadline()
			if !ok || !deadline.After(wall) || deadline.After(wall.Add(20*time.Second+time.Millisecond)) {
				t.Fatal("database clock lacks the production step budget")
			}
			stepContexts = append(stepContexts, step)
			sequence = append(sequence, "db-now")
			return now, nil
		},
		step: func(step context.Context, accepted time.Time) error {
			if accepted != now || step != stepContexts[len(stepContexts)-1] || step.Err() != nil {
				t.Fatal("publication did not consume the same bounded DB clock context")
			}
			sequence = append(sequence, "run-once")
			return nil
		},
	}
	waits := 0
	if e := runLoop(ctx, worker, &output, func(context.Context) bool {
		if stepContexts[len(stepContexts)-1].Err() == nil {
			t.Fatal("tick retained its context while idle")
		}
		sequence = append(sequence, "wait")
		waits++
		return waits < 2
	}); e != nil {
		t.Fatal(e)
	}
	if strings.Join(sequence, ",") != "db-now,run-once,wait,db-now,run-once,wait" || output.Len() != 0 {
		t.Fatal("worker overlapped, queued catch-up or ignored the DB clock")
	}
}

func TestConfigurationWorkerClockAndPublicationFailuresStayFiniteAndNeverFallBack(t *testing.T) {
	for _, failure := range []string{"clock", "zero-clock", "publication"} {
		t.Run(failure, func(t *testing.T) {
			var output bytes.Buffer
			calls := 0
			raw := errors.New("synthetic-private-dsn-or-provider-material")
			worker := loopWorker{
				now: func(context.Context, time.Time) (time.Time, error) {
					if failure == "clock" {
						return time.Time{}, raw
					}
					if failure == "zero-clock" {
						return time.Time{}, nil
					}
					return time.Unix(1_800_000_001, 0), nil
				},
				step: func(context.Context, time.Time) error { calls++; return raw },
			}
			if e := runLoop(context.Background(), worker, &output, func(context.Context) bool { return false }); e != nil {
				t.Fatal(e)
			}
			expected := 0
			if failure == "publication" {
				expected = 1
			}
			if calls != expected || output.String() != "configuration_step_unavailable\n" {
				t.Fatal("failed clock gained a publication or a private error escaped")
			}
		})
	}
}

func TestConfigurationWorkerLoopCancellationJoinsActualStepAndWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	started := make(chan struct{})
	left := make(chan struct{})
	done := make(chan error, 1)
	worker := loopWorker{
		now: func(context.Context, time.Time) (time.Time, error) { return time.Unix(1_800_000_001, 0), nil },
		step: func(step context.Context, _ time.Time) error {
			close(started)
			<-step.Done()
			close(left)
			return step.Err()
		},
	}
	go func() { done <- runLoop(ctx, worker, &output, waitTick) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("step did not start")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
		select {
		case <-left:
		default:
			t.Fatal("worker released ownership before actual step exit")
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not reach the active step")
	}
	if output.Len() != 0 {
		t.Fatal("ordinary shutdown emitted a failure")
	}
	if waitTick(ctx) {
		t.Fatal("cancelled idle wait retained a timer")
	}
}

func TestConfigurationWorkerCLIReadsNoEnrollmentOrFallbackInputs(t *testing.T) {
	var output bytes.Buffer
	var names []string
	getenv := func(name string) string { names = append(names, name); return "synthetic-missing-private-path" }
	if e := run(context.Background(), getenv, &output); e != errWorkerFailed {
		t.Fatal("missing runtime returned a private error")
	}
	if len(names) != 1 || names[0] != "SYN443_CONFIGURATION_WORKER_CONFIG" || output.Len() != 0 {
		t.Fatal("worker consulted enrollment or fallback material")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	names = nil
	if e := run(ctx, getenv, &output); e != errWorkerFailed || len(names) != 0 {
		t.Fatal("cancelled startup read runtime files")
	}
}
