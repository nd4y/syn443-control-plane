package chatweb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/decision"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const routeReplayLimit = 256 * 1024

type replayInput struct {
	Source   string          `json:"source"`
	TrialTTL int64           `json:"trialTtlMs"`
	Frames   json.RawMessage `json:"frames,omitempty"`
}

type replayReport struct {
	Frames  int `json:"frames"`
	Same    int `json:"samePath"`
	Changed int `json:"changedPath"`
	Lost    int `json:"lostPath"`
	Gained  int `json:"gainedPath"`
	Neither int `json:"neither"`
}

var referenceFrames = sync.OnceValues(func() ([]json.RawMessage, error) {
	raw, err := contracts.Files.ReadFile("v1/decision-vectors.json")
	if err != nil {
		return nil, err
	}
	var suite struct {
		Cases []struct{ Input json.RawMessage }
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		return nil, err
	}
	frames := make([]json.RawMessage, 0, len(suite.Cases))
	for _, c := range suite.Cases {
		frames = append(frames, c.Input)
	}
	return frames, nil
})

func replayRouteDecisions(ctx context.Context, frames []json.RawMessage, ttl int64) (replayReport, error) {
	var report replayReport
	if ttl < 1 || ttl > 600_000 || len(frames) < 1 || len(frames) > 64 {
		return report, errors.New("invalid replay")
	}
	for _, raw := range frames {
		if err := ctx.Err(); err != nil {
			return replayReport{}, err
		}
		request, err := decision.DecodeRequest(raw)
		if err != nil || len(request.Candidates) > 64 {
			return replayReport{}, errors.New("invalid frame")
		}
		baseline, err := decision.Select(request)
		if err != nil {
			return replayReport{}, err
		}
		request.EvidenceTtlMs = ttl
		trial, err := decision.Select(request)
		if err != nil {
			return replayReport{}, err
		}
		a, b := baseline.SelectedPathID, trial.SelectedPathID
		switch {
		case a == nil && b == nil:
			report.Neither++
		case a == nil:
			report.Gained++
		case b == nil:
			report.Lost++
		case *a != *b:
			report.Changed++
		default:
			report.Same++
		}
		report.Frames++
	}
	return report, nil
}

// A replay consumes aggregate evidence only. No session token, network
// executor, catalog, signer or storage handle is passed to the decision engine.
func previewRouteReplay(ctx context.Context, w http.ResponseWriter, raw []byte) {
	var input replayInput
	if identity.DecodeConfiguration(raw, &input) != nil {
		fail(w, 400)
		return
	}
	var frames []json.RawMessage
	switch input.Source {
	case "reference":
		if input.Frames != nil {
			fail(w, 400)
			return
		}
		var err error
		frames, err = referenceFrames()
		if err != nil {
			fail(w, 500)
			return
		}
	case "trace":
		if json.Unmarshal(input.Frames, &frames) != nil {
			fail(w, 400)
			return
		}
	default:
		fail(w, 400)
		return
	}
	report, err := replayRouteDecisions(ctx, frames, input.TrialTTL)
	if err != nil {
		fail(w, 400)
		return
	}
	reply(w, report)
}
