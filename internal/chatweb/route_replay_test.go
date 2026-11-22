package chatweb

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/decision"
)

func TestRouteReplayComparesIdenticalEvidenceAndCountsAllOutcomes(t *testing.T) {
	reference, err := referenceFrames()
	if err != nil {
		t.Fatal(err)
	}
	original, err := decision.DecodeRequest(reference[0])
	if err != nil {
		t.Fatal(err)
	}
	// Larger age means older evidence. The first candidate ranks ahead when both qualify.
	frame := func(baseline int64, ages ...int64) json.RawMessage {
		r := original
		r.NowMs = 10000
		r.EvidenceTtlMs = baseline
		r.Candidates = append([]decision.Candidate(nil), original.Candidates[:len(ages)]...)
		for i, age := range ages {
			r.Candidates[i].ObservedAtMs = r.NowMs - age
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	frames := []json.RawMessage{frame(1000, 10), frame(1000, 600, 20), frame(1000, 500), frame(100, 200), frame(100, 999)}
	before, _ := json.Marshal(frames)
	got, err := replayRouteDecisions(context.Background(), frames, 500, false)
	if err != nil || got.ByIntent != nil || got.replayTotals != (replayTotals{Frames: 5, Same: 1, Changed: 1, Lost: 1, Gained: 1, Neither: 1}) {
		t.Fatal(got, err)
	}
	after, _ := json.Marshal(frames)
	if string(before) != string(after) {
		t.Fatal("replay modified source observations")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = replayRouteDecisions(ctx, frames, 500, true); err == nil {
		t.Fatal("cancelled replay completed")
	}
}

func TestRouteReplayIsScopedReadOnlyAndRejectsMalformedOrOversizedTraces(t *testing.T) {
	s, _, p := webFixture(t)
	const endpoint = "/control/route-replay"
	const reference = `{"source":"reference","trialTtlMs":60000}`
	chat := loginWeb(t, s)
	if w := webCall(s, endpoint, reference, chat); w.Code != 404 {
		t.Fatal(w.Code)
	}
	s.config.ControlConsole = true
	p.Scope = "syn443.control"
	cookie := loginWeb(t, s)
	s.client.Transport = consoleTransportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("replay forwarded a request"); return nil, nil })
	if w := webCall(s, endpoint, reference, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	raw := webCall(s, endpoint, reference, cookie)
	var report replayReport
	if raw.Code != 200 || json.Unmarshal(raw.Body.Bytes(), &report) != nil || report.Frames != 30 {
		t.Fatal(raw.Code, report)
	}
	var projection map[string]int
	if json.Unmarshal(raw.Body.Bytes(), &projection) != nil || len(projection) != 6 {
		t.Fatal("unexpected result fields")
	}
	for _, bad := range []string{
		`{"source":"trace","trialTtlMs":1000,"frames":[]}`, `{"source":"trace","trialTtlMs":1000,"frames":null}`,
		`{"source":"reference","trialTtlMs":600001}`, `{"source":"reference","trialTtlMs":100,"frames":[]}`,
		`{"source":"reference","trialTtlMs":0}`, `{"source":"reference","trialTtlMs":60000,"trialTtlMs":1}`,
		`{"source":"trace","trialTtlMs":100,"frames":[{"url":"https://synthetic.invalid/"}]}`,
		`{"source":"trace","trialTtlMs":100,"frames":[` + strings.Repeat("{},", 64) + "{}]}",
	} {
		if w := webCall(s, endpoint, bad, cookie); w.Code != 400 {
			t.Fatal("malformed trace accepted", w.Code)
		}
	}
	if w := webCall(s, endpoint, strings.Repeat("x", routeReplayLimit+1), cookie); w.Code != 413 {
		t.Fatal(w.Code)
	}
	s.sessions[cookie.Value].principal.Scope = "openid"
	if w := webCall(s, endpoint, reference, cookie); w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestRouteReplayAttributesOutcomesAndTrialRejectionsToMeasuredTrafficClasses(t *testing.T) {
	reference, err := referenceFrames()
	if err != nil {
		t.Fatal(err)
	}
	base, err := decision.DecodeRequest(reference[0])
	if err != nil {
		t.Fatal(err)
	}
	frame := func(intent string, ages ...int64) json.RawMessage {
		r := base
		r.Intent, r.NowMs, r.EvidenceTtlMs = intent, 10000, 1000
		r.Candidates = make([]decision.Candidate, 0, len(ages))
		for i, age := range ages {
			c := base.Candidates[i]
			c.ExitClass, c.ObservedAtMs = intent, r.NowMs-age
			r.Candidates = append(r.Candidates, c)
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	frames := []json.RawMessage{frame("RU", 500, 800), frame("NON_RU", 10), frame("INTERNAL")}
	report, err := replayRouteDecisions(context.Background(), frames, 500, true)
	if err != nil || report.Frames != 3 || len(report.ByIntent) != 3 {
		t.Fatal(report, err)
	}
	ru, nonRU, internal := report.ByIntent["RU"], report.ByIntent["NON_RU"], report.ByIntent["INTERNAL"]
	if ru.Lost != 1 || ru.Frames != 1 || len(ru.TrialRejected) != 1 || ru.TrialRejected["stale_evidence"] != 2 ||
		nonRU.Same != 1 || len(nonRU.TrialRejected) != 0 || internal.Neither != 1 || len(internal.TrialRejected) != 0 {
		t.Fatal("rejections must count candidates, outcomes must count frames", report)
	}
	s, _, p := webFixture(t)
	s.config.ControlConsole = true
	p.Scope = "syn443.control"
	cookie := loginWeb(t, s)
	frameBytes, err := json.Marshal(frames)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(replayInput{Source: "trace", TrialTTL: 500, IncludeClasses: true, Frames: frameBytes})
	if err != nil {
		t.Fatal(err)
	}
	w := webCall(s, "/control/route-replay", string(input), cookie)
	var after replayReport
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &after) != nil || after.ByIntent["RU"] == nil || after.ByIntent["RU"].TrialRejected["stale_evidence"] != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, private := range []string{base.Candidates[0].ID, base.Context.DependencyHash, base.MetricGroup} {
		if strings.Contains(w.Body.String(), "\""+private+"\"") {
			t.Fatal("private observation escaped replay")
		}
	}
}
