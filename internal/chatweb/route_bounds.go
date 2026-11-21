package chatweb

import (
	"errors"
	"net/http"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/routegraph"
)

type groupBound struct {
	Group      string `json:"group"`
	Intent     string `json:"intent"`
	UpperBound int    `json:"upperBound"`
	MaxHops    int    `json:"maxHops"`
}

const routeBoundsLimit = configuration.MaxAdaptivePlanBytes

// Count just the submitted declarations. This endpoint never reads a device,
// provider or saved draft and cannot issue or publish a configuration.
func previewRouteBounds(w http.ResponseWriter, raw []byte) {
	var plan configuration.AdaptivePlan
	if len(raw) > configuration.MaxAdaptivePlanBytes || identity.DecodeConfiguration(raw, &plan) != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	snapshot, err := configuration.InspectAdaptivePlan(plan, configuration.Graph{})
	if errors.Is(err, routegraph.ErrCandidateLimit) {
		reply(w, map[string]any{"status": "over_limit", "limit": routegraph.MaxCandidatesPerIntent})
		return
	}
	if err != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	graph := snapshot.Graph()
	groups := make([]groupBound, 0, len(plan.Groups))
	intents := make(map[string]int)
	for _, id := range graph.GroupIDs() {
		info, _ := graph.GroupInfo(id)
		groups = append(groups, groupBound{Group: id, Intent: info.Intent, UpperBound: info.UpperBound, MaxHops: info.MaxHops})
		intents[info.Intent], _ = graph.IntentUpperBound(info.Intent)
	}
	reply(w, map[string]any{"status": "ready", "limit": routegraph.MaxCandidatesPerIntent, "groups": groups, "intents": intents})
}
