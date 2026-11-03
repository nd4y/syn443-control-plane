package chatweb

import (
	"encoding/json"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

// This BFF exposes only explicitly allowed control actions. It cannot
// turn a browser draft into publication authority, accept arbitrary upstream
// paths, or use a support-chat session to access the control audience.
func validConsoleAction(raw []byte) bool {
	var request struct {
		Version   int             `json:"version"`
		Action    string          `json:"action"`
		RequestID string          `json:"requestId"`
		Payload   json.RawMessage `json:"payload"`
	}
	if len(raw) > 278528 || identity.DecodeSourceUpload(raw, &request) != nil || request.Version != 1 || len(request.RequestID) < 16 || len(request.RequestID) > 128 || len(request.Payload) < 2 {
		return false
	}
	switch request.Action {
	case "source.list", "source.get", "source.snapshot", "source.shares.get", "source.put", "source.sync", "job.get", "resource.get", "configuration.draft.get", "configuration.draft.put", "configuration.preview.request", "configuration.publish", "configuration.request.get", "configuration.inventory.get":
		return true
	}
	return false
}
