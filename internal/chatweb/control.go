package chatweb

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const consoleActionLimit = 278528
const consoleImportLimit = 14*1024*1024 + 65536

// This BFF exposes only explicitly allowed control actions. It cannot
// turn a browser draft into publication authority, accept arbitrary upstream
// paths, or use a support-chat session to access the control audience.
func validConsoleAction(raw []byte, sourceImport bool) bool {
	var request struct {
		Version   int             `json:"version"`
		Action    string          `json:"action"`
		RequestID string          `json:"requestId"`
		Payload   json.RawMessage `json:"payload"`
	}
	limit := consoleActionLimit
	if sourceImport {
		limit = consoleImportLimit
	}
	if len(raw) > limit || identity.DecodeSourceUpload(raw, &request) != nil || request.Version != 1 || len(request.RequestID) < 16 || len(request.RequestID) > 128 || len(request.Payload) < 2 {
		return false
	}
	if sourceImport {
		return request.Action == "source.import"
	}
	switch request.Action {
	case "source.review":
		return len(raw) <= 2048 && validSourceReview(request.Payload)
	case "resource.put":
		return len(raw) <= 4096 && validResourceEdit(request.Payload)
	case "invite.issue", "invite.get", "invite.approve", "invite.revoke":
		return len(raw) <= 8192
	case "telemetry.summary.get":
		return true
	case "source.list", "source.get", "source.snapshot", "source.shares.get", "source.shares.put", "source.put", "source.sync", "job.get", "job.list", "resource.get", "configuration.draft.get", "configuration.draft.put", "configuration.preview.request", "configuration.publish", "configuration.request.get", "configuration.inventory.get", "configuration.devices.list", "configuration.runtime.get", "configuration.layers.draft.get", "configuration.layers.draft.put", "configuration.layers.drafts.list", "configuration.layers.draft.discard", "configuration.history.get":
		return true
	}
	return false
}

var resourceEditID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)
var snapshotReviewID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func validSourceReview(raw json.RawMessage) bool {
	var body struct {
		SourceID       string  `json:"sourceId"`
		SourceRevision int64   `json:"sourceRevision"`
		Candidate      string  `json:"candidate"`
		Hash           string  `json:"hash"`
		Active         *string `json:"active"`
		Approve        *bool   `json:"approve"`
	}
	if identity.Decode(raw, &body, true) != nil || body.Active == nil || body.Approve == nil {
		return false
	}
	digest, err := base64.RawURLEncoding.Strict().DecodeString(body.Hash)
	return err == nil && len(digest) == 32 && base64.RawURLEncoding.EncodeToString(digest) == body.Hash &&
		resourceEditID.MatchString(body.SourceID) && snapshotReviewID.MatchString(body.Candidate) &&
		(*body.Active == "" || snapshotReviewID.MatchString(*body.Active)) && *body.Active != body.Candidate &&
		body.SourceRevision > 0 && body.SourceRevision <= 9007199254740991
}

// The browser can change an existing resource's metadata. Credentials and
// provider construction remain behind the catalog's separate operator path.
func validResourceEdit(raw json.RawMessage) bool {
	var body struct {
		Resource struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			ProviderType string `json:"providerType"`
			APIVersion   string `json:"apiVersion"`
			Enabled      *bool  `json:"enabled"`
			Revision     int64  `json:"revision"`
		} `json:"resource"`
		Secret struct {
			Operation string `json:"operation"`
		} `json:"secret"`
		ImpactHash string `json:"impactHash"`
	}
	if identity.Decode(raw, &body, true) != nil {
		return false
	}
	r := body.Resource
	hash, err := base64.RawURLEncoding.Strict().DecodeString(body.ImpactHash)
	return err == nil && len(hash) == 32 && base64.RawURLEncoding.EncodeToString(hash) == body.ImpactHash &&
		body.Secret.Operation == "keep" && resourceEditID.MatchString(r.ID) &&
		r.ProviderType == "panel.remnawave" && r.APIVersion == "3.4" && r.Enabled != nil &&
		r.Revision > 0 && r.Revision < 9007199254740991 && strings.TrimSpace(r.Name) != "" && len(r.Name) <= 256
}
