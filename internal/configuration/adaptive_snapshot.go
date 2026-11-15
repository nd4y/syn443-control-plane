package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"

	"github.com/nd4y/syn443-control-plane/internal/routegraph"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

var adaptiveHopID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var adaptiveSourceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)

// AdaptiveSnapshot owns the exact graph/profile binding for one independently
// authorized source resolution. It is neither publication nor probe authority.
// No accepted policy schema or device capability exposes this primitive yet.
type AdaptiveSnapshot struct {
	graph    *routegraph.Graph
	profiles map[string]subscriptions.Profile
	hash     string
}

func (*AdaptiveSnapshot) String() string        { return "AdaptiveSnapshot([redacted])" }
func (s *AdaptiveSnapshot) GoString() string    { return s.String() }
func (s *AdaptiveSnapshot) ContentHash() string { return s.hash }

// Profile returns an owned normalized copy with only the local hop identifier.
// Source/profile identifiers and display names never become device metadata.
func (s *AdaptiveSnapshot) Profile(hop string) (subscriptions.Profile, error) {
	profile, ok := s.profiles[hop]
	if !ok {
		return subscriptions.Profile{}, ErrInvalid
	}
	profile.Outbound = append(json.RawMessage(nil), profile.Outbound...)
	return profile, nil
}

// DeclaredPath is only graph eligibility, not actual transport/exit evidence.
// Protocol transitions, runtime lease and fresh native proof remain mandatory.
func (s *AdaptiveSnapshot) DeclaredPath(group, mode string, path []string) bool {
	return s.graph.Allows(group, mode, path)
}

// CompileAdaptiveSnapshot performs no network/SQL/signing action. resolve must
// read an independently authorized immutable selection, never a caller URL.
// The eventual publisher must still recheck grant/source/recipient SQL fences.
// The bound includes metadata, normalized credentials and private references;
// the full snapshot is protected configuration and is never an inventory DTO.
func CompileAdaptiveSnapshot(ctx context.Context, metadata []byte, bindings map[string]ProfileReference, resolve func(ProfileReference) (subscriptions.Profile, error)) (*AdaptiveSnapshot, error) {
	if ctx == nil || resolve == nil || len(bindings) < 1 || len(bindings) > 500 || len(metadata) < 1 || len(metadata) > 262144 {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	ownedMetadata := append([]byte(nil), metadata...)
	ownedRefs := make(map[string]ProfileReference, len(bindings))
	ids := make([]string, 0, len(bindings))
	seenRefs := map[ProfileReference]bool{}
	for hop, ref := range bindings {
		if !adaptiveHopID.MatchString(hop) || !adaptiveSourceID.MatchString(ref.SourceID) || !graphProfileID.MatchString(ref.ProfileID) || seenRefs[ref] {
			return nil, ErrInvalid
		}
		ownedRefs[hop] = ref
		ids = append(ids, hop)
		seenRefs[ref] = true
	}
	sort.Strings(ids)
	graph, e := routegraph.Decode(ownedMetadata, ids)
	if e != nil {
		return nil, ErrInvalid
	}
	type binding struct {
		Hop      string           `json:"hop"`
		Ref      ProfileReference `json:"ref"`
		Outbound json.RawMessage  `json:"outbound"`
	}
	rows := make([]binding, 0, len(ids))
	profiles := make(map[string]subscriptions.Profile, len(ids))
	seenNodes := map[[32]byte]bool{}
	used := len(ownedMetadata)
	for _, hop := range ids {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		ref := ownedRefs[hop]
		profile, err := resolve(ref)
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if err != nil || profile.ID != ref.ProfileID || len(profile.Outbound) < 1 || len(profile.Outbound) > 65536 {
			return nil, ErrInvalid
		}
		// Decode into owned maps before consulting any subsequent source. A
		// resolver retaining/reusing its buffers cannot alter earlier entries.
		value, err := subscriptions.DecodeJSON(profile.Outbound)
		node, ok := value.(map[string]any)
		if err != nil || !ok || node["tag"] != ref.ProfileID || node["type"] != profile.Kind || subscriptions.ValidateOutbound(node) != nil {
			return nil, ErrInvalid
		}
		delete(node, "tag")
		canonical, err := json.Marshal(node)
		if err != nil {
			return nil, ErrInvalid
		}
		fingerprint := sha256.Sum256(canonical)
		// Repeated imported copies are not different graph hops. Otherwise
		// aliases could circumvent cycle/repeated-hop rejection.
		if seenNodes[fingerprint] {
			return nil, ErrInvalid
		}
		seenNodes[fingerprint] = true
		node["tag"] = hop
		normalized, err := json.Marshal(node)
		if err != nil {
			return nil, ErrInvalid
		}
		used += len(normalized) + len(hop) + len(ref.SourceID) + len(ref.ProfileID)
		if used > 262144 {
			return nil, ErrInvalid
		}
		profiles[hop] = subscriptions.Profile{ID: hop, Kind: profile.Kind, Outbound: normalized}
		rows = append(rows, binding{hop, ref, normalized})
	}
	bound, err := json.Marshal(struct {
		Graph    json.RawMessage `json:"graph"`
		Profiles []binding       `json:"profiles"`
	}{ownedMetadata, rows})
	if err != nil || len(bound) > 262144 {
		return nil, ErrInvalid
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	digest := sha256.Sum256(bound)
	return &AdaptiveSnapshot{graph: graph, profiles: profiles, hash: hex.EncodeToString(digest[:])}, nil
}
