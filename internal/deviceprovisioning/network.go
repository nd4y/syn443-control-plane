package deviceprovisioning

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

// ApprovedNetworkLayers is returned by the independent approval reader, never
// by a device request or a control-API "ready" flag. Its fence must bind the
// immutable layer revisions, assignments and actual recipient authorization.
// A private saved draft is deliberately not an implementation of this reader.
type ApprovedNetworkLayers struct {
	Target  enrollment.ConfigurationTarget
	Layers  []configuration.Layer
	Mode    string
	UntilMs int64
	Fence   enrollment.ApprovalFence
}

func (ApprovedNetworkLayers) String() string   { return "ApprovedNetworkLayers([redacted])" }
func (ApprovedNetworkLayers) GoString() string { return "ApprovedNetworkLayers([redacted])" }

type NetworkLayerAuthority interface {
	PrepareLayers(context.Context, enrollment.ConfigurationTarget, time.Time) (*ApprovedNetworkLayers, error)
}

// NetworkAuthority joins approved portable layers to currently authorized,
// immutable subscription snapshots. Only the publisher owns this composition;
// source workers cannot sign, and the API cannot supply raw native output.
type NetworkAuthority struct {
	Layers  NetworkLayerAuthority
	Sources *catalog.Store
}

func (a *NetworkAuthority) Prepare(ctx context.Context, target enrollment.ConfigurationTarget, now time.Time) (*enrollment.PreparedConfiguration, error) {
	if ctx == nil || a == nil || a.Layers == nil || a.Sources == nil || target.Device == "" || target.Owner == "" || target.Thumbprint == "" || target.GrantHash == "" || target.CurrentRevision < 0 {
		return nil, enrollment.ErrDenied
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := a.Sources.PublicationRole(ctx); e != nil {
		return nil, e
	}
	// A provider cannot mutate the publisher's capability slice or substitute
	// an approval for a different key, device, account, grant or base revision.
	input := target
	input.Capabilities = append([]string(nil), target.Capabilities...)
	approved, e := a.Layers.PrepareLayers(ctx, input, now)
	if e != nil {
		return nil, e
	}
	if approved == nil || approved.Fence == nil || !sameNetworkTarget(target, approved.Target) || approved.UntilMs <= now.UnixMilli() || approved.UntilMs > now.Add(7*24*time.Hour).UnixMilli() || !networkMode(approved.Mode) {
		return nil, enrollment.ErrDenied
	}
	var plan configuration.NetworkPlan
	_, e = configuration.Merge(ctx, approved.Layers, func(raw json.RawMessage) error {
		var err error
		plan, err = configuration.DecodeNetworkPlan(raw)
		return err
	})
	if e != nil {
		return nil, e
	}
	// Duplicate graph aliases may address one immutable source profile. Sort
	// and deduplicate before SQL selection to keep lock acquisition stable.
	refs := []catalog.ProfileReference{}
	seen := map[catalog.ProfileReference]bool{}
	for _, ref := range plan.Graph.Profiles {
		value := catalog.ProfileReference{SourceID: ref.SourceID, ProfileID: ref.ProfileID}
		if !seen[value] {
			refs = append(refs, value)
			seen[value] = true
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].SourceID == refs[j].SourceID {
			return refs[i].ProfileID < refs[j].ProfileID
		}
		return refs[i].SourceID < refs[j].SourceID
	})
	until := approved.UntilMs
	var selection *catalog.PreparedSelection
	if len(refs) > 0 {
		selection, e = a.Sources.PrepareSelection(ctx, catalog.SelectionTarget{Owner: target.Owner, Device: target.Device}, refs, approved.Mode, until/1000, now)
		if e != nil {
			return nil, e
		}
		until = min(until, selection.ValidUntil()*1000)
	}
	compiled, e := configuration.CompileNetworkPlan(ctx, plan, func(ref configuration.ProfileReference) (subscriptions.Profile, error) {
		if selection != nil {
			if p, ok := selection.Profile(catalog.ProfileReference{SourceID: ref.SourceID, ProfileID: ref.ProfileID}); ok {
				return p, nil
			}
		}
		return subscriptions.Profile{}, enrollment.ErrDenied
	})
	if e != nil {
		return nil, e
	}
	return &enrollment.PreparedConfiguration{EngineConfig: compiled.EngineConfig, Activation: compiled.Activation,
		RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}, UntilMs: until,
		Fence: &networkFence{layers: approved.Fence, sources: selection, untilMs: until}}, nil
}

func sameNetworkTarget(a, b enrollment.ConfigurationTarget) bool {
	return a.Device == b.Device && a.Owner == b.Owner && a.Thumbprint == b.Thumbprint && a.GrantHash == b.GrantHash && a.CurrentRevision == b.CurrentRevision && slices.Equal(a.Capabilities, b.Capabilities)
}

func networkMode(mode string) bool {
	return mode == "home_wifi" || mode == "wifi" || mode == "cellular_restricted" || mode == "cellular"
}

type networkFence struct {
	layers  enrollment.ApprovalFence
	sources *catalog.PreparedSelection
	untilMs int64
}

func (f *networkFence) Lock(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if ctx == nil || tx == nil || f == nil || f.layers == nil || f.untilMs <= now.UnixMilli() {
		return enrollment.ErrDenied
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := f.layers.Lock(ctx, tx, now); e != nil {
		return e
	}
	if f.sources != nil {
		return f.sources.Lock(ctx, tx, now)
	}
	return nil
}
