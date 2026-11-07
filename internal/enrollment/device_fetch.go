package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const deviceFetchClaimPath = "/v1/device/sources/claim"
const deviceFetchResultPath = "/v1/device/sources/result"
const deviceFetchV2ClaimPath = "/v1/device/sources/v2/claim"
const deviceFetchV2ResultPath = "/v1/device/sources/v2/result"
const deviceFetchFrameSize = 88 // 43-byte job and lease identifiers, each followed by LF.

func (a *API) deviceFetch(ctx context.Context, binding Binding, token string, proof identity.Proof, raw []byte, upload, versioned bool, now time.Time) (catalog.DeviceFetchLease, error) {
	var job, lease string
	if upload {
		if len(raw) <= deviceFetchFrameSize || raw[43] != '\n' || raw[87] != '\n' ||
			!idPattern.Match(raw[:43]) || !idPattern.Match(raw[44:87]) || catalog.DeviceFetchPayloadIsVersioned(raw[deviceFetchFrameSize:]) != versioned {
			return catalog.DeviceFetchLease{}, identity.ErrInvalid
		}
		job, lease = string(raw[:43]), string(raw[44:87])
	}
	value, err := a.Store.WithDeviceSession(ctx, binding, token, proof, now, func(ctx context.Context, tx *sql.Tx, authority DeviceAuthority) (DeviceResult, error) {
		scope := catalog.DeviceFetchScope{Owner: authority.Binding.Owner, Device: authority.Binding.Device}
		deadline := min(authority.AccountUntilMs, authority.Binding.AccessUntil*1000, now.Add(time.Minute).UnixMilli())
		if upload {
			err := a.DeviceFetch.AcceptDeviceFetch(ctx, tx, scope, job, lease, raw[deviceFetchFrameSize:], now)
			return DeviceResult{Value: catalog.DeviceFetchLease{}, UntilMs: deadline}, err
		}
		var result catalog.DeviceFetchLease
		var err error
		if versioned {
			result, err = a.DeviceFetch.ClaimDeviceFetchWithValidators(ctx, tx, scope, now)
		} else {
			result, err = a.DeviceFetch.ClaimDeviceFetch(ctx, tx, scope, now)
		}
		if err != nil {
			return DeviceResult{}, err
		}
		if result.JobID != "" {
			encoded, err := json.Marshal(result)
			if err != nil || len(encoded) >= 65536 {
				return DeviceResult{}, catalog.ErrInvalid
			}
			clear(encoded)
			deadline = min(deadline, result.Until*1000)
		}
		return DeviceResult{Value: result, UntilMs: deadline}, nil
	})
	switch {
	case errors.Is(err, catalog.ErrDenied):
		err = ErrDenied
	case errors.Is(err, catalog.ErrStale), errors.Is(err, catalog.ErrConflict):
		err = ErrConflict
	case errors.Is(err, catalog.ErrInvalid):
		err = identity.ErrInvalid
	}
	if err != nil {
		return catalog.DeviceFetchLease{}, err
	}
	return value.(catalog.DeviceFetchLease), nil
}
