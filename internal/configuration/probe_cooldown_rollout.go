package configuration

import (
	"crypto/sha256"
	"encoding/binary"
	"regexp"
	"strconv"
)

// DeviceRollout selects a stable subset of an already approved set.
// No rollout setting grants access or changes the contents of a proxy chain.
type DeviceRollout struct {
	ID                 string              `json:"id"`
	BasisPoints        *int                `json:"basisPoints"`
	ControlBasisPoints rolloutControlShare `json:"controlBasisPoints,omitempty"`
}

type rolloutControlShare int

// An absent holdout preserves existing assignments. An explicit null or a
// malformed percentage must not silently remove an operator's holdout.
func (share *rolloutControlShare) UnmarshalJSON(raw []byte) error {
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 0 || n > 10000 {
		return ErrInvalid
	}
	*share = rolloutControlShare(n)
	return nil
}

var rolloutDevice = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
var rolloutID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)

func (r DeviceRollout) valid() bool {
	return rolloutID.MatchString(r.ID) && r.BasisPoints != nil &&
		*r.BasisPoints >= 0 && *r.BasisPoints <= 10000 &&
		r.ControlBasisPoints >= 0 && r.ControlBasisPoints <= 10000
}

func (r DeviceRollout) IncludesProbeCooldown(device string) bool {
	return r.includes("syn443/route-reserve-cooldown/v1", device)
}

func (r DeviceRollout) IncludesDecision(device string) bool {
	return r.includes("syn443/route-decision/v1", device)
}

// The cohort uses the authenticated device ID and stays independent of policy
// revision, request time, input order and the cohort of another feature.
func (r DeviceRollout) includes(domain, device string) bool {
	if !r.valid() || !rolloutDevice.MatchString(device) {
		return false
	}
	// Features sharing an experiment ID share its control group. The original
	// treatment buckets stay independent, even as treatment grows to 100%.
	if r.ControlBasisPoints > 0 && r.bucket("syn443/rollout-control/v1", device) < int(r.ControlBasisPoints) {
		return false
	}
	return r.bucket(domain, device) < *r.BasisPoints
}

func (r DeviceRollout) bucket(domain, device string) int {
	sum := sha256.Sum256([]byte(domain + "\x00" + r.ID + "\x00" + device))
	return int(binary.BigEndian.Uint64(sum[:8]) % 10000)
}
