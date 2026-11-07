package configuration

import (
	"crypto/sha256"
	"encoding/binary"
	"regexp"
)

// ProbeCooldownRollout selects a stable subset of an already approved set.
// No rollout setting grants access or changes the contents of a proxy chain.
type ProbeCooldownRollout struct {
	ID          string `json:"id"`
	BasisPoints *int   `json:"basisPoints"`
}

var rolloutDevice = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
var rolloutID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)

func (r ProbeCooldownRollout) valid() bool {
	return rolloutID.MatchString(r.ID) && r.BasisPoints != nil &&
		*r.BasisPoints >= 0 && *r.BasisPoints <= 10000
}

// Includes uses the authenticated internal device ID, not an account/display
// name, and never depends on policy revision, request time or input ordering.
func (r ProbeCooldownRollout) Includes(device string) bool {
	if !r.valid() || !rolloutDevice.MatchString(device) {
		return false
	}
	sum := sha256.Sum256([]byte("syn443/route-reserve-cooldown/v1\x00" + r.ID + "\x00" + device))
	bucket := binary.BigEndian.Uint64(sum[:8]) % 10000
	return bucket < uint64(*r.BasisPoints)
}
