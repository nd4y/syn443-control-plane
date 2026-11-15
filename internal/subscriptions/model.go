// Package subscriptions treats provider payloads as untrusted profile sources.
package subscriptions

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

const MaxBytes = 10 * 1024 * 1024
const MaxProfiles = 5000

var ErrInvalid = errors.New("subscription_invalid")
var ErrUnsupported = errors.New("subscription_unsupported")
var ErrAmbiguous = errors.New("subscription_ambiguous")
var sourceID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)

// Outbound is protected configuration, never ordinary inventory or log output.
type Profile struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Outbound json.RawMessage `json:"-"`
}

func (Profile) String() string   { return "SubscriptionProfile([redacted])" }
func (Profile) GoString() string { return "SubscriptionProfile([redacted])" }

// A source-private salt prevents public IDs becoming a password guessing oracle.
// Names, order and imported tags do not participate in identity. Changing the
// actual credentials produces a new candidate identity, checked by quarantine.
func profileID(source string, salt []byte, canonical []byte) (string, error) {
	if !sourceID.MatchString(source) || len(salt) != 32 {
		return "", ErrInvalid
	}
	h := hmac.New(sha256.New, salt)
	h.Write([]byte(source))
	h.Write([]byte{0})
	h.Write(canonical)
	return source + "_" + hex.EncodeToString(h.Sum(nil)[:16]), nil
}
