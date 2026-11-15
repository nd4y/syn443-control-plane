// Package overlay defines the identity boundary. It has no SDK, enrollment,
// network, credential delivery or publication authority.
package overlay

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/policy"
)

var ErrInvalid = errors.New("overlay_identity_invalid")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var deviceID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
var ownerTag = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Address is derived from authenticated installation/account/device state and
// a signed assignment. NetworkID is a provider tenant/network, not Wi-Fi/LTE,
// an individual peer or a group whose membership may change independently.
type Address struct {
	ServiceID     string `json:"serviceId"`
	OwnerTag      string `json:"ownerTag"`
	DeviceID      string `json:"deviceId"`
	OverlayID     string `json:"overlayId"`
	Provider      string `json:"provider"`
	ResourceID    string `json:"resourceId"`
	NetworkID     string `json:"networkId"`
	IdentityEpoch int64  `json:"identityEpoch"`
	ManagementURL string `json:"managementURL"`
}

func (Address) String() string   { return "OverlayAddress([redacted])" }
func (Address) GoString() string { return "OverlayAddress([redacted])" }
func ManagementOrigin(raw string) (string, error) {
	if len(raw) < 1 || len(raw) > 2048 {
		return "", ErrInvalid
	}
	for _, r := range raw {
		if r < 33 || r > 126 {
			return "", ErrInvalid
		}
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.RawPath != "" || u.Path != "" && u.Path != "/" || strings.HasSuffix(u.Host, ":") {
		return "", ErrInvalid
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, "%") {
		return "", ErrInvalid
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", ErrInvalid
		}
		if n == 443 {
			port = ""
		} else {
			port = strconv.Itoa(n)
		}
	}
	if port != "" {
		host += ":" + port
	}
	return "https://" + host, nil
}

// Namespace never incorporates route tags, config revision, direct/VLESS mode,
// transient setup-key reference, root-key rotation or physical network epochs.
// The distinct root can never alias a legacy operator netbird/ directory.
func Namespace(a Address) (string, error) {
	for _, id := range []string{a.ServiceID, a.OverlayID, a.ResourceID, a.NetworkID} {
		if !identifier.MatchString(id) {
			return "", ErrInvalid
		}
	}
	if !deviceID.MatchString(a.DeviceID) || !ownerTag.MatchString(a.OwnerTag) || a.Provider != "netbird" || a.IdentityEpoch < 1 || a.IdentityEpoch > 9007199254740991 {
		return "", ErrInvalid
	}
	key, e := base64.RawURLEncoding.Strict().DecodeString(a.OwnerTag)
	if e != nil || len(key) != 32 {
		return "", ErrInvalid
	}
	origin, e := ManagementOrigin(a.ManagementURL)
	if e != nil {
		return "", e
	}
	raw, e := json.Marshal(map[string]any{"audience": "syn443-overlay-identity-v1", "serviceId": a.ServiceID, "ownerTag": a.OwnerTag, "deviceId": a.DeviceID, "overlayId": a.OverlayID, "provider": a.Provider, "resourceId": a.ResourceID, "networkId": a.NetworkID, "identityEpoch": a.IdentityEpoch, "managementOrigin": origin})
	if e != nil {
		return "", ErrInvalid
	}
	raw, e = policy.Canonical(raw)
	if e != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(raw)
	return "managed-netbird/" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
