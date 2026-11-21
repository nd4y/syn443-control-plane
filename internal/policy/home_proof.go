package policy

import (
	"encoding/base64"
	"net/netip"
	"regexp"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const HomeWiFiProof = "network.home-proof.v1"

// HomeProof authorizes one certificate-authenticated TLS handshake on the
// selected Wi-Fi. The client connects to Address, with Hostname used for SNI
// and certificate validation. This contract grants no direct user traffic.
type HomeProof struct {
	Hostname   string `json:"hostname"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	SPKISHA256 string `json:"spkiSha256"`
}

func (HomeProof) String() string   { return "HomeProof([redacted])" }
func (HomeProof) GoString() string { return "HomeProof([redacted])" }

var homeDNSLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (p HomeProof) Valid() bool {
	addr, err := netip.ParseAddr(p.Address)
	if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.Is6() && strings.Contains(p.Address, ".") || !addr.IsPrivate() ||
		p.Port < 1 || p.Port > 65535 || len(p.Hostname) > 253 || strings.HasSuffix(p.Hostname, ".localhost") {
		return false
	}
	labels := strings.Split(p.Hostname, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !homeDNSLabel.MatchString(label) {
			return false
		}
	}
	if _, err = netip.ParseAddr(p.Hostname); err == nil {
		return false
	}
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" {
		return false
	}
	pin, err := base64.RawURLEncoding.Strict().DecodeString(p.SPKISHA256)
	return err == nil && len(pin) == 32 && base64.RawURLEncoding.EncodeToString(pin) == p.SPKISHA256
}

// ValidHomeProofJSON accepts only the closed physical Wi-Fi TLS check.
func ValidHomeProofJSON(raw []byte) bool {
	var value HomeProof
	return identity.DecodeConfiguration(raw, &value) == nil && value.Valid()
}
