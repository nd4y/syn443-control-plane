package bootstrap

import (
	"encoding/base64"
	"net/url"
	"strings"
	"time"
)

const MaxLink = 8192

type Invitation struct {
	ServiceID string `json:"serviceId"`
	Origin    string `json:"origin"`
	Code      string `json:"-"`
	Manifest  string `json:"-"`
}

func (Invitation) String() string   { return "BootstrapInvitation([redacted])" }
func (Invitation) GoString() string { return "BootstrapInvitation([redacted])" }

type AuthenticatedInvitation struct {
	Descriptor Descriptor `json:"descriptor"`
	Floor      Floor      `json:"floor"`
	Code       string     `json:"-"`
}

func (AuthenticatedInvitation) String() string   { return "AuthenticatedInvitation([redacted])" }
func (AuthenticatedInvitation) GoString() string { return "AuthenticatedInvitation([redacted])" }
func (i Invitation) validate() error {
	if !identifier.MatchString(i.ServiceID) || !secureURL(i.Origin, false) || !digestID.MatchString(i.Code) || len(i.Manifest) < 1 || len(i.Manifest) > MaxManifest {
		return ErrUntrusted
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(i.Code)
	if e != nil || len(raw) != 32 {
		return ErrUntrusted
	}
	return nil
}
func Link(invitation Invitation) (string, error) {
	if invitation.validate() != nil {
		return "", ErrUntrusted
	}
	raw := "syn443://enroll/v1?" + url.Values{"service": {invitation.ServiceID}, "origin": {invitation.Origin}, "code": {invitation.Code}, "bootstrap": {invitation.Manifest}}.Encode()
	if len(raw) > MaxLink {
		return "", ErrUntrusted
	}
	return raw, nil
}
func ParseLink(raw string) (Invitation, error) {
	var result Invitation
	if len(raw) < 1 || len(raw) > MaxLink || !ascii(raw) || !strings.HasPrefix(raw, "syn443://") {
		return result, ErrUntrusted
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "syn443" || u.Host != "enroll" || u.Path != "/v1" || u.RawPath != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return result, ErrUntrusted
	}
	values, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(values) != 4 {
		return result, ErrUntrusted
	}
	for name, list := range values {
		if len(list) != 1 || name != "service" && name != "origin" && name != "code" && name != "bootstrap" {
			return result, ErrUntrusted
		}
	}
	result = Invitation{ServiceID: values.Get("service"), Origin: values.Get("origin"), Code: values.Get("code"), Manifest: values.Get("bootstrap")}
	if result.validate() != nil {
		return Invitation{}, ErrUntrusted
	}
	return result, nil
}

// Authentication is entirely local. An untrusted QR never causes discovery,
// token/code transmission or a request to a caller-selected key endpoint.
// This authenticates the service, not an account or administrative permission.
func AuthenticateLink(raw string, anchor Anchor, floor Floor, now time.Time) (AuthenticatedInvitation, error) {
	invitation, e := ParseLink(raw)
	if e != nil {
		return AuthenticatedInvitation{}, e
	}
	descriptor, next, e := VerifyDescriptor(invitation.Manifest, anchor, floor, now)
	if e != nil {
		return AuthenticatedInvitation{}, e
	}
	if descriptor.ServiceID != invitation.ServiceID || descriptor.APIOrigin != invitation.Origin {
		return AuthenticatedInvitation{}, ErrUntrusted
	}
	return AuthenticatedInvitation{descriptor, next, invitation.Code}, nil
}

// RedactLink is for explicitly opted-in operator diagnostics. Normal logs should
// contain only fixed codes, never an invitation or the rest of an arbitrary URL.
func RedactLink(raw string) string {
	if strings.HasPrefix(raw, "syn443:") {
		return "syn443:[redacted]"
	}
	return "[redacted]"
}
