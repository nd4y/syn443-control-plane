package enrollment

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/netip"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/netbirdapi"
	"github.com/nd4y/syn443-control-plane/internal/overlay"
)

// Bootstrap configuration is private owner input, never a control/device request.
// The SQL catalog-backed resource authority remains a separate integration.
// Archived revisions must be retained until their durable cleanup is complete.
type BrokerResource struct {
	ResourceID       string   `json:"resourceId"`
	Revision         int64    `json:"revision"`
	AccountID        string   `json:"accountId"`
	APIOrigin        string   `json:"apiOrigin"`
	ManagementOrigin string   `json:"managementOrigin"`
	NetworkID        string   `json:"networkId"`
	Groups           []string `json:"groups"`
	Token            string   `json:"token"`
	RootCA           string   `json:"rootCa,omitempty"`
	AllowedNetworks  []string `json:"allowedNetworks,omitempty"`
}

func (BrokerResource) String() string   { return "OverlayBrokerResource([redacted])" }
func (BrokerResource) GoString() string { return "OverlayBrokerResource([redacted])" }

type BrokerRuntimeConfig struct {
	Database        string           `json:"database"`
	EncryptionKey   string           `json:"encryptionKey"`
	Resources       []BrokerResource `json:"resources"`
	FixtureLoopback bool             `json:"fixtureLoopback"`
}

func (BrokerRuntimeConfig) String() string   { return "OverlayBrokerRuntimeConfig([redacted])" }
func (BrokerRuntimeConfig) GoString() string { return "OverlayBrokerRuntimeConfig([redacted])" }
func ReadBrokerRuntimeConfig(path string) (BrokerRuntimeConfig, error) {
	var c BrokerRuntimeConfig
	raw, e := PrivateFile(path, 524288)
	if e != nil {
		return c, e
	}
	if identity.DecodeOperatorDocument(raw, &c) != nil {
		return BrokerRuntimeConfig{}, identity.ErrInvalid
	}
	key, e := base64.StdEncoding.Strict().DecodeString(c.EncryptionKey)
	if e != nil || len(key) != 32 || c.Database == "" {
		return BrokerRuntimeConfig{}, identity.ErrInvalid
	}
	if _, e = NewBrokerResources(c.Resources, c.FixtureLoopback); e != nil {
		return BrokerRuntimeConfig{}, e
	}
	return c, nil
}

type brokerResourceKey struct {
	id       string
	revision int64
}
type brokerResourceValue struct {
	resource BrokerResource
	client   netbirdapi.Config
}
type BrokerResources struct {
	entries map[brokerResourceKey]brokerResourceValue
}

func (*BrokerResources) String() string   { return "OverlayBrokerResources([redacted])" }
func (*BrokerResources) GoString() string { return "OverlayBrokerResources([redacted])" }
func NewBrokerResources(input []BrokerResource, fixture bool) (*BrokerResources, error) {
	if len(input) < 1 || len(input) > 16 {
		return nil, identity.ErrInvalid
	}
	result := &BrokerResources{entries: map[brokerResourceKey]brokerResourceValue{}}
	for _, r := range input {
		k := brokerResourceKey{r.ResourceID, r.Revision}
		management, e := overlay.ManagementOrigin(r.ManagementOrigin)
		if e != nil || management != r.ManagementOrigin || !brokerIdentifier.MatchString(r.ResourceID) || !brokerIdentifier.MatchString(r.NetworkID) || r.Revision < 1 || r.Revision > 9007199254740991 || len(r.Groups) < 1 || len(r.Groups) > 16 || len(r.AllowedNetworks) > 8 || len(r.RootCA) > 32768 {
			return nil, identity.ErrInvalid
		}
		if _, exists := result.entries[k]; exists {
			return nil, identity.ErrInvalid
		}
		seen := map[string]bool{}
		for _, g := range r.Groups {
			if !brokerIdentifier.MatchString(g) || seen[g] {
				return nil, identity.ErrInvalid
			}
			seen[g] = true
		}
		config := netbirdapi.Config{ResourceID: r.ResourceID, AccountID: r.AccountID, APIOrigin: r.APIOrigin, Token: r.Token, FixtureLoopback: fixture}
		for _, raw := range r.AllowedNetworks {
			p, e := netip.ParsePrefix(raw)
			if e != nil {
				return nil, identity.ErrInvalid
			}
			config.AllowedNetworks = append(config.AllowedNetworks, p)
		}
		if r.RootCA != "" {
			config.Roots = x509.NewCertPool()
			rest := bytes.TrimSpace([]byte(r.RootCA))
			count := 0
			for len(rest) > 0 {
				block, next := pem.Decode(rest)
				if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
					return nil, identity.ErrInvalid
				}
				cert, e := x509.ParseCertificate(block.Bytes)
				if e != nil {
					return nil, identity.ErrInvalid
				}
				config.Roots.AddCert(cert)
				rest = bytes.TrimSpace(next)
				count++
				if count > 16 {
					return nil, identity.ErrInvalid
				}
			}
			if count == 0 {
				return nil, identity.ErrInvalid
			}
		}
		client, e := netbirdapi.New(config)
		if e != nil {
			return nil, identity.ErrInvalid
		}
		client.Close()
		r.Groups = append([]string(nil), r.Groups...)
		r.AllowedNetworks = append([]string(nil), r.AllowedNetworks...)
		result.entries[k] = brokerResourceValue{r, config}
	}
	return result, nil
}
func (r *BrokerResources) match(b BrokerScope) (brokerResourceValue, error) {
	if r == nil {
		return brokerResourceValue{}, ErrDenied
	}
	v, ok := r.entries[brokerResourceKey{b.Binding.Address.ResourceID, b.ResourceRevision}]
	management, e := overlay.ManagementOrigin(b.Binding.Address.ManagementURL)
	if !ok || e != nil || v.resource.ManagementOrigin != management || v.resource.AccountID != b.Account || v.resource.NetworkID != b.Binding.Address.NetworkID || len(b.Groups) < 1 || len(b.Groups) > 16 {
		return brokerResourceValue{}, ErrDenied
	}
	for _, g := range b.Groups {
		if !slices.Contains(v.resource.Groups, g) {
			return brokerResourceValue{}, ErrDenied
		}
	}
	return v, nil
}
func (r *BrokerResources) Resolve(ctx context.Context, b BrokerScope) (BrokerProvider, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrUnavailable
	}
	v, e := r.match(b)
	if e != nil {
		return nil, nil, e
	}
	client, e := netbirdapi.New(v.client)
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	return client, client.Close, nil
}

// BrokerNow has its own monotonic SQL clock. The provider worker has no right
// to modify the identity/session clock or read identity/session tables.
func (s *Store) BrokerNow(ctx context.Context, wall time.Time) (time.Time, error) {
	var second int64
	e := s.DB.QueryRowContext(ctx, `UPDATE identity_overlay_broker_clock SET second=GREATEST(second,$1) WHERE id=true RETURNING second`, wall.Unix()).Scan(&second)
	if e != nil {
		return time.Time{}, ErrUnavailable
	}
	return time.Unix(second, 0).UTC(), nil
}
