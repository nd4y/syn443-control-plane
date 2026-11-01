package remnawave

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/resources"
)

type ownerConfig struct {
	ResourceID               string   `json:"resourceId"`
	ProviderType             string   `json:"providerType"`
	APIVersion               string   `json:"apiVersion"`
	Endpoint                 string   `json:"endpoint"`
	Enabled                  bool     `json:"enabled"`
	CredentialFile           string   `json:"credentialFile"`
	CertificateAuthorityFile string   `json:"certificateAuthorityFile"`
	AllowedNetworks          []string `json:"allowedNetworks"`
}

func privateFile(path string, max int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, resources.Failure("invalid_owner_config", false)
	}
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Size() < 1 || i.Size() > max || (secret && i.Mode().Perm()&0077 != 0) {
		return nil, resources.Failure("invalid_owner_config", false)
	}
	if secret {
		parent, e := os.Stat(filepath.Dir(path))
		if e != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
			return nil, resources.Failure("invalid_owner_config", false)
		}
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, resources.Failure("invalid_owner_config", false)
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(i, opened) {
		return nil, resources.Failure("invalid_owner_config", false)
	}
	// Read through this verified descriptor, and bound growth after the stat.
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || len(b) < 1 || int64(len(b)) > max {
		return nil, resources.Failure("invalid_owner_config", false)
	}
	return b, nil
}

func NewFromOwnerFile(path string) (*Client, error) {
	raw, e := privateFile(path, 16*1024, true)
	if e != nil {
		return nil, e
	}
	var o ownerConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if validateJSON(raw) != nil || d.Decode(&o) != nil {
		return nil, resources.Failure("invalid_owner_config", false)
	}
	token, e := privateFile(o.CredentialFile, 4096, true)
	if e != nil {
		return nil, e
	}
	c := Config{Instance: resources.Instance{ResourceID: o.ResourceID, ProviderType: o.ProviderType, APIVersion: o.APIVersion, Endpoint: o.Endpoint, Enabled: o.Enabled, CredentialRef: o.ResourceID + "/api-token"}, Token: strings.TrimSpace(string(token))}
	if o.CertificateAuthorityFile != "" {
		cert, e := privateFile(o.CertificateAuthorityFile, 2*1024*1024, false)
		if e != nil {
			return nil, e
		}
		c.Roots = x509.NewCertPool()
		if !c.Roots.AppendCertsFromPEM(cert) {
			return nil, resources.Failure("invalid_owner_config", false)
		}
	}
	if len(o.AllowedNetworks) > 16 {
		return nil, resources.Failure("invalid_network_grant", false)
	}
	for _, raw := range o.AllowedNetworks {
		p, e := netip.ParsePrefix(raw)
		if e != nil || (p.Addr().Is4() && p.Bits() < 24) || (p.Addr().Is6() && p.Bits() < 64) {
			return nil, resources.Failure("invalid_network_grant", false)
		}
		c.AllowedNetworks = append(c.AllowedNetworks, p)
	}
	return New(c)
}
