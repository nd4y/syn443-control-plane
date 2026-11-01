package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type Config struct {
	Listen          string            `json:"listen"`
	Origin          string            `json:"origin"`
	Issuer          string            `json:"issuer"`
	Audience        string            `json:"audience"`
	ClientID        string            `json:"clientId"`
	Database        string            `json:"database"`
	EncryptionKey   string            `json:"encryptionKey"`
	Roots           map[string]string `json:"roots"`
	Certificate     string            `json:"certificate"`
	CertificateKey  string            `json:"certificateKey"`
	FixtureHTTP     bool              `json:"fixtureHttp"`
	ChatEnabled     bool              `json:"chatEnabled"`
	ChatWebOrigin   string            `json:"chatWebOrigin"`
	ChatWebClientID string            `json:"chatWebClientId"`
	ChatWebAudience string            `json:"chatWebAudience"`
}

func PrivateFile(path string, max int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > max {
		return nil, errors.New("owner_only_file_required")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("owner_only_file_required")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) || opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("owner_only_file_required")
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max || len(raw) == 0 {
		return nil, errors.New("owner_only_file_required")
	}
	return raw, nil
}
func ReadConfig(path string) (Config, error) {
	var c Config
	raw, e := PrivateFile(path, 65536)
	if e != nil {
		return c, e
	}
	if identity.Decode(raw, &c, true) != nil {
		return c, identity.ErrInvalid
	}
	if c.ValidateChat() != nil {
		return c, identity.ErrInvalid
	}
	return c, nil
}
func (c Config) ValidateChat() error {
	if c.ChatWebOrigin == "" && c.ChatWebClientID == "" && c.ChatWebAudience == "" {
		return nil
	}
	u, e := url.Parse(c.ChatWebOrigin)
	if !c.ChatEnabled || e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Scheme != "https" && !(c.FixtureHTTP && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "") || len(c.ChatWebClientID) < 1 || len(c.ChatWebClientID) > 128 || len(c.ChatWebAudience) < 1 || len(c.ChatWebAudience) > 128 || c.ChatWebClientID == c.ClientID || c.ChatWebAudience == c.Audience {
		return identity.ErrInvalid
	}
	return nil
}
func OpenStore(c Config) (*Store, error) {
	key, e := base64.StdEncoding.Strict().DecodeString(c.EncryptionKey)
	if e != nil || len(key) != 32 {
		return nil, identity.ErrInvalid
	}
	parsed, e := pgx.ParseConfig(c.Database)
	if e != nil || parsed.User == "" || parsed.Database == "" {
		return nil, identity.ErrInvalid
	}
	if parsed.Host != "127.0.0.1" {
		if parsed.TLSConfig == nil || parsed.TLSConfig.InsecureSkipVerify || parsed.TLSConfig.ServerName == "" {
			return nil, identity.ErrInvalid
		}
		for _, fallback := range parsed.Fallbacks {
			if fallback.TLSConfig == nil || fallback.TLSConfig.InsecureSkipVerify || fallback.TLSConfig.ServerName == "" {
				return nil, identity.ErrInvalid
			}
		}
	}
	parsed.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*parsed)
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	store, e := NewStore(db, key)
	if e != nil {
		db.Close()
	}
	return store, e
}
func PublicRoots(c Config) (map[string]*ecdsa.PublicKey, error) {
	roots := map[string]*ecdsa.PublicKey{}
	if len(c.Roots) < 1 || len(c.Roots) > 4 {
		return nil, identity.ErrInvalid
	}
	for kid, encoded := range c.Roots {
		raw, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil {
			return nil, e
		}
		parsed, e := x509.ParsePKIXPublicKey(raw)
		if e != nil {
			return nil, e
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, identity.ErrInvalid
		}
		roots[kid] = key
	}
	return roots, nil
}

// Refuse accidental owner/superuser deployment before starting a listener or signing work.
func (s *Store) RuntimeRole(ctx context.Context, publisher bool) error {
	expected := "syn443_identity_api"
	if publisher {
		expected = "syn443_identity_publisher"
	}
	var current, session string
	var unsafe bool
	e := s.DB.QueryRowContext(ctx, `SELECT current_user,session_user,
 rolsuper OR rolcreaterole OR rolcreatedb OR rolinherit OR rolbypassrls
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid)
 OR has_schema_privilege(current_user,'public','CREATE')
 OR has_column_privilege(current_user,'identity_accounts','grant_hash','UPDATE')
 OR has_table_privilege(current_user,'identity_accounts','INSERT')
 FROM pg_roles WHERE rolname=current_user`).Scan(&current, &session, &unsafe)
	if e != nil || unsafe || current != expected || session != expected {
		return ErrDenied
	}
	if !publisher {
		if e = s.DB.QueryRowContext(ctx, `SELECT has_column_privilege(current_user,'identity_devices','publication','UPDATE') OR has_column_privilege(current_user,'identity_devices','approved','UPDATE')`).Scan(&unsafe); e != nil || unsafe {
			return ErrDenied
		}
		if e = s.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'chat_admins','INSERT') OR has_column_privilege(current_user,'chat_admins','enabled','UPDATE')`).Scan(&unsafe); e != nil || unsafe {
			return ErrDenied
		}
	}
	return nil
}
func PrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, e := PrivateFile(path, 8192)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, identity.ErrInvalid
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, identity.ErrInvalid
	}
	return ec, nil
}
