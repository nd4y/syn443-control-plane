package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type installationProfile struct {
	SchemaVersion int              `json:"schemaVersion"`
	Anchor        bootstrap.Anchor `json:"anchor"`
	Service       string           `json:"service"`
}

func signInstallationProfile(raw []byte, key *ecdsa.PrivateKey, now time.Time) (string, error) {
	var specification struct {
		Anchor  bootstrap.Anchor     `json:"anchor"`
		Service bootstrap.Descriptor `json:"service"`
	}
	if identity.DecodeOperatorDocument(raw, &specification) != nil || specification.Anchor.LastTransition != "" {
		return "", identity.ErrInvalid
	}
	service, err := bootstrap.SignDescriptor(specification.Service, specification.Anchor, key, now)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(installationProfile{SchemaVersion: 1, Anchor: specification.Anchor, Service: service})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(body), nil
}

func runBootstrapProfile() error {
	raw, err := enrollment.PrivateFile(os.Getenv("SYN443_BOOTSTRAP_PROFILE_SPEC"), 8192)
	if err != nil {
		return err
	}
	key, err := enrollment.PrivateKey(os.Getenv("SYN443_BOOTSTRAP_ROOT_KEY"))
	if err != nil {
		return err
	}
	profile, err := signInstallationProfile(raw, key, time.Now())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, profile)
	return err
}
