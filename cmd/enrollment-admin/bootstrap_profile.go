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
	SchemaVersion int                  `json:"schemaVersion"`
	Anchor        bootstrap.Anchor     `json:"anchor"`
	Service       string               `json:"service"`
	Upgrade       *installationUpgrade `json:"upgrade,omitempty"`
}

type installationUpgrade struct {
	PreviousAnchor bootstrap.Anchor   `json:"previousAnchor"`
	Rotation       bootstrap.Rotation `json:"rotation"`
}

func signInstallationProfile(raw []byte, key, previousKey *ecdsa.PrivateKey, now time.Time) (string, error) {
	var specification struct {
		Anchor  bootstrap.Anchor     `json:"anchor"`
		Service bootstrap.Descriptor `json:"service"`
		Upgrade *struct {
			PreviousAnchor bootstrap.Anchor     `json:"previousAnchor"`
			Transition     bootstrap.Transition `json:"transition"`
		} `json:"upgrade,omitempty"`
	}
	if identity.DecodeOperatorDocument(raw, &specification) != nil || specification.Anchor.LastTransition != "" ||
		(specification.Upgrade == nil) != (previousKey == nil) {
		return "", identity.ErrInvalid
	}
	service, err := bootstrap.SignDescriptor(specification.Service, specification.Anchor, key, now)
	if err != nil {
		return "", err
	}
	profile := installationProfile{SchemaVersion: 1, Anchor: specification.Anchor, Service: service}
	if upgrade := specification.Upgrade; upgrade != nil {
		previous := upgrade.PreviousAnchor
		if previous.Validate() != nil || previous.LastTransition != "" {
			return "", identity.ErrInvalid
		}
		for _, publicationKey := range specification.Service.Roots {
			if publicationKey == previous.SPKI {
				return "", identity.ErrInvalid
			}
		}
		rotation, err := bootstrap.SignRotation(upgrade.Transition, previous, previousKey, key, now)
		if err != nil {
			return "", err
		}
		next, err := bootstrap.AdvanceRoot(rotation, previous, now)
		if err != nil {
			return "", err
		}
		next.LastTransition = ""
		if next != specification.Anchor {
			return "", identity.ErrInvalid
		}
		profile.SchemaVersion = 2
		profile.Upgrade = &installationUpgrade{PreviousAnchor: previous, Rotation: rotation}
	}
	body, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	if len(encoded) > 12_000 {
		return "", identity.ErrInvalid
	}
	return encoded, nil
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
	var previous *ecdsa.PrivateKey
	if path := os.Getenv("SYN443_BOOTSTRAP_PREVIOUS_ROOT_KEY"); path != "" {
		previous, err = enrollment.PrivateKey(path)
		if err != nil {
			return err
		}
	}
	profile, err := signInstallationProfile(raw, key, previous, time.Now())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, profile)
	return err
}
