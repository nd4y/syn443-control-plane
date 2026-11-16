package main

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/deviceprovisioning"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type configurationQueueMode string

const (
	configurationQueueEmbedded configurationQueueMode = "embedded"
	configurationQueueExternal configurationQueueMode = "external"
)

type configurationStartup struct {
	mode   configurationQueueMode
	config deviceprovisioning.ConfigurationRuntimeConfig
}

func (*configurationStartup) String() string     { return "ConfigurationStartup([redacted])" }
func (s *configurationStartup) GoString() string { return s.String() }

// Run this before enrollment DB/provider initialization. An omitted mode and
// absent configuration retain the ordinary device-only worker. Explicit modes
// require a configuration; unknown/whitespace/case variants never fall back.
func readConfigurationStartup(getenv func(string) string, read func(string) (deviceprovisioning.ConfigurationRuntimeConfig, error)) (*configurationStartup, error) {
	if getenv == nil {
		return nil, identity.ErrInvalid
	}
	rawMode := getenv("SYN443_CONFIGURATION_QUEUE_MODE")
	mode := configurationQueueMode(rawMode)
	if mode != "" && mode != configurationQueueEmbedded && mode != configurationQueueExternal {
		return nil, identity.ErrInvalid
	}
	path := getenv("SYN443_CONFIGURATION_CONFIG")
	if path == "" {
		if mode != "" {
			return nil, identity.ErrInvalid
		}
		return nil, nil
	}
	if read == nil {
		return nil, identity.ErrInvalid
	}
	config, err := read(path)
	if err != nil {
		return nil, identity.ErrInvalid
	}
	if mode == "" {
		mode = configurationQueueEmbedded
	}
	return &configurationStartup{mode: mode, config: config}, nil
}

// Narrow dependency seams cover startup ownership/order, not SQL, provider or
// receipt authorization. Production always uses the existing guarded methods.
type configurationStartupDependencies struct {
	layers  func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig, *sql.DB) (*enrollment.Store, error)
	sources func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig, *sql.DB) (*catalog.Store, error)
	roots   func(deviceprovisioning.ConfigurationRuntimeConfig) (map[string]*ecdsa.PublicKey, error)
	admins  func(context.Context, deviceprovisioning.ConfigurationRuntimeConfig) (catalog.VerifierGroup, error)
	key     func(string) (*ecdsa.PrivateKey, error)
}

func defaultConfigurationStartupDependencies() configurationStartupDependencies {
	return configurationStartupDependencies{
		layers: func(ctx context.Context, c deviceprovisioning.ConfigurationRuntimeConfig, db *sql.DB) (*enrollment.Store, error) {
			return c.LayerStore(ctx, db, true)
		},
		sources: func(ctx context.Context, c deviceprovisioning.ConfigurationRuntimeConfig, db *sql.DB) (*catalog.Store, error) {
			return c.SourceStore(ctx, db)
		},
		roots: func(c deviceprovisioning.ConfigurationRuntimeConfig) (map[string]*ecdsa.PublicKey, error) {
			return c.PublicRoots()
		},
		admins: func(ctx context.Context, c deviceprovisioning.ConfigurationRuntimeConfig) (catalog.VerifierGroup, error) {
			return c.AdminVerifier(ctx, nil)
		},
		key: enrollment.PrivateKey,
	}
}

func (s *configurationStartup) install(ctx context.Context, publisher *enrollment.Publisher, getenv func(string) string, dependencies configurationStartupDependencies) (*deviceprovisioning.ConfigurationPublisher, error) {
	if s == nil {
		return nil, nil
	}
	// The ordinary device signer remains mandatory in every configuration mode.
	if publisher == nil || publisher.Store == nil || publisher.Key == nil {
		return nil, identity.ErrInvalid
	}
	authority, queue, err := s.build(ctx, publisher.Store.DB, getenv, dependencies)
	if err != nil {
		return nil, err
	}
	publisher.Configurations = authority
	return queue, nil
}

func (s *configurationStartup) build(ctx context.Context, db *sql.DB, getenv func(string) string, dependencies configurationStartupDependencies) (*deviceprovisioning.NetworkAuthority, *deviceprovisioning.ConfigurationPublisher, error) {
	if s == nil {
		return nil, nil, nil
	}
	if ctx == nil || ctx.Err() != nil || db == nil || (s.mode != configurationQueueEmbedded && s.mode != configurationQueueExternal) ||
		dependencies.layers == nil || dependencies.sources == nil || dependencies.roots == nil {
		return nil, nil, identity.ErrInvalid
	}
	check, cancel := context.WithTimeout(ctx, 10*time.Second)
	layers, err := dependencies.layers(check, s.config, db)
	if err != nil || layers == nil || check.Err() != nil {
		cancel()
		if err == nil {
			err = identity.ErrInvalid
		}
		return nil, nil, err
	}
	sources, err := dependencies.sources(check, s.config, db)
	checkErr := check.Err()
	cancel()
	if err != nil || sources == nil || checkErr != nil {
		if err == nil {
			err = identity.ErrInvalid
		}
		return nil, nil, err
	}
	roots, err := dependencies.roots(s.config)
	if err != nil || len(roots) == 0 || ctx.Err() != nil {
		if err == nil {
			err = identity.ErrInvalid
		}
		return nil, nil, err
	}
	authority := &deviceprovisioning.NetworkAuthority{Sources: sources, Layers: &deviceprovisioning.SQLNetworkLayers{Store: layers, ControlOrigin: s.config.ControlOrigin, Roots: roots}}
	if s.mode == configurationQueueExternal {
		// Device policy issuance still consumes the verified configuration head.
		// Only the standalone worker discovers the admin IdP, owns the preview
		// signer and consumes the administrative queue in this deployment mode.
		return authority, nil, nil
	}
	if getenv == nil || dependencies.admins == nil || dependencies.key == nil {
		return nil, nil, identity.ErrInvalid
	}
	admins, err := dependencies.admins(ctx, s.config)
	if err != nil || len(admins) == 0 || ctx.Err() != nil {
		if err == nil {
			err = identity.ErrInvalid
		}
		return nil, nil, err
	}
	key, err := dependencies.key(getenv("SYN443_CONFIGURATION_SIGNING_KEY_FILE"))
	if err != nil || key == nil || ctx.Err() != nil {
		if err == nil {
			err = identity.ErrInvalid
		}
		return nil, nil, err
	}
	keyID := getenv("SYN443_CONFIGURATION_KEY_ID")
	if root := roots[keyID]; root == nil || !root.Equal(&key.PublicKey) {
		return nil, nil, identity.ErrInvalid
	}
	queue := &deviceprovisioning.ConfigurationPublisher{Store: layers, Sources: sources, Verifier: admins, Origin: s.config.ControlOrigin,
		AssuranceACR: s.config.AssuranceACR, KeyID: keyID, Key: key, Roots: roots}
	return authority, queue, nil
}
