//go:build postgres

package enrollment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func publishedConfiguration(t *testing.T, f *fixture, device string) (int64, []byte, string) {
	t.Helper()
	var revision int64
	var cipher []byte
	if err := fixtureOwner.QueryRow(`SELECT revision,publication FROM identity_devices WHERE id=$1`, device).Scan(&revision, &cipher); err != nil {
		t.Fatal(err)
	}
	plain, err := f.worker.Open(cipher, "publication/v1/"+device+"/"+fmt.Sprint(revision))
	if err != nil {
		t.Fatal(err)
	}
	return revision, cipher, string(plain)
}
func TestSQLPublisherUsesActualTargetCompiledDocumentAndFinalConfigurationFences(t *testing.T) {
	f := newFixture(t, 2)
	deviceKey := key(t)
	session, _, _ := f.register(t, deviceKey)
	thumb, _ := identity.PublicJWK(&deviceKey.PublicKey).Thumbprint()
	prepared, _, _ := configuredPreparation(t)
	fence := &fixtureConfigurationFence{}
	prepared.Fence = fence
	publisher := f.publisher()
	publisher.Configurations = fixtureConfigurationAuthority(func(ctx context.Context, target ConfigurationTarget, now time.Time) (*PreparedConfiguration, error) {
		if ctx.Err() != nil || target.Device != session.DeviceID || target.Owner != Owner(f.grant.Issuer, f.grant.Subject) || target.Thumbprint != thumb || target.GrantHash != f.grant.Hash() || target.CurrentRevision != 0 || len(target.Capabilities) != 3 || !now.Equal(f.now) {
			t.Fatal("publisher trusted substituted configuration target")
		}
		return prepared, nil
	})
	if err := publisher.publish(context.Background(), session.DeviceID, f.now); err != nil {
		t.Fatal(err)
	}
	revision, cipher, bundle := publishedConfiguration(t, f, session.DeviceID)
	if revision != 1 || fence.calls != 2 {
		t.Fatal("configuration did not receive both transactional fences")
	}
	payload, err := policy.VerifyBound(bundle, f.api.Roots, session.DeviceID, thumb, f.now)
	digest := sha256.Sum256(prepared.EngineConfig)
	if err != nil || payload.ContentHash != fmt.Sprintf("%x", digest) || payload.OfflineUntilMs != prepared.UntilMs {
		t.Fatal("actual compiled publication not signed/bounded", err)
	}
	// A source/config authority outage cannot silently publish the account's
	// static template or replace the existing encrypted last-known-good policy.
	publisher.Configurations = fixtureConfigurationAuthority(func(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error) {
		return nil, ErrUnavailable
	})
	if err = publisher.publish(context.Background(), session.DeviceID, f.now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("authority outage fell back", err)
	}
	after, retained, _ := publishedConfiguration(t, f, session.DeviceID)
	if after != revision || string(retained) != string(cipher) {
		t.Fatal("outage replaced authorized publication")
	}
}

func TestSQLPublisherConfigurationRevokeLateExpiryAndCancellationKeepLastGood(t *testing.T) {
	for _, failure := range []string{"initial-fence", "commit-fence", "late-expiry", "cancel", "missing"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t, 1)
			session, _, _ := f.register(t, key(t))
			publisher := f.publisher()
			if err := publisher.publish(context.Background(), session.DeviceID, f.now); err != nil {
				t.Fatal(err)
			}
			revision, cipher, _ := publishedConfiguration(t, f, session.DeviceID)
			prepared, _, _ := configuredPreparation(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fence := &fixtureConfigurationFence{}
			fence.lock = func(context.Context, *sql.Tx, time.Time) error {
				if failure == "initial-fence" || failure == "commit-fence" && fence.calls == 2 {
					return ErrConflict
				}
				if failure == "late-expiry" && fence.calls == 1 {
					time.Sleep(2100 * time.Millisecond)
				}
				return nil
			}
			prepared.Fence = fence
			if failure == "late-expiry" {
				prepared.UntilMs = f.now.UnixMilli() + 2000
			}
			publisher.Configurations = fixtureConfigurationAuthority(func(context.Context, ConfigurationTarget, time.Time) (*PreparedConfiguration, error) {
				if failure == "missing" {
					return nil, nil
				}
				if failure == "cancel" {
					cancel()
				}
				return prepared, nil
			})
			if err := publisher.publish(ctx, session.DeviceID, f.now); err == nil {
				t.Fatal("invalid/late configuration committed")
			}
			after, retained, _ := publishedConfiguration(t, f, session.DeviceID)
			if after != revision || string(retained) != string(cipher) {
				t.Fatal("rejected configuration replaced last good")
			}
		})
	}
}
