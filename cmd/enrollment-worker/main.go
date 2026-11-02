// Separate publication role. Only owner-authored grants and independently verified receipts are signed.
package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/deviceprovisioning"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/invitation"
)

func run() error {
	c, e := enrollment.ReadConfig(os.Getenv("SYN443_ENROLLMENT_CONFIG"))
	if e != nil {
		return e
	}
	store, e := enrollment.OpenStore(c)
	if e != nil {
		return e
	}
	defer store.DB.Close()
	raw, e := enrollment.PrivateFile(os.Getenv("SYN443_ENROLLMENT_GRANTS"), 524288)
	if e != nil {
		return e
	}
	var grants []enrollment.Grant
	if identity.DecodeOperatorDocument(raw, &grants) != nil || len(grants) < 1 || len(grants) > 128 {
		return identity.ErrInvalid
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	check, cancelRole := context.WithTimeout(ctx, 5*time.Second)
	e = store.RuntimeRole(check, true)
	cancelRole()
	if e != nil {
		return e
	}
	provider, e := identity.NewProvider(ctx, c.Issuer, c.Audience, c.ClientID, nil, c.FixtureHTTP)
	if e != nil {
		return e
	}
	key, e := enrollment.PrivateKey(os.Getenv("SYN443_POLICY_SIGNING_KEY_FILE"))
	if e != nil {
		return e
	}
	p := enrollment.Publisher{Store: store, Verifier: provider, Grants: map[string]enrollment.Grant{}, Key: key, KeyID: os.Getenv("SYN443_POLICY_KEY_ID"), Origin: c.Origin}
	for _, g := range grants {
		if g.Validate(time.Now()) != nil || g.Issuer != c.Issuer {
			return identity.ErrInvalid
		}
		owner := enrollment.Owner(g.Issuer, g.Subject)
		if _, exists := p.Grants[owner]; exists {
			return identity.ErrInvalid
		}
		p.Grants[owner] = g
	}
	var brokerRoots map[string]*ecdsa.PublicKey
	if c.OverlayBrokerEnabled {
		resources, err := enrollment.ReadBrokerPolicyResources(os.Getenv("SYN443_OVERLAY_POLICY_RESOURCES"))
		if err != nil {
			return err
		}
		p.Brokers, err = enrollment.NewBrokerPolicies(store, c.OverlayServiceID, resources)
		if err != nil {
			return err
		}
		brokerRoots, err = enrollment.PublicRoots(c)
		if err != nil {
			return err
		}
	}
	var invites *deviceprovisioning.Invitations
	if path := os.Getenv("SYN443_INVITATION_CONFIG"); path != "" {
		ic, err := invitation.ReadConfig(path, time.Now())
		if err != nil || ic.IdentityOrigin != c.Origin || ic.Issuer != c.Issuer {
			return identity.ErrInvalid
		}
		is, err := invitation.NewStore(store.DB, ic.Key())
		if err != nil {
			return err
		}
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = is.RuntimeRole(check, "syn443_identity_publisher")
		cancel()
		if err != nil {
			return err
		}
		verification, err := ic.Verification(ctx)
		if err != nil {
			return err
		}
		invites = &deviceprovisioning.Invitations{Identity: store, Invitations: is, Verification: verification, Grants: p.Grants}
		p.InvitationApproval = invites
	}
	for {
		step, cancel := context.WithTimeout(ctx, 10*time.Second)
		now, e := store.Now(step, time.Now())
		if e == nil && p.Brokers != nil {
			e = p.Brokers.Schedule(step, now)
		}
		if e == nil {
			if invites != nil {
				e = invites.Prepare(step, now)
			}
			if e == nil {
				e = p.RunOnce(step, now)
			}
			if e == nil && p.Brokers != nil {
				e = p.Brokers.DeliverReady(step, &p, brokerRoots, now)
			}
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, "publication_step_unavailable")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "enrollment_worker_failed")
		os.Exit(1)
	}
}
