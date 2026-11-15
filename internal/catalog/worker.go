package catalog

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/resources"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

// Worker has source read credentials, never signing or enrollment authority.
// FixtureLoopback is an owner process setting, never an API/source field.
type Worker struct {
	Store           *Store
	FixtureLoopback bool
	Clock           func() time.Time
}

func (w *Worker) clock(ctx context.Context) (time.Time, error) {
	now := time.Now()
	if w.Clock != nil {
		now = w.Clock()
	}
	return w.Store.Now(ctx, now)
}
func (w *Worker) ProcessOne(ctx context.Context) (Job, error) {
	if w.Store == nil {
		return Job{}, ErrInvalid
	}
	now, e := w.clock(ctx)
	if e != nil {
		return Job{}, e
	}
	job, e := w.Store.Claim(ctx, now)
	if e != nil || job.ID == "" {
		return job, e
	}
	work, stop := context.WithTimeout(ctx, 40*time.Second)
	defer stop()
	source, salt, secret, payload, e := w.Store.JobInput(work, job, now)
	var profiles []subscriptions.Profile
	var quota subscriptions.Quota
	var cache subscriptions.Cache
	if e == nil {
		switch source.Mode {
		case "manual":
			profiles, e = subscriptions.Import(source.ID, salt, source.Format, payload)
		case "device":
			var result deviceProviderMetadata
			var raw []byte
			result, raw, e = readDeviceProviderResult(payload)
			if e != nil {
				break
			}
			switch result.Status {
			case http.StatusUnauthorized, http.StatusForbidden:
				e = subscriptions.ErrAccess
			case http.StatusGone:
				e = subscriptions.ErrRevoked
			}
			if e == nil && providerErrorStatus(result.Status) {
				e = subscriptions.ErrFetch
			}
			if e != nil {
				break
			}
			cache = result.cache()
			quota, e = subscriptions.ParseQuota(result.Quota, now)
			if e != nil {
				break
			}
			if result.Status == http.StatusNotModified {
				var previous Snapshot
				var oldCache subscriptions.Cache
				oldCache, previous, profiles, e = w.Store.SyncCache(work, job, now)
				if e == nil && (previous.ID == "" || previous.SourceRevision != source.Revision ||
					oldCache.ETag == "" && oldCache.LastModified == "") {
					e = subscriptions.ErrInvalid
				}
				if cache.ETag == "" {
					cache.ETag = oldCache.ETag
				}
				if cache.LastModified == "" {
					cache.LastModified = oldCache.LastModified
				}
			} else {
				profiles, e = subscriptions.Import(source.ID, salt, source.Format, raw)
			}
		case "server":
			var previous Snapshot
			var old []subscriptions.Profile
			cache, previous, old, e = w.Store.SyncCache(work, job, now)
			if e == nil {
				var c FetchCredential
				c, e = ReadFetchCredential(secret)
				if e == nil {
					var config subscriptions.FetchConfig
					config, e = c.Config(w.FixtureLoopback)
					if e == nil {
						var result subscriptions.Fetched
						result, e = subscriptions.Fetch(work, config, cache, now)
						if e == nil {
							cache = result.Cache
							quota = result.Quota
							if result.NotModified {
								if previous.ID == "" {
									e = subscriptions.ErrInvalid
								} else {
									profiles = old
								}
							} else {
								profiles, e = subscriptions.Import(source.ID, salt, source.Format, result.Raw)
							}
						}
					}
				}
			}
		case "resource":
			client, id, err := w.Store.ResourceClient(work, job, w.FixtureLoopback, now)
			e = err
			if e == nil {
				snapshot, err := client.ReadAssignment(work, client.Binding(id))
				client.Close()
				e = err
				if e == nil {
					quota = subscriptions.Quota{Known: true, Used: snapshot.TrafficUsedBytes, Limit: snapshot.TrafficLimitBytes, ExpiresAt: snapshot.ExpiresAt.Unix(), ObservedAt: snapshot.ObservedAt.Unix()}
					profiles, e = subscriptions.Import(source.ID, salt, "uri", []byte(strings.Join(snapshot.Links, "\n")))
				}
			}
		default:
			e = ErrInvalid
		}
	}
	finished, clockErr := w.clock(ctx)
	if clockErr != nil {
		return job, clockErr
	}
	if e == nil {
		_, e = w.Store.Complete(ctx, job, profiles, quota, cache, finished)
	}
	if e == nil {
		job.Phase = "succeeded"
		return job, nil
	}
	if errors.Is(e, ErrStale) {
		job.Phase = "cancelled"
		job.Reason = "stale_inputs"
		return job, w.Store.Abandon(ctx, job, finished)
	}
	if errors.Is(e, ErrUnavailable) || ctx.Err() != nil {
		return job, ErrUnavailable
	}
	reason, permanent := sourceFailure(e)
	if e = w.Store.Fail(ctx, job, reason, permanent, finished); e != nil {
		return job, e
	}
	job.Phase = "queued"
	if permanent {
		job.Phase = "failed"
	}
	job.Reason = reason
	return job, nil
}
func sourceFailure(e error) (string, bool) {
	for _, known := range []error{subscriptions.ErrInvalid, subscriptions.ErrUnsupported, subscriptions.ErrAmbiguous, subscriptions.ErrTLS, subscriptions.ErrAccess, subscriptions.ErrRevoked, subscriptions.ErrExpired, subscriptions.ErrEmpty, subscriptions.ErrSize} {
		if errors.Is(e, known) {
			return known.Error(), true
		}
	}
	var provider *resources.Error
	if errors.As(e, &provider) {
		switch provider.Code {
		case "assignment_revoked":
			return "resource_denied", true
		case "assignment_expired":
			return subscriptions.ErrExpired.Error(), true
		case "access_denied":
			return subscriptions.ErrAccess.Error(), true
		case "tls_validation_failed":
			return subscriptions.ErrTLS.Error(), true
		case "empty_snapshot":
			return subscriptions.ErrEmpty.Error(), true
		case "invalid_response", "identity_mismatch", "invalid_binding", "unsupported_api_version":
			return subscriptions.ErrInvalid.Error(), true
		case "address_not_allowed":
			return subscriptions.ErrAccess.Error(), true
		}
		return "resource_unavailable", !provider.Retryable
	}
	if errors.Is(e, ErrInvalid) {
		return subscriptions.ErrInvalid.Error(), true
	}
	return subscriptions.ErrFetch.Error(), false
}
