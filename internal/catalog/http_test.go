package catalog

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

type rejectVerifier struct{}

func (rejectVerifier) Verify(context.Context, string, time.Time) (identity.Principal, error) {
	return identity.Principal{}, identity.ErrInvalid
}
func TestAdminOriginAdmissionAndFixedErrorContracts(t *testing.T) {
	if _, e := NewAPI(&Store{}, rejectVerifier{}, "https://control.example.invalid", "urn:syn443:loa:2", false); e != nil {
		t.Fatal(e)
	}
	for _, origin := range []string{"http://control.example.invalid", "https://control.example.invalid/path", "https://control.example.invalid?x=y", "https://user@control.example.invalid", "https://control.example.invalid#x"} {
		if _, e := NewAPI(&Store{}, rejectVerifier{}, origin, "mfa", false); e == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	if _, e := NewAPI(&Store{}, rejectVerifier{}, "http://127.0.0.1:12345", "mfa", true); e != nil {
		t.Fatal(e)
	}
	if _, e := NewAPI(&Store{}, rejectVerifier{}, "https://control.example.invalid", "", false); e == nil {
		t.Fatal("unpinned assurance")
	}
	a, _ := NewAPI(&Store{}, rejectVerifier{}, "https://control.example.invalid", "mfa", false)
	now := time.Unix(1800000000, 0)
	for i := 0; i < 120; i++ {
		if !a.admit("same-client", now) {
			t.Fatal("premature rate limit")
		}
	}
	if a.admit("same-client", now) {
		t.Fatal("request budget not enforced")
	}
	for i := 1; i < 512; i++ {
		if !a.admit(fmt.Sprintf("client-%d", i), now) {
			t.Fatal("rate-map capacity")
		}
	}
	if a.admit("client-overflow", now) {
		t.Fatal("unbounded rate map")
	}
	if !a.admit("new-client", now.Add(2*time.Minute)) {
		t.Fatal("expired rate slots not reclaimed")
	}
	for _, test := range []struct {
		e      error
		status int
	}{{ErrDenied, 403}, {identity.ErrInvalid, 403}, {ErrInvalid, 400}, {ErrConflict, 409}, {ErrStale, 409}, {ErrQuota, 429}, {ErrUnavailable, 503}} {
		w := httptest.NewRecorder()
		apiFailure(w, test.e)
		if w.Code != test.status {
			t.Fatal("fixed API status", w.Code)
		}
	}
}
