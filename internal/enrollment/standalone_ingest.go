package enrollment

import (
	"context"
	_ "embed"
	"net/http"
	"net/url"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/identity"
)

//go:embed ingest-roles.sql
var IngestRoles string

//go:embed ingest-authority.sql
var ingestAuthority string

// StandaloneIngest never loads the policy encryption key or an OIDC provider.
type StandaloneIngest struct {
	api *API
}

func OpenStandaloneIngest(ctx context.Context, dsn, origin string, fixtureHTTP bool) (*StandaloneIngest, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin ||
		(u.Scheme != "https" && !(fixtureHTTP && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "")) {
		return nil, identity.ErrInvalid
	}
	db, err := openDatabase(dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(telemetryConnections)
	s := &StandaloneIngest{api: &API{TelemetryStore: &Store{DB: db, telemetryOnly: true},
		Origin: origin, Clock: time.Now, uploads: newAdmission(telemetryConnections)}}
	if err := s.Ready(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *StandaloneIngest) Close() error { return s.api.TelemetryStore.DB.Close() }

func (s *StandaloneIngest) Ready(ctx context.Context) error {
	var allowed bool
	if err := s.api.TelemetryStore.DB.QueryRowContext(ctx, ingestAuthority).Scan(&allowed); err != nil || !allowed {
		return ErrUnavailable
	}
	return nil
}

func (s *StandaloneIngest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != telemetryPath || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	s.api.ServeHTTP(w, r)
}
