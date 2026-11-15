#!/usr/bin/env bash
# Disposable Actions-only identity/catalog invitation role fixture.
set +x
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
port=17848
export POSTGRES_PASSWORD PGPASSWORD SYN443_TEST_DATABASE
POSTGRES_PASSWORD=$(openssl rand -hex 32)
PGPASSWORD="$POSTGRES_PASSWORD"
SYN443_TEST_DATABASE="postgres://postgres@127.0.0.1:$port/postgres?sslmode=disable"
container_id=''
cleanup() {
  if [ -n "$container_id" ]; then docker rm -f -v "$container_id" >/dev/null; fi
  unset POSTGRES_PASSWORD PGPASSWORD SYN443_TEST_DATABASE
}
trap cleanup EXIT
container_id=$(docker run -d --cpus=0.5 --memory=256m --shm-size=32m \
  -p "127.0.0.1:$port:5432" -e POSTGRES_PASSWORD \
  postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c)
ready=false
for ((i=0; i<45; i++)); do
  if docker exec "$container_id" pg_isready -q -h 127.0.0.1 -U postgres; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
GOMAXPROCS=2 GOMEMLIMIT=384MiB go test -p 2 -tags postgres -race -count=1 -timeout=3m \
  -coverpkg=./internal/invitation -coverprofile=invitation-coverage.out ./internal/invitation

GOMAXPROCS=2 GOMEMLIMIT=384MiB go test -p 1 -tags postgres -race -count=1 -timeout=3m \
  -coverpkg=./internal/invitation,./internal/deviceprovisioning,./internal/enrollment \
  -coverprofile=provisioning-coverage.out ./internal/deviceprovisioning
