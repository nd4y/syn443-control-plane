#!/usr/bin/env bash
# Own short-lived PostgreSQL only. No existing database or operator credentials.
set +x
set -euo pipefail
port=${SYN443_POSTGRES_TEST_PORT:-17846}
[[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1024 && port <= 65535 ))
export POSTGRES_PASSWORD
POSTGRES_PASSWORD=$(openssl rand -hex 32)
export PGPASSWORD="$POSTGRES_PASSWORD"
export SYN443_TEST_DATABASE="postgres://postgres@127.0.0.1:$port/postgres?sslmode=disable"
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
  if docker exec "$container_id" pg_isready -q -U postgres; then ready=true; break; fi
  sleep 1
done
if [ "$ready" != true ]; then echo 'Temporary PostgreSQL fixture did not become ready'; exit 1; fi
if [ -n "${SYN443_GO_IMAGE:-}" ]; then
  # Optional bounded builder for the shared build host; CI uses its pinned Go installation.
  mkdir -p "$PWD/.fixture-cache/mod" "$PWD/.fixture-cache/build"
  docker run --rm --network host --cpus=1 --memory=768m -e GOMAXPROCS=2 -e SYN443_TEST_DATABASE -e PGPASSWORD \
    -v "$PWD:/src" -v "$PWD/.fixture-cache/mod:/go/pkg/mod" \
    -v "$PWD/.fixture-cache/build:/root/.cache/go-build" -w /src "$SYN443_GO_IMAGE" \
    sh -c 'export SYN443_TEST_BINARY_DIR="$PWD/bin"; go build -o bin/enrollment-api ./cmd/enrollment-api && go build -o bin/enrollment-worker ./cmd/enrollment-worker && go test -p 1 -tags postgres -race -count=1 -timeout=2m -coverpkg=./internal/enrollment,./internal/supportchat -coverprofile=enrollment-coverage.out -v ./internal/enrollment ./internal/supportchat'
else
  export SYN443_TEST_BINARY_DIR="$PWD/bin"
  go build -o bin/enrollment-api ./cmd/enrollment-api
  go build -o bin/enrollment-worker ./cmd/enrollment-worker
  go test -tags postgres -race -count=1 -timeout=2m -coverpkg=./internal/enrollment,./internal/supportchat -coverprofile=enrollment-coverage.out -v ./internal/enrollment ./internal/supportchat
fi
