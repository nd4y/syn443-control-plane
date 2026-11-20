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
tls_dir=$(mktemp -d)
cleanup() {
  if [ -n "$container_id" ]; then docker rm -f -v "$container_id" >/dev/null; fi
  rm -f -- "$tls_dir"/{ca.key,ca.crt,server.key,server.csr,server.crt,extensions}
  rmdir -- "$tls_dir"
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
if [ "$ready" != true ]; then echo 'Temporary PostgreSQL fixture did not become ready'; exit 1; fi

# Only the disposable PostgreSQL container receives this short-lived server key.
# Both trust files and credentials remain outside the checkout and CI artifacts.
(
  umask 077
  cd "$tls_dir"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj '/CN=SYN443 test CA' -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj '/CN=localhost' -keyout server.key -out server.csr 2>/dev/null
  printf '%s\n' 'basicConstraints=CA:FALSE' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' > extensions
  openssl x509 -req -days 1 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 1 \
    -extfile extensions -out server.crt 2>/dev/null
)
docker cp "$tls_dir/server.crt" "$container_id:/tmp/syn443-server.crt"
docker cp "$tls_dir/server.key" "$container_id:/tmp/syn443-server.key"
docker exec --user root "$container_id" chown postgres /tmp/syn443-server.crt /tmp/syn443-server.key
docker exec --user root "$container_id" chmod 0600 /tmp/syn443-server.key
docker exec "$container_id" psql -X -U postgres -v ON_ERROR_STOP=1 \
  -c "ALTER SYSTEM SET ssl_cert_file = '/tmp/syn443-server.crt'" \
  -c "ALTER SYSTEM SET ssl_key_file = '/tmp/syn443-server.key'" \
  -c "ALTER SYSTEM SET ssl = 'on'" -c 'SELECT pg_reload_conf()' >/dev/null
export SYN443_TEST_DATABASE_CA="$tls_dir/ca.crt"
if [ -n "${SYN443_GO_IMAGE:-}" ]; then
  # Optional bounded builder for the shared build host; CI uses its pinned Go installation.
  mkdir -p "$PWD/.fixture-cache/mod" "$PWD/.fixture-cache/build"
  docker run --rm --network host --cpus=1 --memory=768m -e GOMAXPROCS=2 -e SYN443_TEST_DATABASE -e PGPASSWORD \
    -e SYN443_TEST_DATABASE_CA=/tmp/syn443-fixture-ca.crt \
    -v "$tls_dir/ca.crt:/tmp/syn443-fixture-ca.crt:ro" \
    -v "$PWD:/src" -v "$PWD/.fixture-cache/mod:/go/pkg/mod" \
    -v "$PWD/.fixture-cache/build:/root/.cache/go-build" -w /src "$SYN443_GO_IMAGE" \
    sh -c 'export SYN443_TEST_BINARY_DIR="$PWD/bin"; go build -o bin/enrollment-api ./cmd/enrollment-api && go build -o bin/enrollment-worker ./cmd/enrollment-worker && go build -o bin/enrollment-admin ./cmd/enrollment-admin && go build -o bin/overlay-worker ./cmd/overlay-worker && go test -p 1 -tags postgres -race -count=1 -timeout=2m -coverpkg=./internal/enrollment,./internal/supportchat -coverprofile=enrollment-coverage.out -v ./internal/enrollment ./internal/supportchat'
else
  export SYN443_TEST_BINARY_DIR="$PWD/bin"
  export SYN443_RESTORE_FIXTURE_CONTAINER="$container_id"
  go build -o bin/enrollment-api ./cmd/enrollment-api
  go build -o bin/enrollment-worker ./cmd/enrollment-worker
  go build -o bin/enrollment-admin ./cmd/enrollment-admin
  go build -o bin/overlay-worker ./cmd/overlay-worker
  go test -tags postgres -race -count=1 -timeout=2m -coverpkg=./internal/enrollment,./internal/supportchat -coverprofile=enrollment-coverage.out -v ./internal/enrollment ./internal/supportchat
fi
