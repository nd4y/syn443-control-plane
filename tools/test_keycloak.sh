#!/usr/bin/env bash
# Only ephemeral synthetic fixtures; never use credentials from an existing realm.
set +x
set -euo pipefail
port=${SYN443_KEYCLOAK_TEST_PORT:-17845}
[[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1024 && port <= 65535 ))
export SYN443_TEST_ISSUER="http://127.0.0.1:$port/realms/syn443-test"
export KC_BOOTSTRAP_ADMIN_PASSWORD
KC_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 32)
export SYN443_TEST_ADMIN_PASSWORD="$KC_BOOTSTRAP_ADMIN_PASSWORD"
container_id=''
cleanup() {
  if [ -n "$container_id" ]; then docker rm -f "$container_id" >/dev/null; fi
  unset KC_BOOTSTRAP_ADMIN_PASSWORD SYN443_TEST_ADMIN_PASSWORD
}
trap cleanup EXIT
container_id=$(docker run -d --cpus=1 --memory=640m \
  -p "127.0.0.1:$port:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD \
  -e JAVA_OPTS_KC_HEAP='-Xms64m -Xmx256m -XX:MaxMetaspaceSize=192m' \
  -e KC_HOSTNAME="http://127.0.0.1:$port" \
  -v "$PWD/deploy/keycloak/syn443-test-realm.json:/opt/keycloak/data/import/syn443-test-realm.json:ro" \
  quay.io/keycloak/keycloak@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c \
  start-dev --import-realm)
ready=false
for ((i=0; i<90; i++)); do
  if curl --silent --fail --max-time 2 "$SYN443_TEST_ISSUER/.well-known/openid-configuration" >/dev/null; then ready=true; break; fi
  sleep 1
done
if [ "$ready" != true ]; then echo 'Temporary Keycloak fixture did not become ready'; exit 1; fi
go test -tags keycloak -race -count=1 -timeout=3m -v ./integration/keycloak
