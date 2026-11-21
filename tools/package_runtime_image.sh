#!/usr/bin/env bash
# Package one scanned runtime with only its public roots and verified executable.
set -euo pipefail
service=${1:?service name}
runtime=${2:?control-plane release directory}
output=${3:?new artifact directory}
revision=$(git rev-parse HEAD)
[[ "$revision" =~ ^[0-9a-f]{40}$ && "$(cat "$runtime/SOURCE.txt")" = "$revision" ]]
(cd "$runtime" && sha256sum -c SHA256SUMS)
context=$(mktemp -d)
trap 'rm -r -- "$context"' EXIT
image="syn443-$service:$revision"
case "$service" in
  overlay-worker)
    expected=overlay_worker_failed
    export SYN443_OVERLAY_IMAGE="$image" SYN443_OVERLAY_CONFIG_FILE="$context/fixture.json" SYN443_BACKEND_NETWORK=fixture
    ;;
  telemetry-ingest)
    expected=telemetry_ingest_unavailable
    export SYN443_TELEMETRY_IMAGE="$image" SYN443_TELEMETRY_PRIVATE_DIR="$context" SYN443_INGRESS_CONTAINER=fixture
    ;;
  support-chat-web)
    expected=chat_web_failed
    export SYN443_CHAT_WEB_IMAGE="$image" SYN443_CHAT_WEB_PRIVATE_DIR="$context" SYN443_INGRESS_CONTAINER=fixture
    ;;
  *) exit 2 ;;
esac
mkdir -- "$output"
install -m 0555 "$runtime/$service" "$context/$service"
docker build --platform linux/amd64 --build-arg "VCS_REF=$revision" \
  --file "deploy/$service/Dockerfile" --tag "$image" "$context"
docker compose -f "deploy/$service/compose.yaml" config --format json | python3 -c '
import json, sys
config = json.load(sys.stdin)
role, expected_image = sys.argv[1:]
s = config["services"][role]
assert s["image"] == expected_image and s["pull_policy"] == "never"
assert s["read_only"] and s["user"] == "65532:65532" and s["cap_drop"] == ["ALL"]
assert not s.get("ports") and not s.get("privileged") and s["pids_limit"] == 64
assert s["restart"] == "unless-stopped" and float(s["cpus"]) == .5
assert str(s["mem_limit"]).lower() in ("134217728", "128m", "128mb", "128mib")
mount, = s["volumes"]
assert mount["type"] == "bind" and mount["read_only"] and not mount["bind"].get("create_host_path", False)
if role == "overlay-worker":
    assert mount["target"] == "/run/secrets/overlay-worker.json" and config["networks"]["backend"]["external"]
else:
    directory = {"telemetry-ingest": "telemetry", "support-chat-web": "web"}[role]
    assert mount["target"] == "/run/syn443/"+directory and s["network_mode"] == "container:fixture"
' "$service" "$image"
docker image inspect "$image" | python3 -c '
import json, sys
image, = json.load(sys.stdin)
role, revision = sys.argv[1:]
c = image["Config"]
assert image["Os"] == "linux" and image["Architecture"] == "amd64"
assert c["User"] == "65532:65532" and c["Entrypoint"] == ["/"+role] and not c.get("Cmd")
assert c["Labels"]["org.opencontainers.image.revision"] == revision
assert c["Healthcheck"]["Test"] == ["CMD", "/"+role, "--check-ready"]
assert not c.get("Volumes") and not c.get("ExposedPorts")
' "$service" "$revision"
set +e
diagnostic=$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$image" --check-ready 2>&1)
status=$?
set -e
[[ "$status" == 1 && "$diagnostic" == "$expected" ]]
docker save "$image" | gzip -n > "$output/$service.tar.gz"
python3 tools/verify_overlay_image.py "$output/$service.tar.gz" "$runtime/$service" "$image" "$service"
printf '%s\n' "$revision" > "$output/SOURCE.txt"
(cd "$output" && sha256sum "$service.tar.gz" > SHA256SUMS)
