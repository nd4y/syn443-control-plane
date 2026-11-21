#!/usr/bin/env bash
# Build with an isolated context containing only the verified release binary.
set -euo pipefail
runtime=${1:?control-plane release directory}
output=${2:?new artifact directory}
revision=$(git rev-parse HEAD)
[[ "$revision" =~ ^[0-9a-f]{40}$ && "$(cat "$runtime/SOURCE.txt")" = "$revision" ]]
(cd "$runtime" && sha256sum -c SHA256SUMS)
mkdir -- "$output"
context=$(mktemp -d)
image="syn443-overlay-worker:$revision"
trap 'rm -r -- "$context"' EXIT
install -m 0555 "$runtime/overlay-worker" "$context/overlay-worker"
docker build --platform linux/amd64 --build-arg "VCS_REF=$revision" \
  --file deploy/overlay-worker/Dockerfile --tag "$image" "$context"
docker image inspect "$image" | python3 -c '
import json, sys
image, = json.load(sys.stdin)
config = image["Config"]
assert image["Os"] == "linux" and image["Architecture"] == "amd64"
assert config["User"] == "65532:65532" and config["Entrypoint"] == ["/overlay-worker"] and not config.get("Cmd")
assert config["Labels"]["org.opencontainers.image.revision"] == sys.argv[1]
assert config["Healthcheck"]["Test"] == ["CMD", "/overlay-worker", "--check-ready"]
assert not config.get("Volumes") and not config.get("ExposedPorts")
' "$revision"
set +e
diagnostic=$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$image" --check-ready 2>&1)
missing=$?
set -e
test "$missing" = 1
test "$diagnostic" = overlay_worker_failed
docker save "$image" | gzip -n > "$output/overlay-worker.tar.gz"
python3 tools/verify_overlay_image.py "$output/overlay-worker.tar.gz" "$runtime/overlay-worker" "$image"
printf '%s\n' "$revision" > "$output/SOURCE.txt"
(cd "$output" && sha256sum overlay-worker.tar.gz > SHA256SUMS)
