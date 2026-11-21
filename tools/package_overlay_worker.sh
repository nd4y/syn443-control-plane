#!/usr/bin/env bash
set -euo pipefail
exec bash tools/package_runtime_image.sh overlay-worker "$@"
