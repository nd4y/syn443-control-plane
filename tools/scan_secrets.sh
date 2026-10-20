#!/usr/bin/env bash
set -euo pipefail
version=8.30.1
digest=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
task_dir=$(mktemp -d)
trap 'rm -rf -- "$task_dir"' EXIT
curl --fail --silent --show-error --location --retry 2 \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz" \
  --output "$task_dir/gitleaks.tar.gz"
printf '%s  %s\n' "$digest" "$task_dir/gitleaks.tar.gz" | sha256sum --check --status
tar -xzf "$task_dir/gitleaks.tar.gz" -C "$task_dir" gitleaks
python3 tools/test_secret_gate.py "$task_dir/gitleaks"
if [ "$#" -eq 0 ]; then
  "$task_dir/gitleaks" git . --log-opts=--all --config .gitleaks.toml --redact=100 --no-banner
else
  for path in "$@"; do
    "$task_dir/gitleaks" dir "$path" --config .gitleaks.toml --redact=100 --no-banner --max-archive-depth=3
  done
fi
