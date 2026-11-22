#!/usr/bin/env bash
set -euo pipefail
version=8.30.1
digest=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
scratch_root=${TMPDIR:-/tmp}
cache=''
if [[ ${GITHUB_ACTIONS:-} == true && -n ${RUNNER_TEMP:-} ]]; then
  scratch_root=$RUNNER_TEMP
  cache="$scratch_root/syn443-gitleaks-${version}-${digest}.tar.gz"
fi
task_dir=$(mktemp -d "$scratch_root/syn443-secret-scan.XXXXXXXX")
trap 'rm -rf -- "$task_dir"' EXIT
archive="$task_dir/gitleaks.tar.gz"
verified() {
  printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status
}
# Use a private copy so the bytes verified are the same bytes extracted.
if [[ -z $cache ]] || ! cp -- "$cache" "$archive" 2>/dev/null || ! verified; then
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --retry 2 --retry-all-errors --retry-max-time 75 --connect-timeout 10 --max-time 45 \
    "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz" \
    --output "$archive"
  verified
  if [[ -n $cache ]]; then
    cp -- "$archive" "$task_dir/verified.tar.gz"
    mv -fT -- "$task_dir/verified.tar.gz" "$cache"
  fi
fi
tar -xzf "$task_dir/gitleaks.tar.gz" -C "$task_dir" gitleaks
python3 tools/verify_secret_gate.py "$task_dir/gitleaks"
if [ "$#" -eq 0 ]; then
  "$task_dir/gitleaks" git . --log-opts=--all --config .gitleaks.toml --redact=100 --no-banner
else
  python3 tools/check_apk_secrets.py "$task_dir/gitleaks" "$@"
  for path in "$@"; do
    if "$task_dir/gitleaks" dir "$path" --config .gitleaks.toml --redact=100 --no-banner --max-archive-depth=3 \
      --report-format json --report-path "$task_dir/findings.json"; then
      :
    else
      status=$?
      python3 tools/summarize_secret_findings.py "$task_dir/findings.json" || true
      exit "$status"
    fi
  done
fi
