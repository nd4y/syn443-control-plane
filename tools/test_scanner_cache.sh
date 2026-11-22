#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:?requires a disposable Actions runner}"
[[ ${GITHUB_ACTIONS:-} == true ]]
shopt -s nullglob
archives=("$RUNNER_TEMP"/syn443-gitleaks-*.tar.gz)
[[ ${#archives[@]} == 1 && -s ${archives[0]} ]]
fixture=$(mktemp -d "$RUNNER_TEMP/syn443-scanner-test.XXXXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/job"
cp -- "${archives[0]}" "$fixture/job/"
cat > "$fixture/bin/curl" <<'STUB'
#!/usr/bin/env bash
touch "$RUNNER_TEMP/attempted-download"
exit 22
STUB
chmod 700 "$fixture/bin/curl"
export RUNNER_TEMP="$fixture/job"
export PATH="$fixture/bin:$PATH"
bash tools/scan_secrets.sh README.md
[[ ! -e $RUNNER_TEMP/attempted-download ]]
printf '%s\n' 'corrupt public test archive' > "$RUNNER_TEMP/${archives[0]##*/}"
if bash tools/scan_secrets.sh README.md; then
  echo 'corrupt archive unexpectedly passed' >&2
  exit 1
fi
[[ -f $RUNNER_TEMP/attempted-download ]]
