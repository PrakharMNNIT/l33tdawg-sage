#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/sage-tauri-appimage-tools-test.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT INT TERM

manifest_entries=0
while IFS='|' read -r allowed_hashes helper_name helper_url; do
  case ${allowed_hashes} in ''|'#'*) continue ;; esac
  [[ ${allowed_hashes} =~ ^[a-f0-9]{64}(,[a-f0-9]{64})*$ ]]
  [[ ${helper_name} =~ ^[A-Za-z0-9._-]+$ ]]
  [[ ${helper_url} =~ ^https:// ]]
  manifest_entries=$((manifest_entries + 1))
done < "${REPO_ROOT}/scripts/tauri-appimage-tools.sha256"
test "${manifest_entries}" = 5

SOURCE=${TEST_ROOT}/source-helper
MANIFEST=${TEST_ROOT}/manifest
CACHE=${TEST_ROOT}/cache
FAKE_CURL=${TEST_ROOT}/curl
COUNT=${TEST_ROOT}/count
printf 'verified helper bytes\n' > "${SOURCE}"
EXPECTED=$(sha256sum "${SOURCE}" | awk '{print $1}')
printf '%s|helper.AppImage|https://example.invalid/helper.AppImage\n' "${EXPECTED}" > "${MANIFEST}"

printf '%s\n' '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'out=' \
  'while [ "$#" -gt 0 ]; do' \
  '  case "$1" in --output) out=$2; shift 2 ;; *) shift ;; esac' \
  'done' \
  'count=0; [ ! -f "${FAKE_COUNT}" ] || count=$(cat "${FAKE_COUNT}")' \
  'count=$((count + 1)); printf "%s\n" "${count}" > "${FAKE_COUNT}"' \
  'if [ "${FAKE_ALWAYS_FAIL:-0}" = 1 ] || { [ "${FAKE_FAIL_FIRST:-0}" = 1 ] && [ "${count}" = 1 ]; }; then exit 22; fi' \
  'cp "${FAKE_SOURCE}" "${out}"' > "${FAKE_CURL}"
chmod +x "${FAKE_CURL}"

run_prepare() {
  env \
    SAGE_TAURI_APPIMAGE_MANIFEST="${MANIFEST}" \
    SAGE_TAURI_APPIMAGE_CACHE="${CACHE}" \
    SAGE_TAURI_CURL_BIN="${FAKE_CURL}" \
    SAGE_TAURI_RETRY_DELAY_SECONDS=0 \
    FAKE_COUNT="${COUNT}" \
    FAKE_SOURCE="${SOURCE}" \
    "$@" \
    "${REPO_ROOT}/scripts/prepare-tauri-appimage-tools.sh"
}

run_prepare FAKE_FAIL_FIRST=1 > "${TEST_ROOT}/transient.log" 2>&1
test "$(cat "${COUNT}")" = 2
grep -F 'attempt=2/3 verified' "${TEST_ROOT}/transient.log" >/dev/null
test "$(sha256sum "${CACHE}/helper.AppImage" | awk '{print $1}')" = "${EXPECTED}"

run_prepare > "${TEST_ROOT}/hit.log" 2>&1
test "$(cat "${COUNT}")" = 2
grep -F 'cache=hit' "${TEST_ROOT}/hit.log" >/dev/null

printf 'partial corrupt download' > "${CACHE}/helper.AppImage"
run_prepare > "${TEST_ROOT}/corrupt.log" 2>&1
test "$(cat "${COUNT}")" = 3
grep -F 'cache=corrupt' "${TEST_ROOT}/corrupt.log" >/dev/null
test "$(sha256sum "${CACHE}/helper.AppImage" | awk '{print $1}')" = "${EXPECTED}"

rm -f -- "${CACHE}/helper.AppImage"
if run_prepare FAKE_ALWAYS_FAIL=1 > "${TEST_ROOT}/persistent.log" 2>&1; then
  echo 'persistent helper failure unexpectedly succeeded' >&2
  exit 1
fi
test "$(cat "${COUNT}")" = 6
grep -F 'attempt=3/3 curl_status=22' "${TEST_ROOT}/persistent.log" >/dev/null
grep -F 'terminal_failure attempts=3' "${TEST_ROOT}/persistent.log" >/dev/null
test ! -e "${CACHE}/helper.AppImage"

echo 'Tauri AppImage helper retry/cache tests passed'
