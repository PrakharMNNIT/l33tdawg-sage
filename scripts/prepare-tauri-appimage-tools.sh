#!/usr/bin/env bash
# Populate Tauri's AppImage helper directory through a bounded, verified,
# atomic cache. Tauri skips its own one-shot downloads when these exact files
# exist, so transient upstream failures cannot discard an otherwise healthy
# Linux package build.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
TOOLS_MANIFEST=${SAGE_TAURI_APPIMAGE_MANIFEST:-${REPO_ROOT}/scripts/tauri-appimage-tools.sha256}
TOOLS_CACHE=${SAGE_TAURI_APPIMAGE_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/tauri}
CURL_BIN=${SAGE_TAURI_CURL_BIN:-curl}
MAX_ATTEMPTS=3
BASE_DELAY=${SAGE_TAURI_RETRY_DELAY_SECONDS:-1}

case ${BASE_DELAY} in
  ''|*[!0-9]*) echo "tauri-appimage-tools: retry delay must be an integer" >&2; exit 2 ;;
esac
if [ "${BASE_DELAY}" -gt 10 ]; then
  echo "tauri-appimage-tools: retry delay must not exceed 10 seconds" >&2
  exit 2
fi
if [ ! -f "${TOOLS_MANIFEST}" ]; then
  echo "tauri-appimage-tools: manifest not found: ${TOOLS_MANIFEST}" >&2
  exit 2
fi

mkdir -p "${TOOLS_CACHE}"
LOCK_DIR=${TOOLS_CACHE}/.sage-appimage-tools.lock
lock_attempt=1
while ! mkdir "${LOCK_DIR}" 2>/dev/null; do
  if [ "${lock_attempt}" -ge 20 ]; then
    echo "tauri-appimage-tools: cache lock remained busy after ${lock_attempt} attempts" >&2
    exit 1
  fi
  sleep 1
  lock_attempt=$((lock_attempt + 1))
done

TEMP_FILES=()
cleanup() {
  for temp_file in "${TEMP_FILES[@]:-}"; do
    rm -f -- "${temp_file}"
  done
  rmdir -- "${LOCK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

hash_allowed() {
  local actual=$1 allowed=$2 candidate
  IFS=',' read -r -a candidates <<< "${allowed}"
  for candidate in "${candidates[@]}"; do
    if [ "${actual}" = "${candidate}" ]; then
      return 0
    fi
  done
  return 1
}

while IFS='|' read -r allowed_hashes helper_name helper_url; do
  case ${allowed_hashes} in ''|'#'*) continue ;; esac
  if [[ ! ${allowed_hashes} =~ ^[a-f0-9]{64}(,[a-f0-9]{64})*$ ]] ||
     [[ ! ${helper_name} =~ ^[A-Za-z0-9._-]+$ ]] ||
     [[ ! ${helper_url} =~ ^https:// ]]; then
    echo "tauri-appimage-tools: invalid manifest entry for ${helper_name:-unknown}" >&2
    exit 2
  fi

  target=${TOOLS_CACHE}/${helper_name}
  if [ -f "${target}" ]; then
    actual_hash=$(hash_file "${target}")
    if hash_allowed "${actual_hash}" "${allowed_hashes}"; then
      chmod 0755 "${target}"
      echo "tauri-appimage-tools: helper=${helper_name} cache=hit sha256=${actual_hash}"
      continue
    fi
    echo "tauri-appimage-tools: helper=${helper_name} cache=corrupt sha256=${actual_hash}; replacing"
    rm -f -- "${target}"
  else
    echo "tauri-appimage-tools: helper=${helper_name} cache=miss"
  fi

  downloaded=false
  attempt=1
  while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
    temp_file=$(mktemp "${TOOLS_CACHE}/.${helper_name}.download.XXXXXX")
    TEMP_FILES+=("${temp_file}")
    echo "tauri-appimage-tools: helper=${helper_name} attempt=${attempt}/${MAX_ATTEMPTS} downloading"
    if "${CURL_BIN}" --location --fail --silent --show-error \
        --connect-timeout 20 --max-time 180 \
        --output "${temp_file}" "${helper_url}"; then
      actual_hash=$(hash_file "${temp_file}")
      if hash_allowed "${actual_hash}" "${allowed_hashes}"; then
        chmod 0755 "${temp_file}"
        mv -f -- "${temp_file}" "${target}"
        echo "tauri-appimage-tools: helper=${helper_name} attempt=${attempt}/${MAX_ATTEMPTS} verified sha256=${actual_hash}"
        downloaded=true
        break
      fi
      echo "tauri-appimage-tools: helper=${helper_name} attempt=${attempt}/${MAX_ATTEMPTS} checksum_mismatch sha256=${actual_hash}" >&2
    else
      curl_status=$?
      echo "tauri-appimage-tools: helper=${helper_name} attempt=${attempt}/${MAX_ATTEMPTS} curl_status=${curl_status}" >&2
    fi
    rm -f -- "${temp_file}"
    if [ "${attempt}" -lt "${MAX_ATTEMPTS}" ] && [ "${BASE_DELAY}" -gt 0 ]; then
      sleep $((BASE_DELAY * attempt))
    fi
    attempt=$((attempt + 1))
  done

  if [ "${downloaded}" != true ]; then
    echo "tauri-appimage-tools: helper=${helper_name} terminal_failure attempts=${MAX_ATTEMPTS} url=${helper_url}" >&2
    exit 1
  fi
done < "${TOOLS_MANIFEST}"

echo "tauri-appimage-tools: verified cache ready at ${TOOLS_CACHE}"
