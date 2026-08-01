#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HARNESS="${ROOT}/scripts/native-shell-windows-runtime-smoke.ps1"
SHELL_SOURCE="${ROOT}/desktop/sage-shell/src/main.rs"
test -s "${HARNESS}"
test -s "${SHELL_SOURCE}"

for required in \
  'GetNamedPipeServerProcessId' \
  'CreateFileW' \
  '[uint32]3221225472' \
  'e4ec5178983b20c1' \
  'profileBResult' \
  'profileBPorts[3]' \
  'tls_addr:' \
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SAGE Native Preview' \
  'NamedPipeClientStream' \
  'SAGE_CMT_RPC_ADDR' \
  'SAGE_CMT_P2P_ADDR' \
  'startup_proof' \
  'CloseMainWindow' \
  'Stop-ExactTree' \
  'Stop-LaunchedTree' \
  'Get-ExactProcessHandle' \
  '$firstDaemon' \
  '$reinstallDaemon' \
  'reinstalled bundled daemon did not survive normal shell close' \
  '$Process.Kill($true)' \
  'taskkill.exe /PID' \
  'preserve.sentinel' \
  'Get-AuthenticodeStatusText' \
  'reinstall reused a stale daemon generation' \
  "@('/S', \"/D=\$installRoot\")"; do
  grep -Fq "${required}" "${HARNESS}"
done

# Diagnostic metadata must never be able to fail the harness. A raw
# (Get-AuthenticodeSignature ...).Status read is a TERMINATING error under
# Set-StrictMode when the file is missing or unsupported, which killed an
# otherwise-green run on 2026-07-20.
if grep -Eq '\(Get-AuthenticodeSignature[^)]*\)\.Status' "${HARNESS}"; then
  echo 'Windows runtime harness reads .Status directly off Get-AuthenticodeSignature' >&2
  exit 1
fi
grep -Fq "\$sig.PSObject.Properties['Status']" "${HARNESS}"

if grep -Eq 'taskkill\.exe[[:space:]]+/IM|Get-Process[[:space:]]+sage-gui|Stop-Process[[:space:]]+-Name' "${HARNESS}"; then
  echo 'Windows runtime harness contains broad process-name cleanup' >&2
  exit 1
fi

if grep -Eiq '\$(sage)?home([[:space:]]|[),=])' "${HARNESS}"; then
  echo 'Windows runtime harness shadows the read-only PowerShell HOME variable' >&2
  exit 1
fi

# The Windows renderer can stall before WebviewWindowBuilder::build returns.
# Verified SSCP startup is control-plane work and must already be running by
# then; otherwise the installed-package test can observe a live shell with no
# daemon launch log and no status pipe.
supervisor_line=$(grep -n 'supervisor_ready' "${SHELL_SOURCE}" | tail -1 | cut -d: -f1)
webview_line=$(grep -n 'WebviewWindowBuilder::new' "${SHELL_SOURCE}" | head -1 | cut -d: -f1)
if [ -z "${supervisor_line}" ] || [ -z "${webview_line}" ] || [ "${supervisor_line}" -ge "${webview_line}" ]; then
  echo 'native-shell supervisor must start before WebView construction' >&2
  exit 1
fi

echo 'native-shell Windows runtime harness contract tests passed'
