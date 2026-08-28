#!/usr/bin/env bash
set -u

M3E_SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
M3E_REPO_ROOT="$(CDPATH= cd -- "$M3E_SCRIPT_DIR/../.." && pwd)"
M3E_REQUIREMENTS="$M3E_SCRIPT_DIR/requirements-m3e-vault-browser.txt"
M3E_PROOF="$M3E_SCRIPT_DIR/m3e_vault_webkit.py"
M3E_PORT="4178"
M3E_BROWSER_SELECTION="all"
M3E_PREPARE_ONLY="false"
M3E_VITE_PID=""
M3E_VITE_LOG="$(mktemp -t nomad-m3e-vite.XXXXXX)"

emit_block() {
  printf '{"status":"BLOCK","code":"%s","detail":"%s"}\n' "$1" "$2"
}

cleanup() {
  if [[ -n "$M3E_VITE_PID" ]] && kill -0 "$M3E_VITE_PID" 2>/dev/null; then
    kill "$M3E_VITE_PID" 2>/dev/null || true
    wait "$M3E_VITE_PID" 2>/dev/null || true
  fi
  rm -f "$M3E_VITE_LOG"
}
trap cleanup EXIT INT TERM

append_loopback_no_proxy() {
  local current="$1"
  local host
  for host in 127.0.0.1 localhost; do
    if [[ ",$current," != *",$host,"* ]]; then
      if [[ -n "$current" ]]; then
        current="$current,$host"
      else
        current="$host"
      fi
    fi
  done
  printf '%s' "$current"
}

usage() {
  printf '%s\n' \
    'Usage: bash testkit/browser/run_m3e_vault_browser.sh [options]' \
    '' \
    'Options:' \
    '  --browser chromium|webkit|all  Browser proof to run (default: all)' \
    '  --prepare-only                 Install pinned browser executables only' \
    '  --help                         Show this help' \
    '' \
    'Environment:' \
    '  PLAYWRIGHT_BROWSERS_PATH  Explicit executable cache override' \
    '  M3E_VAULT_PORT            Local Vite port override'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --browser)
      if [[ $# -lt 2 ]]; then
        emit_block 'M3E_BROWSER_BLOCK_USAGE' 'missing_browser_value'
        exit 2
      fi
      M3E_BROWSER_SELECTION="$2"
      shift 2
      ;;
    --prepare-only)
      M3E_PREPARE_ONLY="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      emit_block 'M3E_BROWSER_BLOCK_USAGE' 'unknown_argument'
      exit 2
      ;;
  esac
done

if [[ "$M3E_BROWSER_SELECTION" != 'all' && "$M3E_BROWSER_SELECTION" != 'chromium' && "$M3E_BROWSER_SELECTION" != 'webkit' ]]; then
  emit_block 'M3E_BROWSER_BLOCK_USAGE' 'unsupported_browser'
  exit 2
fi
if ! command -v uv >/dev/null 2>&1; then
  emit_block 'M3E_BROWSER_BLOCK_UV_MISSING' 'install_uv_0.11_or_newer'
  exit 2
fi
if ! command -v pnpm >/dev/null 2>&1; then
  emit_block 'M3E_BROWSER_BLOCK_PNPM_MISSING' 'pnpm_is_required_to_start_vite'
  exit 2
fi

if [[ -n "${PLAYWRIGHT_BROWSERS_PATH:-}" ]]; then
  M3E_BROWSER_CACHE="$PLAYWRIGHT_BROWSERS_PATH"
else
  M3E_BROWSER_CACHE="$HOME/.cache/nomad-playwright-1.62.0"
fi
if [[ -n "${M3E_VAULT_PORT:-}" ]]; then
  M3E_PORT="$M3E_VAULT_PORT"
fi
export PLAYWRIGHT_BROWSERS_PATH="$M3E_BROWSER_CACHE"
export NO_PROXY="$(append_loopback_no_proxy "${NO_PROXY:-}")"
export no_proxy="$(append_loopback_no_proxy "${no_proxy:-}")"

run_python() {
  uv run --isolated --no-project --with-requirements "$M3E_REQUIREMENTS" "$@"
}

if ! run_python python -c "import importlib.metadata; assert importlib.metadata.version('playwright') == '1.62.0'"; then
  emit_block 'M3E_BROWSER_BLOCK_DEPENDENCY_PREPARE' 'playwright_1.62.0_resolution_failed'
  exit 2
fi
if ! run_python python -m playwright install chromium webkit; then
  emit_block 'M3E_BROWSER_BLOCK_EXECUTABLE_PREPARE' "cache=$M3E_BROWSER_CACHE"
  exit 2
fi
printf '{"status":"PREPARED","playwrightVersion":"1.62.0","browserCache":"%s"}\n' "$M3E_BROWSER_CACHE"
if [[ "$M3E_PREPARE_ONLY" == 'true' ]]; then
  exit 0
fi

start_vite() {
  if [[ -n "$M3E_VITE_PID" ]] && kill -0 "$M3E_VITE_PID" 2>/dev/null; then
    return 0
  fi
  : >"$M3E_VITE_LOG"
(
  cd "$M3E_REPO_ROOT/mobile-reference" || exit 1
  exec ./node_modules/.bin/vite --host 127.0.0.1 --port "$M3E_PORT" --strictPort
) >"$M3E_VITE_LOG" 2>&1 &
M3E_VITE_PID="$!"

M3E_READY="false"
for _ in {1..100}; do
  if ! kill -0 "$M3E_VITE_PID" 2>/dev/null; then
    break
  fi
  if curl --noproxy '*' --fail --silent --show-error "http://127.0.0.1:$M3E_PORT/" >/dev/null 2>&1; then
    M3E_READY="true"
    break
  fi
  sleep 0.1
done
if [[ "$M3E_READY" != 'true' ]]; then
  emit_block 'M3E_BROWSER_BLOCK_VITE_START' "log=$M3E_VITE_LOG"
  return 2
fi
}

ensure_vite_ready() {
  if [[ -n "$M3E_VITE_PID" ]] \
      && kill -0 "$M3E_VITE_PID" 2>/dev/null \
      && curl --noproxy '*' --fail --silent --show-error "http://127.0.0.1:$M3E_PORT/" >/dev/null 2>&1; then
    return 0
  fi
  M3E_VITE_PID=""
  start_vite
}

if ! start_vite; then
  exit 2
fi

run_browser() {
  if ! ensure_vite_ready; then
    emit_block 'M3E_BROWSER_BLOCK_VITE_HEALTH' "browser=$1"
    exit 2
  fi
  if ! run_python python "$M3E_PROOF" --browser "$1" --base-url "http://127.0.0.1:$M3E_PORT"; then
    emit_block 'M3E_BROWSER_BLOCK_PROOF' "browser=$1"
    exit 2
  fi
}

if [[ "$M3E_BROWSER_SELECTION" == 'all' || "$M3E_BROWSER_SELECTION" == 'chromium' ]]; then
  run_browser chromium
fi
if [[ "$M3E_BROWSER_SELECTION" == 'all' || "$M3E_BROWSER_SELECTION" == 'webkit' ]]; then
  run_browser webkit
fi

printf '{"status":"PASS","browsers":"%s","physicalIPhone":"NOT_RUN"}\n' "$M3E_BROWSER_SELECTION"
