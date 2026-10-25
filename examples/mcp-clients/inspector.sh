#!/bin/sh
# Inspector qualification for the Orcel local client examples.
# Drives tools/list through three independent client paths and checks the
# 44-tool default local profile (desktop_structured) on each. Requires Node.js, this repository checkout (for
# node apps/orcel-mcp/dist), and a orceld binary for ORCEL_DAEMON.
# Fails closed on any mismatch. Uses the loopback bearer from the
# environment; export ORCEL_LOOPBACK_TOKEN first (at least 32 characters).
set -eu

cd "$(dirname "$0")/../.."

: "${ORCEL_LOOPBACK_TOKEN:?export ORCEL_LOOPBACK_TOKEN first}"
ORCELD="${ORCEL_DAEMON:-./target/debug/orceld.exe}"
DIST="apps/orcel-mcp/dist"
EXPECTED="clipboard_read clipboard_write desktop_cursor_get desktop_element_invoke desktop_element_scroll desktop_element_select desktop_element_set_value desktop_element_toggle desktop_input_execute desktop_window_action desktop_window_capture desktop_window_list desktop_window_tree fs_edit fs_find fs_list fs_mkdir fs_move fs_read fs_read_range fs_remove fs_search fs_stat fs_write fs_write_preview git_branch_create git_commit git_diff git_fetch git_fetch_preview git_log git_push git_push_preview git_stage git_status git_unstage process_spawn report_commit report_preview report_start system_status task_resume_summary web_fetch web_search workspace_get"

check() {
  names="$1"
  label="$2"
  if [ "$names" != "$EXPECTED" ]; then
    echo "FAIL $label: got: $names"
    exit 1
  fi
  echo "PASS $label (45 tools)"
}

# Path 1: Inspector CLI over stdio.
out=$(npx -y @modelcontextprotocol/inspector --cli node "$DIST/index.js" \
  --method tools/list -e "ORCEL_DAEMON=$ORCELD" 2>/dev/null \
  | python3 -c "import json,sys; print(' '.join(sorted(t['name'] for t in (lambda t: json.loads(t[t.index(chr(123)):]))(sys.stdin.read())['tools'])))")
check "$out" "inspector-stdio"

# Path 2: Inspector CLI over loopback HTTP.
export ORCEL_LOOPBACK_PORT="${ORCEL_LOOPBACK_PORT:-8377}"
ORCEL_DAEMON="$ORCELD" node "$DIST/entrypoints/loopback_http.js" 2>/dev/null &
srv=$!
cfg=""
trap 'kill $srv 2>/dev/null; [ -n "$cfg" ] && rm -f "$cfg"' EXIT
sleep 4
url="http://127.0.0.1:$ORCEL_LOOPBACK_PORT/mcp"
out=$(npx -y @modelcontextprotocol/inspector --cli --transport http \
  --server-url "$url" --header "Authorization: Bearer $ORCEL_LOOPBACK_TOKEN" \
  --method tools/list 2>/dev/null \
  | python3 -c "import json,sys; print(' '.join(sorted(t['name'] for t in (lambda t: json.loads(t[t.index(chr(123)):]))(sys.stdin.read())['tools'])))")
check "$out" "inspector-http"
kill $srv 2>/dev/null
trap - EXIT

# Path 3: config-file mode with the mcpServers wrapper shape used by
# claude-desktop.json (absolute server entry here because this checkout is
# not an installed release; installed machines use "orcel" on PATH).
cfg="$PWD/$DIST/inspector-smoke-config.json"
winpwd="$(pwd -W)"
printf '{"mcpServers":{"orcel":{"command":"node","args":["%s/%s/index.js"]}}}' \
  "$winpwd" "$DIST" > "$cfg"
out=$(npx -y @modelcontextprotocol/inspector --cli --config "$cfg" \
  --server orcel --method tools/list -e "ORCEL_DAEMON=$ORCELD" 2>"$cfg.err" \
  | python3 -c "import json,sys; print(' '.join(sorted(t['name'] for t in (lambda t: json.loads(t[t.index(chr(123)):]))(sys.stdin.read())['tools'])))") || {
  echo "inspector config mode failed:"
  cat "$cfg.err"
  rm -f "$cfg" "$cfg.err"
  exit 1
}
rm -f "$cfg" "$cfg.err"
check "$out" "inspector-config"