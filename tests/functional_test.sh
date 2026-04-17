#!/usr/bin/env bash
# Black-box functional tests for anno-server + anno-client.
# Usage:
#   ./tests/functional_test.sh              # run all tests
#   ./tests/functional_test.sh T01 T03      # run selected tests
#
# Requirements: bash, curl, python3, kill, timeout (coreutils)

set -euo pipefail

: "${TMPDIR:=/tmp}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Ports (avoid well-known ranges)
export CTRL_PORT="${CTRL_PORT:-19000}"
export API_PORT="${API_PORT:-19080}"
export MAP_TCP="${MAP_TCP:-19001}"
export MAP_UDP="${MAP_UDP:-19002}"
export ECHO_TCP="${ECHO_TCP:-19100}"
export ECHO_UDP="${ECHO_UDP:-19101}"
# TCP endpoint that accepts and holds each connection open (for session-limit tests)
export HOLD_TCP="${HOLD_TCP:-19102}"

SERVER_BIN="${SERVER_BIN:-$ROOT/target/debug/anno-server}"
CLIENT_BIN="${CLIENT_BIN:-$ROOT/target/debug/anno-client}"

API_BASE="http://127.0.0.1:${API_PORT}"
TOTAL=0
PASS=0
FAIL=0
FAILED_TESTS=()

# --- embedded Python helpers (no nc/socat required) ---
py_tcp_echo_server() {
  python3 - "$ECHO_TCP" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
while True:
    c, _ = s.accept()
    try:
        data = c.recv(65536)
        if data:
            c.sendall(data)
    finally:
        c.close()
PY
}

py_udp_echo_server() {
  python3 - "$ECHO_UDP" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
while True:
    data, addr = s.recvfrom(65536)
    if data:
        s.sendto(data, addr)
PY
}

# args: host port message -> prints one line of received bytes as repr
py_tcp_client() {
  python3 - "$@" <<'PY'
import socket, sys
host, port, msg = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(30)
s.connect((host, port))
s.sendall(msg)
data = s.recv(65536)
sys.stdout.buffer.write(data)
s.close()
PY
}

py_udp_client() {
  python3 - "$@" <<'PY'
import socket, sys
host, port, msg = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)
s.sendto(msg, (host, port))
data, _ = s.recvfrom(65536)
sys.stdout.buffer.write(data)
s.close()
PY
}

# Accepts TCP connections and blocks in recv() forever per connection (keeps tunnel session alive).
py_tcp_blackhole_server() {
  python3 - "$HOLD_TCP" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(32)

def handle(c):
    try:
        while True:
            c.recv(65536)
    except Exception:
        pass
    finally:
        c.close()

while True:
    c, a = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
}

# Long-lived TCP connection (keeps socket open until SIGTERM)
py_tcp_hold() {
  python3 - "$@" <<'PY'
import socket, sys, signal
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
signal.pause()  # wait for kill
PY
}

wait_tcp_port() {
  local host="$1" port="$2" deadline=$(( $(date +%s) + ${3:-30} ))
  while (( $(date +%s) < deadline )); do
    if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('$host',$port)); s.close()" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

api_get() {
  curl -fsS "$API_BASE$1"
}

api_post_json() {
  curl -fsS -X POST "$API_BASE$1" -H "Content-Type: application/json" -d "$2"
}

api_delete() {
  curl -fsS -X DELETE "$API_BASE$1"
}

# Count clients with status online (JSON array from /api/clients)
count_online_clients() {
  api_get "/api/clients" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for c in d if c.get('status')=='online'))"
}

wait_online_clients() {
  local want="$1" deadline=$(( $(date +%s) + ${2:-45} ))
  while (( $(date +%s) < deadline )); do
    local n
    n="$(count_online_clients 2>/dev/null || echo 0)"
    if [[ "$n" == "$want" ]]; then
      return 0
    fi
    sleep 0.3
  done
  return 1
}

cleanup() {
  pkill -f "anno-server.*--control 127.0.0.1:${CTRL_PORT}" 2>/dev/null || true
  pkill -f "anno-client.*--server 127.0.0.1:${CTRL_PORT}" 2>/dev/null || true
  pkill -f "python3 -.*${ECHO_TCP}" 2>/dev/null || true
  pkill -f "python3 -.*${ECHO_UDP}" 2>/dev/null || true
  pkill -f "python3 -.*${HOLD_TCP}" 2>/dev/null || true
  sleep 0.3
}
trap cleanup EXIT

build() {
  echo "[build] cargo build --workspace"
  cargo build --workspace -q
}

start_server() {
  local regfile="$1"
  shift
  cleanup
  RUST_LOG="${RUST_LOG:-warn}" "$SERVER_BIN" \
    --control "127.0.0.1:${CTRL_PORT}" \
    --api "127.0.0.1:${API_PORT}" \
    --registry-file "$regfile" \
    "$@" &
  SERVER_PID=$!
  wait_tcp_port 127.0.0.1 "$API_PORT" 30
  wait_tcp_port 127.0.0.1 "$CTRL_PORT" 30
}

stop_server_graceful() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

kill_server_hard() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -9 "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

start_client() {
  local key="$1"
  local log="$2"
  RUST_LOG="${RUST_LOG:-warn}" "$CLIENT_BIN" \
    --server "127.0.0.1:${CTRL_PORT}" \
    --key "$key" >>"$log" 2>&1 &
}

registry_create() {
  local name="$1"
  api_post_json "/api/registry" "{\"name\":\"$name\",\"description\":\"test\"}"
}

get_client_id_by_name() {
  local name="$1"
  api_get "/api/clients" | python3 -c "import sys,json; d=json.load(sys.stdin);
for c in d:
  if c['name']==sys.argv[1]: print(c['id']); sys.exit(0)
sys.exit(1)" "$name"
}

# Call after the client has connected (registry entry must exist and client online).
wait_client_id() {
  local name="$1"
  local deadline=$(( $(date +%s) + ${2:-30} ))
  while (( $(date +%s) < deadline )); do
    if cid="$(api_get "/api/clients" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin);
for c in d:
  if c['name']==sys.argv[1]: print(c['id']); sys.exit(0)
sys.exit(1)" "$name" 2>/dev/null)"; then
      echo "$cid"
      return 0
    fi
    sleep 0.3
  done
  return 1
}

add_mapping_tcp() {
  local cid="$1" sport="$2" tport="$3"
  api_post_json "/api/clients/${cid}/mappings" \
    "{\"server_port\":${sport},\"protocol\":\"tcp\",\"target_host\":\"127.0.0.1\",\"target_port\":${tport}}" \
    >/dev/null
}

add_mapping_udp() {
  local cid="$1" sport="$2" tport="$3"
  api_post_json "/api/clients/${cid}/mappings" \
    "{\"server_port\":${sport},\"protocol\":\"udp\",\"target_host\":\"127.0.0.1\",\"target_port\":${tport}}" \
    >/dev/null
}

delete_mapping() {
  local cid="$1" sport="$2"
  api_delete "/api/clients/${cid}/mappings/${sport}"
}

run_test() {
  local id="$1" name="$2"
  shift 2
  TOTAL=$((TOTAL + 1))
  echo ""
  echo "========== ${id} ${name} =========="
  if "$@"; then
    echo "PASS  ${id} ${name}"
    PASS=$((PASS + 1))
  else
    echo "FAIL  ${id} ${name}"
    FAIL=$((FAIL + 1))
    FAILED_TESTS+=("${id} ${name}")
  fi
}

# --- Test cases ---

test_T01_basic_tcp() {
  local reg="$TMPDIR/anno_ft_reg_$$.json"
  rm -f "$reg"
  start_server "$reg"
  local resp key cid
  resp="$(registry_create "ft-tcp")"
  key="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"

  py_tcp_echo_server &
  ECHO_PID=$!
  sleep 0.3

  local clog="$TMPDIR/anno_ft_cl_$$.log"
  start_client "$key" "$clog"
  CLIENT_PID=$!
  wait_online_clients 1 30
  cid="$(wait_client_id "ft-tcp" 30)"

  add_mapping_tcp "$cid" "$MAP_TCP" "$ECHO_TCP"
  sleep 0.8

  local out
  out="$(py_tcp_client 127.0.0.1 "$MAP_TCP" "hello-tcp")"
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  kill "$ECHO_PID" 2>/dev/null || true

  [[ "$out" == "hello-tcp" ]]
}

test_T02_basic_udp() {
  local reg="$TMPDIR/anno_ft_reg2_$$.json"
  rm -f "$reg"
  start_server "$reg"
  local resp key cid
  resp="$(registry_create "ft-udp")"
  key="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"

  py_udp_echo_server &
  ECHO_PID=$!
  sleep 0.3

  local clog="$TMPDIR/anno_ft_cl2_$$.log"
  start_client "$key" "$clog"
  CLIENT_PID=$!
  wait_online_clients 1 30
  cid="$(wait_client_id "ft-udp" 30)"

  add_mapping_udp "$cid" "$MAP_UDP" "$ECHO_UDP"
  sleep 0.8

  local out
  out="$(py_udp_client 127.0.0.1 "$MAP_UDP" "ping-udp")"
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  kill "$ECHO_PID" 2>/dev/null || true

  [[ "$out" == "ping-udp" ]]
}

test_T03_server_restart_reconnect() {
  local reg="$TMPDIR/anno_ft_reg3_$$.json"
  rm -f "$reg"
  start_server "$reg"
  local resp key cid
  resp="$(registry_create "ft-rst")"
  key="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"

  py_tcp_echo_server &
  ECHO_PID=$!
  sleep 0.3

  local clog="$TMPDIR/anno_ft_cl3_$$.log"
  start_client "$key" "$clog"
  CLIENT_PID=$!
  wait_online_clients 1 30
  cid="$(wait_client_id "ft-rst" 30)"
  add_mapping_tcp "$cid" "$MAP_TCP" "$ECHO_TCP"
  sleep 0.8
  [[ "$(py_tcp_client 127.0.0.1 "$MAP_TCP" "a")" == "a" ]]

  kill_server_hard
  sleep 0.5
  start_server "$reg"
  wait_online_clients 1 60

  [[ "$(py_tcp_client 127.0.0.1 "$MAP_TCP" "b")" == "b" ]]

  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  kill "$ECHO_PID" 2>/dev/null || true
}

test_T04_duplicate_register() {
  local reg="$TMPDIR/anno_ft_reg4_$$.json"
  rm -f "$reg"
  start_server "$reg"
  local resp key cid
  resp="$(registry_create "ft-dup")"
  key="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"
  cid="$(get_client_id_by_name "ft-dup")"

  local c1="$TMPDIR/ft_c1_$$.log"
  local c2="$TMPDIR/ft_c2_$$.log"
  start_client "$key" "$c1"
  P1=$!
  wait_online_clients 1 30

  start_client "$key" "$c2"
  P2=$!
  sleep 2
  wait_online_clients 1 15

  kill "$P1" 2>/dev/null || true
  wait "$P1" 2>/dev/null || true
  sleep 1
  [[ "$(count_online_clients)" == "1" ]]

  kill "$P2" 2>/dev/null || true
  wait "$P2" 2>/dev/null || true
}

test_T05_invalid_key() {
  local reg="$TMPDIR/anno_ft_reg5_$$.json"
  rm -f "$reg"
  start_server "$reg"
  registry_create "ft-ok" >/dev/null

  set +e
  RUST_LOG=error "$CLIENT_BIN" --server "127.0.0.1:${CTRL_PORT}" --key "00000000-0000-0000-0000-000000000000" >/dev/null 2>&1
  local ec=$?
  set -e
  [[ "$ec" == 2 ]]
}

test_T06_max_control_connections() {
  local reg="$TMPDIR/anno_ft_reg6_$$.json"
  rm -f "$reg"
  cleanup
  RUST_LOG=warn "$SERVER_BIN" \
    --control "127.0.0.1:${CTRL_PORT}" \
    --api "127.0.0.1:${API_PORT}" \
    --registry-file "$reg" \
    --max-control-connections 1 \
    &
  SERVER_PID=$!
  wait_tcp_port 127.0.0.1 "$API_PORT" 30
  wait_tcp_port 127.0.0.1 "$CTRL_PORT" 30

  local a b
  a="$(registry_create "ft-a")"
  b="$(registry_create "ft-b")"
  local ka kb
  ka="$(echo "$a" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"
  kb="$(echo "$b" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"

  local la="$TMPDIR/ft_la_$$.log" lb="$TMPDIR/ft_lb_$$.log"
  start_client "$ka" "$la"
  PA=$!
  wait_online_clients 1 30

  start_client "$kb" "$lb"
  PB=$!
  sleep 3
  # Second client must not be online simultaneously
  [[ "$(count_online_clients)" == "1" ]] || return 1

  kill "$PB" 2>/dev/null || true
  wait "$PB" 2>/dev/null || true
  kill "$PA" 2>/dev/null || true
  wait "$PA" 2>/dev/null || true
}

test_T07_per_client_session_limit() {
  local reg="$TMPDIR/anno_ft_reg7_$$.json"
  rm -f "$reg"
  # Limit 1: first public TCP session stays open against a blackhole target;
  # second incoming TCP must be rejected at accept side.
  start_server "$reg" --max-sessions-per-client 1
  local resp key cid
  resp="$(registry_create "ft-slim")"
  key="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"

  py_tcp_blackhole_server &
  local bh_pid=$!
  sleep 0.4

  local clog="$TMPDIR/ft_slim_$$.log"
  start_client "$key" "$clog"
  CLIENT_PID=$!
  wait_online_clients 1 30
  cid="$(wait_client_id "ft-slim" 30)"
  add_mapping_tcp "$cid" "$MAP_TCP" "$HOLD_TCP"
  sleep 1.0

  # First connection stays open (tunnel session counts toward limit).
  python3 - "$MAP_TCP" <<'PY' &
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(30)
s.connect(("127.0.0.1", port))
s.sendall(b"hold")
import time
time.sleep(600)
PY
  local hold_pid=$!
  sleep 2.0

  # Second connect should be shut down by server (RST/EOF/reset).
  python3 - "$MAP_TCP" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(5)
try:
    s.connect(("127.0.0.1", port))
    s.sendall(b"x")
    chunk = s.recv(16)
    sys.exit(0 if chunk == b"" else 3)
except (ConnectionRefusedError, BrokenPipeError, ConnectionResetError, OSError):
    sys.exit(0)
except socket.timeout:
    sys.exit(1)
PY
  local second_ec=$?

  kill "$hold_pid" 2>/dev/null || true
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  kill "$bh_pid" 2>/dev/null || true

  [[ "$second_ec" == 0 ]]
}

test_T08_port_reuseaddr() {
  local reg="$TMPDIR/anno_ft_reg8_$$.json"
  rm -f "$reg"
  start_server "$reg"
  local resp key cid
  resp="$(registry_create "ft-reuse")"
  key="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"

  py_tcp_echo_server &
  ECHO_PID=$!
  sleep 0.3
  local clog="$TMPDIR/ft_reuse_$$.log"
  start_client "$key" "$clog"
  CLIENT_PID=$!
  wait_online_clients 1 30
  cid="$(wait_client_id "ft-reuse" 30)"

  add_mapping_tcp "$cid" "$MAP_TCP" "$ECHO_TCP"
  sleep 0.5
  [[ "$(py_tcp_client 127.0.0.1 "$MAP_TCP" "1")" == "1" ]]

  delete_mapping "$cid" "$MAP_TCP"
  sleep 0.5
  add_mapping_tcp "$cid" "$MAP_TCP" "$ECHO_TCP"
  sleep 0.8
  [[ "$(py_tcp_client 127.0.0.1 "$MAP_TCP" "2")" == "2" ]]

  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  kill "$ECHO_PID" 2>/dev/null || true
}

test_T09_registry_api() {
  local reg="$TMPDIR/anno_ft_reg9_$$.json"
  rm -f "$reg"
  start_server "$reg"

  api_post_json "/api/registry" '{"name":"reg-x","description":"d"}' >/dev/null
  api_get "/api/registry/reg-x" | python3 -c "import sys,json; assert json.load(sys.stdin)['name']=='reg-x'"

  local oldkey newkey
  oldkey="$(api_get "/api/registry/reg-x" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"
  api_post_json "/api/registry/reg-x/regenerate-key" '{}' >/dev/null
  newkey="$(api_get "/api/registry/reg-x" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")"
  [[ "$oldkey" != "$newkey" ]] || return 1

  set +e
  RUST_LOG=error "$CLIENT_BIN" --server "127.0.0.1:${CTRL_PORT}" --key "$oldkey" >/dev/null 2>&1
  local ec_old=$?
  set -e
  [[ "$ec_old" == 2 ]] || return 1

  RUST_LOG=error "$CLIENT_BIN" --server "127.0.0.1:${CTRL_PORT}" --key "$newkey" >/dev/null 2>&1 &
  local pc=$!
  sleep 2
  kill "$pc" 2>/dev/null || true
  wait "$pc" 2>/dev/null || true

  api_delete "/api/registry/reg-x"
}

test_T10_graceful_shutdown() {
  local reg="$TMPDIR/anno_ft_reg10_$$.json"
  rm -f "$reg"
  echo '{"clients":[]}' >"$reg"
  start_server "$reg"
  registry_create "ft-term" >/dev/null
  stop_server_graceful
  python3 -c "import json; d=json.load(open('$reg')); assert isinstance(d.get('clients'), list)"
}

# --- main ---

TESTS=( "$@" )
if [[ ${#TESTS[@]} -eq 0 ]]; then
  TESTS=(T01 T02 T03 T04 T05 T06 T07 T08 T09 T10)
fi

build

for t in "${TESTS[@]}"; do
  case "$t" in
    T01) run_test T01 basic_tcp test_T01_basic_tcp ;;
    T02) run_test T02 basic_udp test_T02_basic_udp ;;
    T03) run_test T03 server_restart_reconnect test_T03_server_restart_reconnect ;;
    T04) run_test T04 duplicate_register test_T04_duplicate_register ;;
    T05) run_test T05 invalid_key test_T05_invalid_key ;;
    T06) run_test T06 max_control_connections test_T06_max_control_connections ;;
    T07) run_test T07 per_client_session_limit test_T07_per_client_session_limit ;;
    T08) run_test T08 port_reuseaddr test_T08_port_reuseaddr ;;
    T09) run_test T09 registry_api test_T09_registry_api ;;
    T10) run_test T10 graceful_shutdown test_T10_graceful_shutdown ;;
    *) echo "Unknown test: $t"; exit 1 ;;
  esac
done

echo ""
echo "========================================"
echo "TOTAL: $TOTAL  PASS: $PASS  FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
  echo "Failed:"
  for x in "${FAILED_TESTS[@]}"; do echo "  - $x"; done
  exit 1
fi
exit 0
