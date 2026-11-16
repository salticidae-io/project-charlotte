#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ -n "${CHARLOTTE_DEMO_STATE:-}" ]]; then
  STATE_BASE="$CHARLOTTE_DEMO_STATE"
elif [[ "$PWD" == /workspace ]]; then
  STATE_BASE=/tmp/charlotte-demo
else
  STATE_BASE="$PROJECT_ROOT/target/demo"
fi
mkdir -p "$STATE_BASE"
if [[ "$(id -u)" == 0 ]]; then
  chmod 755 "$STATE_BASE"
fi
STATE="$STATE_BASE/run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$STATE"/{certs,conf,logs,pids,vhosts.d}
chmod 755 "$STATE"
cp -R "$SCRIPT_DIR/sites" "$STATE/sites"
cp "$SCRIPT_DIR/conf/modsecurity-demo.conf" "$STATE/conf/modsecurity-demo.conf"
chmod -R a+rX "$STATE/sites"
chmod +x "$STATE/sites/cgi/hello.sh"

if [[ "$(id -u)" == 0 ]]; then
  WORKER=nobody
else
  WORKER="$(id -un)"
fi

HTTP_PORT="${CHARLOTTE_DEMO_HTTP_PORT:-8080}"
TLS_PORT="${CHARLOTTE_DEMO_TLS_PORT:-8443}"
UPSTREAM_PORT="${CHARLOTTE_DEMO_UPSTREAM_PORT:-18081}"
for port in "$HTTP_PORT" "$TLS_PORT" "$UPSTREAM_PORT"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    printf 'demo: invalid TCP port: %s\n' "$port" >&2
    exit 1
  fi
done
export CHARLOTTE_DEMO_HTTP_PORT="$HTTP_PORT"
export CHARLOTTE_DEMO_TLS_PORT="$TLS_PORT"
export CHARLOTTE_DEMO_UPSTREAM_PORT="$UPSTREAM_PORT"

PHP_CGI=""
if command -v php-cgi >/dev/null 2>&1; then
  PHP_CGI="$(command -v php-cgi)"
fi

CHARLOTTE_BIN_DIR="${CHARLOTTE_BIN_DIR:-}"
if [[ -z "$CHARLOTTE_BIN_DIR" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    printf 'demo: cargo is required when CHARLOTTE_BIN_DIR is not set\n' >&2
    exit 1
  fi
  cargo build --release --bins
  CHARLOTTE_BIN_DIR="$PROJECT_ROOT/target/release"
fi

for binary in project-charlotte charlotte-ctl apache2charlotte nginx2charlotte; do
  if [[ ! -x "$CHARLOTTE_BIN_DIR/$binary" ]]; then
    printf 'demo: missing executable %s/%s\n' "$CHARLOTTE_BIN_DIR" "$binary" >&2
    exit 1
  fi
done

# A PATH entry named "chromium" is not always the browser (CLI wrappers and
# helper tools reuse the name and reject Chromium switches such as
# --host-resolver-rules), so prefer real browser binaries and require each
# candidate to identify itself as Chromium/Chrome before it is used.
is_chromium() {
  local version
  [[ -x "$1" && ! -d "$1" ]] || return 1
  version="$(timeout 20 "$1" --version 2>/dev/null </dev/null)" || return 1
  [[ "$version" =~ (Chromium|Google\ Chrome) ]]
}
CHROMIUM=""
if [[ -n "${CHROMIUM_BIN:-}" ]]; then
  CHROMIUM="$(command -v -- "$CHROMIUM_BIN" || true)"
  if [[ -z "$CHROMIUM" ]] || ! is_chromium "$CHROMIUM"; then
    printf 'demo: CHROMIUM_BIN=%s is not a Chromium/Chrome browser\n' "$CHROMIUM_BIN" >&2
    exit 1
  fi
else
  for candidate in /usr/lib/chromium/chromium /usr/lib/chromium-browser/chromium-browser \
      /opt/google/chrome/chrome chromium chromium-browser google-chrome google-chrome-stable; do
    path="$(command -v -- "$candidate" || true)"
    if [[ -n "$path" ]] && is_chromium "$path"; then
      CHROMIUM="$path"
      break
    fi
  done
fi
if [[ -z "$CHROMIUM" ]]; then
  printf 'demo: no Chromium/Chrome browser found; install one or set CHROMIUM_BIN\n' >&2
  exit 1
fi
printf 'demo: browser is %s (%s)\n' "$CHROMIUM" "$("$CHROMIUM" --version 2>/dev/null </dev/null)"
for binary in node openssl setsid; do
  if ! command -v "$binary" >/dev/null 2>&1; then
    printf 'demo: %s is required\n' "$binary" >&2
    exit 1
  fi
done

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout "$STATE/certs/demo-ca.key" -out "$STATE/certs/demo-ca.pem" \
  -subj '/CN=Charlotte Demo Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -newkey rsa:2048 -nodes \
  -keyout "$STATE/certs/server.key" -out "$STATE/certs/server.csr" \
  -subj '/CN=charlotte.test'
cat > "$STATE/certs/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:charlotte.test,DNS:*.charlotte.test
EOF
openssl x509 -req -in "$STATE/certs/server.csr" \
  -CA "$STATE/certs/demo-ca.pem" -CAkey "$STATE/certs/demo-ca.key" \
  -CAcreateserial -days 14 -sha256 -extfile "$STATE/certs/server.ext" \
  -out "$STATE/certs/server.pem"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$STATE/certs/pebble-listener.key" -out "$STATE/certs/pebble-listener.csr" \
  -subj '/CN=localhost'
cat > "$STATE/certs/pebble-listener.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "$STATE/certs/pebble-listener.csr" \
  -CA "$STATE/certs/demo-ca.pem" -CAkey "$STATE/certs/demo-ca.key" \
  -CAcreateserial -days 14 -sha256 -extfile "$STATE/certs/pebble-listener.ext" \
  -out "$STATE/certs/pebble-listener.pem"
chmod 600 "$STATE/certs/"*.key "$STATE/certs/demo-ca.pem"

PEBBLE_BIN="${PEBBLE_BIN:-}"
if [[ -n "$PEBBLE_BIN" ]]; then
  PEBBLE_BIN="$(command -v -- "$PEBBLE_BIN" || true)"
elif command -v pebble >/dev/null 2>&1; then
  PEBBLE_BIN="$(command -v pebble)"
elif [[ -x /usr/bin/pebble ]]; then
  PEBBLE_BIN=/usr/bin/pebble
fi
PEBBLE_CA="$STATE/certs/demo-ca.pem"
ACME_ENABLED=0
if [[ -x "$PEBBLE_BIN" ]]; then
  node "$SCRIPT_DIR/pebble-config.mjs" \
    "$STATE/conf/pebble-config.json" \
    "$STATE/certs/pebble-listener.pem" "$STATE/certs/pebble-listener.key" \
    "$HTTP_PORT" "$TLS_PORT"
  ACME_ENABLED=1
else
  printf 'demo: Pebble is unavailable; ACME scene will be skipped\n'
fi

CHROMIUM_PID=""
PEBBLE_PID=""
CHARLOTTE_PID=""
SERVICES_PID=""
CHROME_PROFILE=""
start_group() {
  local result_name=$1
  local log_file=$2
  local pid_file="$STATE/pids/${result_name,,}.pid"
  local launcher_pid
  local group_pid=""
  shift 2
  setsid bash -c 'printf "%s\n" "$$" > "$1"; shift; exec "$@"' \
    _ "$pid_file" "$@" >"$log_file" 2>&1 &
  launcher_pid=$!
  disown "$launcher_pid" 2>/dev/null || true
  for attempt in {1..50}; do
    if [[ -s "$pid_file" ]]; then
      IFS= read -r group_pid < "$pid_file"
      break
    fi
    if ! kill -0 "$launcher_pid" 2>/dev/null; then
      break
    fi
    sleep 0.02
  done
  if [[ -z "$group_pid" ]]; then
    kill -KILL "$launcher_pid" 2>/dev/null || true
    printf 'demo: could not start process group for %s; see %s\n' "$result_name" "$log_file" >&2
    return 1
  fi
  printf -v "$result_name" '%s' "$group_pid"
}
cleanup() {
  local pid
  for pid in "$CHROMIUM_PID" "$CHARLOTTE_PID" "$PEBBLE_PID" "$SERVICES_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  sleep 0.3
  for pid in "$CHROMIUM_PID" "$CHARLOTTE_PID" "$PEBBLE_PID" "$SERVICES_PID"; do
    if [[ -n "$pid" ]]; then
      kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
  done
  if [[ -n "$CHROME_PROFILE" && -d "$CHROME_PROFILE" ]]; then
    rm -rf -- "$CHROME_PROFILE"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_group SERVICES_PID "$STATE/logs/services.log" node "$SCRIPT_DIR/services.mjs"
if ! node "$SCRIPT_DIR/wait-for-services.mjs" "$UPSTREAM_PORT" 1053; then
  printf 'demo: local upstream or DNS responder failed; see %s\n' "$STATE/logs/services.log" >&2
  exit 1
fi

if (( ACME_ENABLED )); then
  start_group PEBBLE_PID "$STATE/logs/pebble.log" env PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
    "$PEBBLE_BIN" -config "$STATE/conf/pebble-config.json" -dnsserver 127.0.0.1:1053
  if node "$SCRIPT_DIR/wait-for-pebble.mjs" "$PEBBLE_CA" "$STATE/certs/pebble-issuers.pem"; then
    printf 'demo: local Pebble ACME test CA is ready\n'
  else
    printf 'demo: Pebble did not become ready; ACME scene will be skipped\n'
    kill -TERM -- "-$PEBBLE_PID" 2>/dev/null || kill "$PEBBLE_PID" 2>/dev/null || true
    sleep 0.1
    kill -KILL -- "-$PEBBLE_PID" 2>/dev/null || kill -KILL "$PEBBLE_PID" 2>/dev/null || true
    PEBBLE_PID=""
    ACME_ENABLED=0
  fi
fi

node "$SCRIPT_DIR/render-config.mjs" \
  "$SCRIPT_DIR/conf/vhosts.yaml.in" "$STATE/conf/vhosts.yaml" \
  "$STATE" "$WORKER" "$PHP_CGI" "$ACME_ENABLED" "$UPSTREAM_PORT"

SPKI_LIST="$(openssl x509 -in "$STATE/certs/server.pem" -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | openssl base64 -A)"
if (( ACME_ENABLED )); then
  # Pin both Pebble issuers so the freshly issued ACME leaf chains validate.
  mkdir -p "$STATE/certs/pebble-issuers"
  awk -v dir="$STATE/certs/pebble-issuers" \
    '/BEGIN CERTIFICATE/ { n++ } n { print > (dir "/" n ".pem") }' \
    "$STATE/certs/pebble-issuers.pem"
  for issuer in "$STATE/certs/pebble-issuers/"*.pem; do
    PEBBLE_SPKI="$(openssl x509 -in "$issuer" -pubkey -noout \
      | openssl pkey -pubin -outform DER \
      | openssl dgst -sha256 -binary | openssl base64 -A)"
    SPKI_LIST="$SPKI_LIST,$PEBBLE_SPKI"
  done
fi

CHROME_PROFILE="$(mktemp -d "$STATE/chrome-profile.XXXXXX")"
if command -v certutil >/dev/null 2>&1; then
  certutil -N -d "sql:$CHROME_PROFILE" --empty-password >/dev/null 2>&1 || true
  certutil -A -d "sql:$CHROME_PROFILE" -t 'C,,' -n 'Charlotte Demo Root' \
    -i "$STATE/certs/demo-ca.pem" >/dev/null 2>&1 || true
  if (( ACME_ENABLED )); then
    certutil -A -d "sql:$CHROME_PROFILE" -t 'C,,' -n 'Pebble Demo Root' \
      -i "$STATE/certs/pebble-issuers/1.pem" >/dev/null 2>&1 || true
  fi
fi

CHROME_DEBUG_PORT="${CHARLOTTE_DEMO_CHROME_DEBUG_PORT:-9222}"

CHARLOTTE_ARGS=(
  --bind "127.0.0.1:$HTTP_PORT"
  --tls-bind "127.0.0.1:$TLS_PORT"
  --http3-bind "127.0.0.1:$TLS_PORT"
  --tls-cert "$STATE/certs/server.pem"
  --tls-key "$STATE/certs/server.key"
  --root "$STATE/sites/fallback"
  --config "$STATE/conf/vhosts.yaml"
  --vhost-dir "$STATE/vhosts.d"
  --control-socket "$STATE/control.sock"
  --access-log-file "$STATE/logs/access.log"
  --access-log-format '%v "%r" %>s %{Range}i'
  --bot-config "$SCRIPT_DIR/conf/bot-policy.yaml"
  --modsecurity-rules "$STATE/conf/modsecurity-demo.conf"
  --modsecurity-block-status 403
  --threads 2
  --worker-threads 1
)
if (( ACME_ENABLED )); then
  CHARLOTTE_ARGS+=(
    --acme-directory https://localhost:14000/dir
    --acme-cache "$STATE/acme"
    --acme-ca-root "$PEBBLE_CA"
  )
fi
start_group CHARLOTTE_PID "$STATE/logs/charlotte.log" \
  "$CHARLOTTE_BIN_DIR/project-charlotte" "${CHARLOTTE_ARGS[@]}"

if ! node "$SCRIPT_DIR/wait-for-charlotte.mjs" "$HTTP_PORT"; then
  printf 'demo: Charlotte did not serve its ready page; see %s\n' "$STATE/logs/charlotte.log" >&2
  exit 1
fi

CHROME_ARGS=(
  --user-data-dir="$CHROME_PROFILE"
  --remote-debugging-address=127.0.0.1
  --remote-debugging-port="$CHROME_DEBUG_PORT"
  --remote-allow-origins=*
  '--host-resolver-rules=MAP *.charlotte.test 127.0.0.1,MAP charlotte.test 127.0.0.1,EXCLUDE localhost'
  --ignore-certificate-errors-spki-list="$SPKI_LIST"
  --origin-to-force-quic-on="h3.charlotte.test:$TLS_PORT"
  --enable-quic
  --no-proxy-server
  --no-first-run
  --no-default-browser-check
  --disable-background-networking
  --disable-component-update
  --disable-dev-shm-usage
  --window-size=1440,1000
)
if [[ "$(id -u)" == 0 ]]; then
  CHROME_ARGS+=(--no-sandbox)
fi
for argument in "$@"; do
  if [[ "$argument" == --headless ]]; then
    CHROME_ARGS+=(--headless=new)
  fi
done
start_group CHROMIUM_PID "$STATE/logs/chromium.log" "$CHROMIUM" "${CHROME_ARGS[@]}" about:blank

export CHARLOTTE_DEMO_STATE="$STATE"
export CHARLOTTE_DEMO_HAS_PHP=0
if [[ -n "$PHP_CGI" ]]; then
  export CHARLOTTE_DEMO_HAS_PHP=1
fi
export CHARLOTTE_DEMO_HAS_ACME="$ACME_ENABLED"
export CHARLOTTE_DEMO_BIN_DIR="$CHARLOTTE_BIN_DIR"
export CHARLOTTE_DEMO_PROJECT_ROOT="$PROJECT_ROOT"
export CHARLOTTE_DEMO_WORKER_USER="$WORKER"
export CHARLOTTE_DEMO_ACCESS_LOG="$STATE/logs/access.log"
export CHARLOTTE_DEMO_CONTROL_SOCKET="$STATE/control.sock"
export CHARLOTTE_DEMO_CHROME_DEBUG_PORT="$CHROME_DEBUG_PORT"
export CHARLOTTE_DEMO_PROJECT_ROOT="$PROJECT_ROOT"
export CHARLOTTE_DEMO_WORKER_USER="$WORKER"
printf 'demo: state is %s\n' "$STATE"
node "$SCRIPT_DIR/director.mjs" "$@"