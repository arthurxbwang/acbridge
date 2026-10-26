#!/usr/bin/env bash
# Install or upgrade acbridge without discarding existing configuration.
set -Eeuo pipefail
umask 077

fail() { printf 'Error: %s\n' "$*" >&2; return 1; }
usage() {
    cat <<'USAGE'
Usage: sudo bash install.sh [--yes] [options]
  --install-dir PATH     Installation directory (default /opt/acbridge)
  --ref REF              Build this Git tag/branch/commit; resolved commit is recorded
  --version VERSION      Install a published release with SHA256 verification
  --port PORT            Listener port (default 9443)
  --bind ADDRESS         Listener IP (default 127.0.0.1)
  --caddy URL            Caddy Admin URL (default http://127.0.0.1:2019)
  --cert-dir PATH        Certificate cache (default /var/lib/acbridge/certs)
  --sync-interval N      Synchronization seconds (default 30)
  --mode proxy|tls       Loopback HTTP behind HTTPS proxy, or supplied TLS certificate
  --tls-cert PATH --tls-key PATH --tls-server-name NAME
  --tls-ca PATH          Optional private CA bundle for TLS readiness verification
  --token-file PATH      Read a token from a protected file (never a command argument)
  --rotate-token         Explicitly generate a new token
  --yes                 Noninteractive installation using saved/default settings
Existing configuration and token are retained unless explicitly overridden.
USAGE
}
defaults() {
    INSTALL_DIR=/opt/acbridge SERVICE_FILE=/etc/systemd/system/acbridge.service
    PORT=9443 BIND=127.0.0.1 CADDY_URL=http://127.0.0.1:2019
    CERT_DIR=/var/lib/acbridge/certs SYNC_INTERVAL=30 MODE=proxy
    TLS_CERT='' TLS_KEY='' TLS_SERVER_NAME='' TLS_CA='' REF=main VERSION='' TOKEN_FILE=''
    ROTATE=0 YES=0 LEGACY_TRANSPORT=0 MODE_EXPLICIT=0 BIND_EXPLICIT=0 TXN=0 SUCCESS=0 WAS_ACTIVE=0 WAS_ENABLED=0 BACKUP='' TMP=''
}
# Only known keys are loaded; shell text is never sourced or evaluated.
load_existing() {
    local key value legacy_data
    if [[ -f "$INSTALL_DIR/install.conf" ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                PORT|BIND|CADDY_URL|CERT_DIR|SYNC_INTERVAL|MODE|TLS_CERT|TLS_KEY|TLS_SERVER_NAME|TLS_CA|REF|VERSION) printf -v "$key" '%s' "$value" ;;
                ''|'#'*) ;;
                *) fail "Unknown key in install.conf: $key"; return 1 ;;
            esac
        done < "$INSTALL_DIR/install.conf"
    elif [[ -f "$SERVICE_FILE" ]]; then
        LEGACY_TRANSPORT=1
        # Migrate the original unit's simple arguments, without executing any text.
        legacy_data=$(python3 - "$SERVICE_FILE" <<'PYUNIT'
import shlex,sys
for line in open(sys.argv[1]):
    if not line.startswith('ExecStart='): continue
    args=shlex.split(line.split('=',1)[1]); mapping={'-caddy':'CADDY_URL','-cert-dir':'CERT_DIR','-sync-interval':'SYNC_INTERVAL'}
    for i,arg in enumerate(args[:-1]):
        if arg in mapping: print(mapping[arg]+'='+args[i+1])
        if arg=='-addr':
            host,port=args[i+1].rsplit(':',1)
            print('PORT='+port)
            print('BIND='+(host or '0.0.0.0'))
PYUNIT
)
        while IFS='=' read -r key value; do
            case "$key" in
                PORT|BIND|CADDY_URL|CERT_DIR|SYNC_INTERVAL) printf -v "$key" '%s' "$value" ;;
            esac
        done <<< "$legacy_data"
    fi
}
parse_args() {
    while (($#)); do
        case "$1" in
            --yes) YES=1; shift ;;
            --rotate-token) ROTATE=1; shift ;;
            --help|-h) usage; exit 0 ;;
            --install-dir|--port|--bind|--caddy|--cert-dir|--sync-interval|--mode|--tls-cert|--tls-key|--tls-server-name|--tls-ca|--ref|--version|--token-file)
                (($# >= 2)) || { fail "Missing value for $1"; return 1; }
                case "$1" in
                    --install-dir) INSTALL_DIR=$2 ;; --port) PORT=$2 ;; --bind) BIND=$2; BIND_EXPLICIT=1 ;;
                    --caddy) CADDY_URL=$2 ;; --cert-dir) CERT_DIR=$2 ;; --sync-interval) SYNC_INTERVAL=$2 ;;
                    --mode) MODE=$2; MODE_EXPLICIT=1 ;; --tls-cert) TLS_CERT=$2 ;; --tls-key) TLS_KEY=$2 ;;
                    --tls-server-name) TLS_SERVER_NAME=$2 ;; --tls-ca) TLS_CA=$2 ;; --ref) REF=$2; VERSION='' ;;
                    --version) VERSION=$2 ;; --token-file) TOKEN_FILE=$2 ;;
                esac
                shift 2 ;;
            *) fail "Unknown option: $1"; return 1 ;;
        esac
    done
}
prompt_settings() {
    local answer
    [[ $YES == 1 ]] && return 0
    [[ -r /dev/tty ]] || { fail 'No terminal; use --yes and explicit options'; return 1; }
    if [[ $LEGACY_TRANSPORT == 1 && $MODE_EXPLICIT == 0 ]]; then
        printf 'Legacy HTTPS service detected. Choose proxy (requires a new trusted HTTPS frontend) or tls (requires certificate options). Existing AllinSSL URL may need updating.\n'
        read -r -p 'Explicit transport choice [proxy/tls]: ' answer < /dev/tty
        MODE=$answer; MODE_EXPLICIT=1
    fi
    read -r -p "Listener port [$PORT]: " answer < /dev/tty; PORT=${answer:-$PORT}
    read -r -p "Caddy Admin URL [$CADDY_URL]: " answer < /dev/tty; CADDY_URL=${answer:-$CADDY_URL}
    read -r -p "Synchronization seconds [$SYNC_INTERVAL]: " answer < /dev/tty; SYNC_INTERVAL=${answer:-$SYNC_INTERVAL}
    printf 'Mode: %s. Existing token is retained; use --rotate-token to change it.\n' "$MODE"
    read -r -p 'Continue installation? [y/N]: ' answer < /dev/tty
    [[ $answer == y || $answer == Y ]] || { fail 'Installation cancelled'; return 1; }
}
validate() {
    if [[ $LEGACY_TRANSPORT == 1 ]]; then
        [[ $MODE_EXPLICIT == 1 ]] || { fail 'Legacy HTTPS upgrade requires explicit --mode proxy or --mode tls. Proxy mode requires a trusted HTTPS frontend and updating the AllinSSL URL.'; return 1; }
        if [[ $MODE == proxy && $BIND_EXPLICIT == 0 ]]; then BIND=127.0.0.1; fi
    fi
    [[ $BIND != localhost ]] || BIND=127.0.0.1
    [[ $INSTALL_DIR =~ ^/[a-zA-Z0-9_./-]+$ && $INSTALL_DIR != / && ! $INSTALL_DIR =~ (^|/)\.\.(/|$) ]] || { fail 'Unsafe installation directory'; return 1; }
    [[ $CERT_DIR =~ ^/[a-zA-Z0-9_./-]+$ && $CERT_DIR != / && ! $CERT_DIR =~ (^|/)\.\.(/|$) ]] || { fail 'Unsafe certificate directory'; return 1; }
    [[ $PORT =~ ^[0-9]{1,5}$ ]] && ((10#$PORT >= 1024 && 10#$PORT <= 65535)) || { fail 'Port must be 1024..65535'; return 1; }
    [[ $SYNC_INTERVAL =~ ^[0-9]{1,6}$ ]] && ((10#$SYNC_INTERVAL >= 1 && 10#$SYNC_INTERVAL <= 86400)) || { fail 'Sync interval must be 1..86400'; return 1; }
    [[ $BIND =~ ^[0-9.]+$ || $BIND == localhost ]] || { fail 'Bind must be an IPv4 address or localhost'; return 1; }
    [[ $MODE == proxy || $MODE == tls ]] || { fail 'Mode must be proxy or tls'; return 1; }
    if [[ $MODE == proxy ]]; then
        [[ $BIND == 127.0.0.1 || $BIND == localhost ]] || { fail 'Proxy HTTP mode requires loopback binding'; return 1; }
    else
        [[ -r $TLS_CERT && -r $TLS_KEY && $TLS_SERVER_NAME =~ ^[a-zA-Z0-9.-]+$ ]] || { fail 'TLS mode needs readable --tls-cert/--tls-key and --tls-server-name'; return 1; }
    fi
    [[ -z $TLS_CA || -r $TLS_CA ]] || { fail 'Cannot read TLS CA bundle'; return 1; }
    PORT=$((10#$PORT)); SYNC_INTERVAL=$((10#$SYNC_INTERVAL))
    [[ $REF =~ ^[a-zA-Z0-9_./-]+$ && $REF != -* ]] || { fail 'Invalid Git ref'; return 1; }
    [[ -z $VERSION || $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]] || { fail 'Release version must be vMAJOR.MINOR.PATCH'; return 1; }
    [[ ! ($ROTATE == 1 && -n $TOKEN_FILE) ]] || { fail 'Use either --rotate-token or --token-file'; return 1; }
    python3 - "$CADDY_URL" "$BIND" "$INSTALL_DIR" "$CERT_DIR" <<'PY'
import ipaddress,pathlib,sys,urllib.parse
u=urllib.parse.urlsplit(sys.argv[1])
if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.query or u.fragment or any(c.isspace() for c in sys.argv[1]) or any(c in sys.argv[1] for c in '"\\%$'): raise SystemExit('Invalid Caddy URL; credentials in URL are unsupported')
if sys.argv[2]!='localhost': ipaddress.IPv4Address(sys.argv[2])
install_dir,cache_dir=map(pathlib.Path,sys.argv[3:5])
reserved={'/','/etc','/usr','/usr/local','/var','/var/lib','/var/cache','/var/log','/tmp','/opt','/home','/root','/run','/srv','/boot','/dev','/proc','/sys','/workspace'}
for p in (install_dir,cache_dir):
    if str(p.resolve()) in reserved or p.is_symlink(): raise SystemExit('Use a dedicated directory, not a system directory or symlink')
if cache_dir.resolve() in (install_dir.resolve(),*install_dir.resolve().parents): raise SystemExit('Certificate cache must be separate from installation directory')
if cache_dir.exists():
    for p in cache_dir.iterdir():
        if p.is_symlink() or not p.is_file() or not (p.name=='.acbridge-cache.json' or p.name.startswith('.cache-') or p.suffix in ('.pem','.crt','.key')):
            raise SystemExit('Existing certificate directory contains unrelated entries; choose a dedicated cache directory')
PY
}
preflight() {
    [[ $EUID == 0 ]] || { fail 'Run this installer as root'; return 1; }
    local cmd
    for cmd in curl python3 systemctl install useradd getent; do command -v "$cmd" >/dev/null || { fail "Required command missing: $cmd"; return 1; }; done
    [[ -d /run/systemd/system ]] || { fail 'A running systemd host is required'; return 1; }
    curl --fail --silent --show-error --max-time 10 "${CADDY_URL%/}/config/" -o "$TMP/caddy.json"
    python3 - "$TMP/caddy.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]))
if v is not None and not isinstance(v,dict): raise SystemExit('Caddy /config/ must return an object')
PY
}
prepare_binary() {
    if [[ -n $VERSION ]]; then
        local arch archive url
        case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'Unsupported release architecture'; return 1 ;; esac
        archive="acbridge_linux_${arch}.tar.gz"
        url="https://github.com/arthurxbwang/acbridge/releases/download/$VERSION"
        curl --fail --silent --show-error --location "$url/$archive" -o "$TMP/$archive"
        curl --fail --silent --show-error --location "$url/SHA256SUMS" -o "$TMP/SHA256SUMS"
        (cd "$TMP"; python3 - "$archive" <<'PY'
import hashlib,pathlib,sys
name=sys.argv[1]
lines=[line.split() for line in pathlib.Path('SHA256SUMS').read_text().splitlines()]
expected=[x[0] for x in lines if len(x)==2 and x[1].lstrip('*')==name]
if len(expected)!=1 or hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()!=expected[0]: raise SystemExit('Release checksum verification failed')
PY
        tar -xzf "$archive" acbridge)
        chmod 0755 "$TMP/acbridge"
    else
        command -v git >/dev/null || { fail 'Install git, or select a published --version'; return 1; }
        command -v go >/dev/null || { fail 'Install Go >=1.20, or select a published --version'; return 1; }
        local go_version
        go_version=$(go version)
        [[ $go_version =~ go1\.([0-9]+) ]] && ((${BASH_REMATCH[1]} >= 20)) || { fail 'Go >=1.20 is required'; return 1; }
        git init --quiet "$TMP/source"
        git -C "$TMP/source" remote add origin https://github.com/arthurxbwang/acbridge.git
        git -C "$TMP/source" fetch --quiet --depth=1 origin "$REF"
        git -C "$TMP/source" checkout --quiet --detach FETCH_HEAD
        REF=$(git -C "$TMP/source" rev-parse HEAD)
        (cd "$TMP/source"; CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags "-s -w -X main.version=source -X main.commit=$REF" -o "$TMP/acbridge" .)
    fi
    "$TMP/acbridge" -version >/dev/null
}
prepare_token() {
    if [[ -n $TOKEN_FILE ]]; then
        [[ -f $TOKEN_FILE && -r $TOKEN_FILE ]] || { fail 'Cannot read token file'; return 1; }
        TOKEN=$(cat "$TOKEN_FILE")
    elif [[ $ROTATE == 0 && -f "$INSTALL_DIR/acbridge.env" ]]; then
        TOKEN=$(python3 - "$INSTALL_DIR/acbridge.env" <<'PY'
import shlex,sys
values=[]
for line in open(sys.argv[1]):
    if line.startswith('ACBRIDGE_TOKEN='):
        fields=shlex.split(line.rstrip('\n').split('=',1)[1], comments=False)
        if len(fields)!=1: raise SystemExit('Cannot safely read existing token')
        values.append(fields[0])
if len(values)!=1: raise SystemExit('Expected exactly one existing ACBRIDGE_TOKEN')
sys.stdout.write(values[0])
PY
)
    elif [[ $ROTATE == 0 && -f "$SERVICE_FILE" ]]; then
        TOKEN=$(python3 - "$SERVICE_FILE" <<'PYTOKEN'
import secrets,shlex,sys
values=[]
for line in open(sys.argv[1]):
    if not line.startswith('ExecStart='): continue
    args=shlex.split(line.split('=',1)[1])
    for i,arg in enumerate(args[:-1]):
        if arg=='-token': values.append(args[i+1])
if len(values)>1: raise SystemExit('Ambiguous legacy token; supply --token-file')
sys.stdout.write(values[0] if values else secrets.token_hex(32))
PYTOKEN
)
    else
        TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    fi
    [[ -n $TOKEN && ${#TOKEN} -le 512 && $TOKEN != *$'\n'* && $TOKEN != *$'\r'* && $TOKEN != 'acbridge-secret-token' ]] || { fail 'Token is empty, invalid, or the insecure legacy default; use --rotate-token'; return 1; }
}
setup_account() {
    getent passwd acbridge >/dev/null || useradd --system --home-dir /var/lib/acbridge --shell /usr/sbin/nologin acbridge
    install -d -o acbridge -g acbridge -m 0700 "$CERT_DIR"
    # Existing certificate files must remain usable after migration from root.
    local cached_file
    while IFS= read -r -d '' cached_file; do chown acbridge:acbridge "$cached_file"; done < <(find "$CERT_DIR" -maxdepth 1 -type f -print0)
}
render_unit() {
    local transport='-http'
    [[ $MODE == tls ]] && transport="-tls-cert $INSTALL_DIR/tls/cert.pem -tls-key $INSTALL_DIR/tls/key.pem"
    cat <<UNIT
[Unit]
Description=acbridge - AllinSSL to Caddy certificate bridge
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=acbridge
Group=acbridge
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/acbridge.env
ExecStart=$INSTALL_DIR/acbridge -addr $BIND:$PORT -caddy $CADDY_URL -cert-dir $CERT_DIR -sync-interval $SYNC_INTERVAL $transport
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CERT_DIR
CapabilityBoundingSet=
RestrictSUIDSGID=true
[Install]
WantedBy=multi-user.target
UNIT
}
write_config() {
    local key
    for key in PORT BIND CADDY_URL CERT_DIR SYNC_INTERVAL MODE TLS_CERT TLS_KEY TLS_SERVER_NAME TLS_CA REF VERSION; do printf '%s=%s\n' "$key" "${!key}"; done
}
wait_ready() {
    local url="http://127.0.0.1:$PORT/readyz" i connect_host=$BIND
    [[ $connect_host != 0.0.0.0 ]] || connect_host=127.0.0.1
    local -a tls_args=()
    if [[ $MODE == tls ]]; then
        url="https://$TLS_SERVER_NAME:$PORT/readyz"
        tls_args=(--resolve "$TLS_SERVER_NAME:$PORT:$connect_host")
        [[ -z $TLS_CA ]] || tls_args+=(--cacert "$TLS_CA")
    fi
    # Token travels through a 0600 curl config, never argv or terminal output.
    printf '%s' "$TOKEN" | python3 -c 'import sys; s=sys.stdin.read(); print("header = \"X-SLCE-API-TOKEN: "+s.replace("\\","\\\\").replace("\"","\\\"")+"\"")' > "$TMP/curl.conf"
    for ((i=0;i<30;i++)); do
        if curl --config "$TMP/curl.conf" --fail --silent --max-time 2 "${tls_args[@]}" "$url" > "$TMP/ready.json" && python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("data", {}).get("ready") is True else 1)' "$TMP/ready.json"; then return 0; fi
        sleep 1
    done
    fail 'Readiness failed: bridge did not confirm successful Caddy synchronization'
}
restore_file() {
    local name=$1 target=$2
    if [[ -e "$BACKUP/$name" ]]; then cp -a "$BACKUP/$name" "$target.rollback"; mv -f "$target.rollback" "$target"; else rm -f "$target"; fi
}
rollback() {
    printf 'Installation failed; restoring previous binary, configuration and unit.\n' >&2
    systemctl stop acbridge >/dev/null 2>&1 || true
    restore_file acbridge "$INSTALL_DIR/acbridge"
    restore_file acbridge.env "$INSTALL_DIR/acbridge.env"
    restore_file install.conf "$INSTALL_DIR/install.conf"
    restore_file service "$SERVICE_FILE"
    if [[ -d "$BACKUP/tls" ]]; then rm -rf "$INSTALL_DIR/tls"; cp -a "$BACKUP/tls" "$INSTALL_DIR/tls"; else rm -rf "$INSTALL_DIR/tls"; fi
    systemctl daemon-reload || true
    if [[ $WAS_ENABLED == 1 ]]; then systemctl enable acbridge >/dev/null 2>&1 || true; else systemctl disable acbridge >/dev/null 2>&1 || true; fi
    if [[ $WAS_ACTIVE == 1 ]]; then systemctl restart acbridge || printf 'Previous service also failed to restart; inspect journalctl -u acbridge.\n' >&2; fi
}
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ $TXN == 1 && $SUCCESS != 1 ]]; then rollback || true; rc=1; fi
    [[ -z $TMP ]] || rm -rf "$TMP"
    exit "$rc"
}
perform_install() {
    install -d -m 0755 "$INSTALL_DIR"
    BACKUP=$(mktemp -d "$INSTALL_DIR/.backup.XXXXXX")
    local file
    for file in acbridge acbridge.env install.conf; do [[ ! -e "$INSTALL_DIR/$file" ]] || cp -a "$INSTALL_DIR/$file" "$BACKUP/$file"; done
    [[ ! -f $SERVICE_FILE ]] || cp -a "$SERVICE_FILE" "$BACKUP/service"
    [[ ! -d "$INSTALL_DIR/tls" ]] || cp -a "$INSTALL_DIR/tls" "$BACKUP/tls"
    systemctl is-active --quiet acbridge && WAS_ACTIVE=1
    systemctl is-enabled --quiet acbridge && WAS_ENABLED=1
    TXN=1
    setup_account
    if [[ $MODE == tls ]]; then
        install -d -o root -g acbridge -m 0750 "$INSTALL_DIR/tls"
        install -o root -g acbridge -m 0640 "$TLS_CERT" "$TMP/cert.pem"
        install -o root -g acbridge -m 0640 "$TLS_KEY" "$TMP/key.pem"
        cp -p "$TMP/cert.pem" "$INSTALL_DIR/tls/cert.pem.new"; mv -f "$INSTALL_DIR/tls/cert.pem.new" "$INSTALL_DIR/tls/cert.pem"
        cp -p "$TMP/key.pem" "$INSTALL_DIR/tls/key.pem.new"; mv -f "$INSTALL_DIR/tls/key.pem.new" "$INSTALL_DIR/tls/key.pem"
        TLS_CERT=$INSTALL_DIR/tls/cert.pem TLS_KEY=$INSTALL_DIR/tls/key.pem
    fi
    install -m 0755 "$TMP/acbridge" "$INSTALL_DIR/acbridge.new"
    mv -f "$INSTALL_DIR/acbridge.new" "$INSTALL_DIR/acbridge"
    local escaped=${TOKEN//\\/\\\\}; escaped=${escaped//\"/\\\"}
    printf 'ACBRIDGE_TOKEN="%s"\n' "$escaped" > "$INSTALL_DIR/acbridge.env.new"
    chmod 0600 "$INSTALL_DIR/acbridge.env.new"; mv -f "$INSTALL_DIR/acbridge.env.new" "$INSTALL_DIR/acbridge.env"
    write_config > "$INSTALL_DIR/install.conf.new"; mv -f "$INSTALL_DIR/install.conf.new" "$INSTALL_DIR/install.conf"
    render_unit > "$SERVICE_FILE.new"; chmod 0644 "$SERVICE_FILE.new"; mv -f "$SERVICE_FILE.new" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl restart acbridge
    wait_ready
    systemctl enable acbridge
    SUCCESS=1
    printf 'acbridge installed and Caddy synchronization verified. Backup: %s\n' "$BACKUP"
    printf 'Token retained/generated in %s/acbridge.env (0600); value is not displayed.\n' "$INSTALL_DIR"
    if [[ $MODE == proxy ]]; then
        printf '\nHTTPS frontend still needs configuration before AllinSSL can connect. Add a dedicated hostname to your Caddyfile:\n\nbridge.example.com {\n    reverse_proxy 127.0.0.1:%s\n}\n\n' "$PORT"
        printf 'Use your real hostname, configure DNS, validate/reload Caddy, then use that HTTPS URL in AllinSSL → 雷池 WAF 面板.\n'
    else
        printf 'AllinSSL HTTPS URL: https://%s:%s (ensure DNS/network access).\n' "$TLS_SERVER_NAME" "$PORT"
    fi
}
main() {
    defaults
    command -v python3 >/dev/null || { fail 'python3 is required for safe configuration handling'; return 1; }
    local -a args=("$@")
    local explicit_dir=0 i
    for ((i=0;i<${#args[@]};i++)); do
        if [[ ${args[i]} == --help || ${args[i]} == -h ]]; then usage; return; fi
        if [[ ${args[i]} == --install-dir ]]; then INSTALL_DIR=${args[i+1]:-}; explicit_dir=1; fi
    done
    # Find the previous custom installation directory from a literal unit directive.
    if [[ $explicit_dir == 0 && -f $SERVICE_FILE ]]; then
        local line
        while IFS= read -r line; do [[ $line != WorkingDirectory=* ]] || INSTALL_DIR=${line#WorkingDirectory=}; done < "$SERVICE_FILE"
    fi
    load_existing
    parse_args "$@"
    prompt_settings
    validate
    TMP=$(mktemp -d /tmp/acbridge-install.XXXXXX)
    trap cleanup EXIT
    preflight
    prepare_binary
    prepare_token
    perform_install
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
