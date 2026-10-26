#!/usr/bin/env bash
# Exercises actual installer transactions using filesystem fixtures and service mocks.
set -euo pipefail
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
export TMPDIR="$test_dir"
export ACBRIDGE_INSTALL_SOURCE="$repo_dir/install.sh"
cat > "$test_dir/scenario.sh" <<'DRIVER'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$ACBRIDGE_INSTALL_SOURCE"
defaults
fixture=$(mktemp -d)
INSTALL_DIR=$fixture/install SERVICE_FILE=$fixture/service CERT_DIR=$fixture/cache
TMP=$fixture/tmp
mkdir -p "$INSTALL_DIR" "$TMP"
printf '#!/bin/sh\nexit 0\n' > "$TMP/acbridge"
printf 'old-binary' > "$INSTALL_DIR/acbridge"
printf 'ACBRIDGE_TOKEN="existing-test-token"\n' > "$INSTALL_DIR/acbridge.env"
printf 'PORT=9555\nBIND=127.0.0.1\nCADDY_URL=http://127.0.0.1:2020\nCERT_DIR=%s\nSYNC_INTERVAL=45\nMODE=proxy\n' "$CERT_DIR" > "$INSTALL_DIR/install.conf"
printf 'old-unit\n' > "$SERVICE_FILE"
cp -a "$INSTALL_DIR" "$fixture/original"
cp "$SERVICE_FILE" "$fixture/original-unit"
export FIXTURE=$fixture
systemctl() {
    printf '%s\n' "$*" >> "$fixture/systemctl.log"
    if [[ ${FAIL_RESTART:-0} == 1 && $1 == restart ]]; then return 1; fi
    return 0
}
setup_account() { mkdir -p "$CERT_DIR"; }
case "$1" in
    preserve)
        wait_ready() { return 0; }
        load_existing; prepare_token
        [[ $PORT == 9555 && $SYNC_INTERVAL == 45 && $TOKEN == existing-test-token && $CADDY_URL == http://127.0.0.1:2020 ]]
        trap cleanup EXIT
        perform_install
        [[ $SUCCESS == 1 ]]
        cmp "$fixture/original/acbridge.env" "$INSTALL_DIR/acbridge.env"
        grep -q 'User=acbridge' "$SERVICE_FILE"
        grep -q -- '-addr 127.0.0.1:9555' "$SERVICE_FILE"
        [[ -f "$BACKUP/acbridge" ]]
        ;;
    rotate)
        load_existing; ROTATE=1; prepare_token
        [[ $TOKEN != existing-test-token && ${#TOKEN} == 64 ]]
        ;;
    rollback)
        load_existing; prepare_token
        wait_ready() { return 1; }
        trap 'rc=$?; trap - EXIT; rollback; cmp "$fixture/original/acbridge" "$INSTALL_DIR/acbridge"; cmp "$fixture/original/acbridge.env" "$INSTALL_DIR/acbridge.env"; cmp "$fixture/original/install.conf" "$INSTALL_DIR/install.conf"; cmp "$fixture/original-unit" "$SERVICE_FILE"; [[ $rc != 0 ]]; exit 0' EXIT
        perform_install
        exit 99
        ;;
    failed_exit)
        load_existing; prepare_token
        wait_ready() { return 1; }
        trap cleanup EXIT
        perform_install
        ;;
    malicious_config)
        printf 'PORT=$(touch %s/should-not-exist)\n' "$fixture" > "$INSTALL_DIR/install.conf"
        load_existing
        [[ ! -e "$fixture/should-not-exist" ]]
        if validate 2>/dev/null; then exit 1; fi
        ;;
    invalid_port)
        PORT=0
        if validate 2>/dev/null; then exit 1; fi
        ;;
    unsafe_cache)
        CERT_DIR=/etc
        if validate 2>/dev/null; then exit 1; fi
        ;;
    unrelated_cache)
        mkdir -p "$CERT_DIR"; printf 'unrelated' > "$CERT_DIR/database.sqlite"
        if validate 2>/dev/null; then exit 1; fi
        ;;
    public_http)
        BIND=0.0.0.0
        if validate 2>/dev/null; then exit 1; fi
        ;;
    readiness)
        load_existing; prepare_token
        curl() {
            local arg
            for arg in "$@"; do [[ $arg != *existing-test-token* ]] || return 99; done
            printf '{"data":{"ready":true},"err":"","msg":""}'
        }
        wait_ready
        [[ -f $TMP/curl.conf ]]
        ;;
    unready)
        load_existing; prepare_token
        curl() { printf '{"data":{"ready":false},"err":"not_ready","msg":"pending"}'; }
        sleep() { :; }
        if wait_ready 2>/dev/null; then exit 1; fi
        ;;
    legacy_token)
        rm "$INSTALL_DIR/acbridge.env"
        printf 'ExecStart=/opt/acbridge/acbridge -token legacy-cli-test -addr :9443\n' > "$SERVICE_FILE"
        prepare_token
        [[ $TOKEN == legacy-cli-test ]]
        ;;
    localhost)
        BIND=localhost
        validate
        [[ $BIND == 127.0.0.1 ]]
        ;;
    legacy)
        rm "$INSTALL_DIR/install.conf"
        printf 'WorkingDirectory=%s\nExecStart=%s/acbridge -addr :9666 -caddy http://127.0.0.1:2021 -cert-dir %s -sync-interval 90\n' "$INSTALL_DIR" "$INSTALL_DIR" "$CERT_DIR" > "$SERVICE_FILE"
        load_existing; prepare_token
        [[ $PORT == 9666 && $SYNC_INTERVAL == 90 && $TOKEN == existing-test-token && $BIND == 0.0.0.0 ]]
        if validate 2>/dev/null; then exit 1; fi
        parse_args --mode proxy
        validate
        [[ $BIND == 127.0.0.1 && $PORT == 9666 ]]
        ;;
    *) exit 2 ;;
esac
rm -rf "$fixture"
DRIVER
# The child shell owns errexit. Do not wrap its body in an if/function that disables it.
for scenario in preserve rotate rollback malicious_config invalid_port unsafe_cache unrelated_cache public_http legacy legacy_token localhost readiness unready; do
    bash "$test_dir/scenario.sh" "$scenario" > "$test_dir/output" 2>&1 || { cat "$test_dir/output"; printf 'FAIL %s\n' "$scenario"; exit 1; }
    printf 'PASS installer %s\n' "$scenario"
done
set +e
bash "$test_dir/scenario.sh" failed_exit > "$test_dir/output" 2>&1
status=$?
set -e
[[ $status != 0 ]] || { cat "$test_dir/output"; printf 'FAIL installer failure exit status\n'; exit 1; }
printf 'PASS installer failure returns nonzero\n'
