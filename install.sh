#!/bin/bash
# mc-tarpit installer — see SECURITY.md for what this script touches.
#
#   curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh
#   sudo bash install.sh --server-dir /home/mc/server
#
# Optional: verify the download against the SHA256SUMS asset, preview the
# changes with --check, skip the confirmation prompt with --yes, install
# without starting the service with --no-start, remove everything with
# --uninstall.
#
# --server-dir DIR   server with whitelist.json (auto-detected when omitted)
# --ports LIST       comma separated Minecraft ports (default 25565)
# --trust IP         IP to trust right away, repeatable (your player, LAN)
# --trust-subnets S  CIDRs never blocked, e.g. 192.168.0.0/24
# --tarpit-ttl T     how long an unknown login stays blocked (default 1d)
# --ping-ttl T       how long an untrusted ping stays blocked (default 1m)
# --table NAME       nftables table name (default mc_tarpit)
# --config PATH      config file to write (default /etc/mc-tarpit.conf)
# --sha256 HASH      expected sha256 of the downloaded release archive
# --check            print the plan and exit, change nothing
# --yes              do not ask for confirmation
# --no-start         install only, do not start the service
# --uninstall        remove service, config, script and nftables table
#
# A second run keeps an existing config and only rewrites the keys that were
# passed on the command line, so hand-tuned values survive a reinstall.
set -euo pipefail

REPO=${MC_TARPIT_REPO:-https://github.com/SergeLeon/minecraft-antibot-tarpit}
SERVER_DIR=""
PORTS="25565"
TRUST=()
TRUST_SUBNETS=""
TARPIT_TTL="1d"
PING_TTL="1m"
TABLE="mc_tarpit"
CONF=/etc/mc-tarpit.conf
UNIT=/etc/systemd/system/mc-tarpit.service
NFT_CONF=/etc/nftables.conf
PREFIX=/usr/local/bin
START=1
UNINSTALL=0
CHECK=0
YES=0
EXPECTED_SHA=""
declare -A GIVEN=()

usage() {
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --server-dir) SERVER_DIR=${2:-}; GIVEN[server_dir]=1; shift 2 ;;
        --ports) PORTS=${2:-}; GIVEN[ports]=1; shift 2 ;;
        --trust) TRUST+=("${2:-}"); shift 2 ;;
        --trust-subnets) TRUST_SUBNETS=${2:-}; GIVEN[trust_subnets]=1; shift 2 ;;
        --tarpit-ttl) TARPIT_TTL=${2:-}; GIVEN[tarpit_ttl]=1; shift 2 ;;
        --ping-ttl) PING_TTL=${2:-}; GIVEN[ping_ttl]=1; shift 2 ;;
        --table) TABLE=${2:-}; GIVEN[table]=1; shift 2 ;;
        --config) CONF=${2:-}; shift 2 ;;
        --sha256) EXPECTED_SHA=${2:-}; shift 2 ;;
        --check) CHECK=1; shift ;;
        --yes) YES=1; shift ;;
        --no-start) START=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo 'run as root: sudo bash install.sh --server-dir DIR' >&2; exit 1; }

detect_server_dir() {
    for dir in "$PWD" /home/*/mcserver /home/*/minecraft /srv/minecraft /srv/mc \
               /opt/minecraft /opt/mcserver /var/opt/minecraft; do
        [ -f "$dir/whitelist.json" ] && { printf '%s' "$dir"; return 0; }
    done
    return 1
}

PORT_LIST=$(echo "$PORTS" | tr ',' ' ' | xargs)
[ -n "$PORT_LIST" ] || { echo '--ports must not be empty' >&2; exit 1; }

print_plan() {
    cat <<TXT
plan
  tool          $PREFIX/mc_tarpit.py           (0755)
  config        $CONF$( [ -f "$CONF" ] && printf ' (kept, only the keys given on this run are updated)' )
                  server_dir    = $SERVER_DIR
                  ports         = $PORT_LIST
                  table         = $TABLE
                  trust_subnets = ${TRUST_SUBNETS:-<empty>}
                  tarpit_ttl    = $TARPIT_TTL
                  ping_ttl      = $PING_TTL
  systemd unit  $UNIT
  nftables      table inet $TABLE appended to $NFT_CONF (backup kept)
  trusted IPs   ${TRUST[*]:-<none>} -> $SERVER_DIR/tarpit-trusted.json
  service       mc-tarpit enabled$( [ "$START" = 1 ] && printf ' and started' )
  downloads     $REPO/releases/latest/download/mc-tarpit.tar.gz (only if no local sources)
TXT
}

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
    echo '== uninstalling'
    systemctl disable --now mc-tarpit 2>/dev/null || true
    rm -f "$UNIT" "$CONF" "$PREFIX/mc_tarpit.py"
    systemctl daemon-reload 2>/dev/null || true
    nft delete table inet "$TABLE" 2>/dev/null || true
    python3 - "$NFT_CONF" "$TABLE" <<'PY' || true
import re
import sys

path, table = sys.argv[1], sys.argv[2]
try:
    text = open(path, encoding='utf-8').read()
except OSError:
    sys.exit()
new = re.sub(r'\ntable inet %s \{.*?\n\}\n?' % re.escape(table), '\n', text, flags=re.S)
if new != text:
    open(path, 'w', encoding='utf-8').write(new)
    print('table block removed from', path)
PY
    systemctl restart nftables 2>/dev/null || true
    echo 'removed: service, config, script, nftables table'
    echo 'kept:    the trusted IP list inside the server directory'
    exit 0
fi

# ---------------------------------------------------------------- preflight
echo '== checking prerequisites'
missing=0
for tool in nft tcpdump python3; do
    if command -v "$tool" >/dev/null; then
        printf '   %-8s %s\n' "$tool" "$(command -v "$tool")"
    else
        printf '   %-8s MISSING\n' "$tool"
        missing=1
    fi
done
[ "$missing" = 0 ] || { echo "install the missing tools first (apt install nftables tcpdump python3)" >&2; exit 1; }

if [ -z "$SERVER_DIR" ]; then
    if SERVER_DIR=$(detect_server_dir); then
        echo "== server dir auto-detected: $SERVER_DIR"
    else
        echo 'server dir not found, pass --server-dir /path/to/server' >&2
        exit 1
    fi
fi
[ -f "$SERVER_DIR/whitelist.json" ] || echo "warning: $SERVER_DIR/whitelist.json not found" >&2

if [ "$CHECK" = 1 ]; then
    echo
    print_plan
    echo
    echo 'nothing was changed (--check)'
    exit 0
fi

# ---------------------------------------------------------------- sources
HERE=$(cd "$(dirname "$0")" && pwd)
if [ ! -f "$HERE/mc_tarpit.py" ] || [ ! -f "$HERE/contrib/nftables.conf" ]; then
    for tool in curl tar; do
        command -v "$tool" >/dev/null || { echo "$tool is needed to download the release" >&2; exit 1; }
    done
    echo "== downloading $REPO/releases/latest/download/mc-tarpit.tar.gz"
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    curl -fsSL "$REPO/releases/latest/download/mc-tarpit.tar.gz" -o "$TMP/mc-tarpit.tar.gz"
    ACTUAL_SHA=$(sha256sum "$TMP/mc-tarpit.tar.gz" | awk '{print $1}')
    echo "   sha256 $ACTUAL_SHA"
    if [ -n "$EXPECTED_SHA" ]; then
        if [ "$ACTUAL_SHA" = "$EXPECTED_SHA" ]; then
            echo '   sha256 matches the expected value'
        else
            echo 'sha256 mismatch: the archive is not the one that was published' >&2
            exit 1
        fi
    else
        echo '   compare this with the release page, or pass --sha256 HASH next time'
    fi
    tar -xzf "$TMP/mc-tarpit.tar.gz" -C "$TMP" --strip-components=1
    HERE=$TMP
fi

# ---------------------------------------------------------------- confirm
if [ "$YES" = 0 ] && [ -t 0 ]; then
    echo
    print_plan
    echo
    read -r -p 'continue? [y/N] ' answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) echo 'aborted, nothing changed'; exit 1 ;;
    esac
fi

# ---------------------------------------------------------------- script
echo "== script -> $PREFIX/mc_tarpit.py"
install -m 0755 "$HERE/mc_tarpit.py" "$PREFIX/mc_tarpit.py"

# ---------------------------------------------------------------- config
# config_set rewrites one key of the INI file and appends it when missing.
# Python instead of sed: paths and CIDRs may contain characters sed would
# interpret, and the key is matched exactly once.
config_set() {
    python3 - "$CONF" "$1" "$2" <<'PY'
import re
import sys

path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding='utf-8') as fh:
        lines = fh.readlines()
except OSError:
    lines = []
pattern = re.compile(r'^\s*%s\s*=' % re.escape(key))
out = []
written = False
for line in lines:
    if pattern.match(line):
        if not written:
            out.append('%s = %s\n' % (key, value))
            written = True
        continue
    out.append(line)
if not written:
    out.append('%s = %s\n' % (key, value))
with open(path, 'w', encoding='utf-8') as fh:
    fh.writelines(out)
PY
}

declare -A VALUE=(
    [server_dir]="$SERVER_DIR"
    [ports]="$PORT_LIST"
    [table]="$TABLE"
    [trust_subnets]="$TRUST_SUBNETS"
    [tarpit_ttl]="$TARPIT_TTL"
    [ping_ttl]="$PING_TTL"
)

echo "== config -> $CONF"
if [ -f "$CONF" ]; then
    cp -a "$CONF" "$CONF.bak-$(date +%Y%m%d-%H%M%S)"
    echo '   existing config kept (backup written), only the keys given on this run change'
    for key in "${!VALUE[@]}"; do
        if [ -n "${GIVEN[$key]:-}" ]; then
            config_set "$key" "${VALUE[$key]}"
        fi
    done
else
    install -m 0644 "$HERE/contrib/mc-tarpit.conf" "$CONF"
    for key in "${!VALUE[@]}"; do
        config_set "$key" "${VALUE[$key]}"
    done
fi
chmod 0644 "$CONF"

# ---------------------------------------------------------------- nftables
echo "== nftables"
if grep -q "table inet $TABLE" "$NFT_CONF" 2>/dev/null; then
    python3 - "$NFT_CONF" "$PORT_LIST" "$TABLE" <<'PY'
import re
import sys

path, ports, table = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding='utf-8').read()
pattern = r'(table inet %s \{.*?set ports \{.*?elements = \{)[^}]*(\})' % re.escape(table)
new, count = re.subn(pattern, lambda m: m.group(1) + ' ' + ports + ' ' + m.group(2),
                     text, count=1, flags=re.S)
if count:
    open(path, 'w', encoding='utf-8').write(new)
    print('ports updated to', ports)
else:
    print('warning: table has no `set ports`, edit %s manually' % path)
PY
else
    [ -f "$NFT_CONF" ] && cp -a "$NFT_CONF" "$NFT_CONF.bak-$(date +%Y%m%d-%H%M%S)"
    {
        echo
        sed "s|elements = { 25565 }|elements = { $PORT_LIST }|" "$HERE/contrib/nftables.conf"
    } >> "$NFT_CONF"
    echo "table appended to $NFT_CONF"
fi
systemctl enable nftables >/dev/null 2>&1 || true
if nft list table inet "$TABLE" >/dev/null 2>&1; then
    # A full reload of /etc/nftables.conf would wipe the contents of the
    # tarpit/pingsink sets, which exist only in the kernel, so touch the port
    # set of the running table instead.
    if nft flush set inet "$TABLE" ports \
       && nft add element inet "$TABLE" ports "{ $PORT_LIST }"; then
        echo "live port set updated to $PORT_LIST, blocked addresses kept"
    else
        echo 'warning: could not update the live port set, run: nft list ruleset' >&2
    fi
else
    SNIPPET=$(mktemp)
    sed "s|elements = { 25565 }|elements = { $PORT_LIST }|" "$HERE/contrib/nftables.conf" > "$SNIPPET"
    if nft -f "$SNIPPET"; then
        echo "table inet $TABLE loaded"
    else
        echo 'warning: nft -f failed, check /etc/nftables.conf' >&2
    fi
    rm -f "$SNIPPET"
fi
if nft list set inet "$TABLE" tarpit >/dev/null 2>&1; then
    echo 'sets are ready'
else
    echo 'warning: set tarpit not found, check: nft list ruleset' >&2
fi

# ---------------------------------------------------------------- systemd
echo "== systemd -> $UNIT"
install -m 0644 "$HERE/contrib/mc-tarpit.service" "$UNIT"
sed -i "s|^Environment=MC_TARPIT_CONFIG=.*|Environment=MC_TARPIT_CONFIG=$CONF|" "$UNIT"
systemctl daemon-reload
systemctl enable mc-tarpit >/dev/null
[ "$START" = 1 ] && systemctl restart mc-tarpit

# ---------------------------------------------------------------- trusted IPs
if [ ${#TRUST[@]} -gt 0 ]; then
    echo "== trusted IPs"
    "$PREFIX/mc_tarpit.py" --config "$CONF" trust "${TRUST[@]}"
fi

# ---------------------------------------------------------------- done
if [ "$START" = 1 ]; then
    sleep 2
    systemctl is-active mc-tarpit || true
    journalctl -u mc-tarpit --no-pager -n 3 2>/dev/null || true
fi

cat <<TXT

done. useful commands:
  sudo mc_tarpit.py status                 # config, sets, trusted IPs
  sudo journalctl -u mc-tarpit -f          # live decisions
  sudo mc_tarpit.py --mode log watch       # dry run
  sudo bash install.sh --uninstall         # remove everything
docs: $REPO/blob/main/DOCUMENTATION.md
TXT
