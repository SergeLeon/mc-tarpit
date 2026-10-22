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
# --table NAME       nftables table name (default mc_tarpit)
# --config PATH      config file to write (default /etc/mc-tarpit.conf)
# --sha256 HASH      expected sha256 of the downloaded release archive
# --check            print the plan and exit, change nothing
# --yes              do not ask for confirmation
# --no-start         install only, do not start the service
# --uninstall        remove service, config, script and nftables table
set -euo pipefail

REPO=${MC_TARPIT_REPO:-https://github.com/SergeLeon/minecraft-antibot-tarpit}
SERVER_DIR=""
PORTS="25565"
TRUST=()
TRUST_SUBNETS=""
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

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --server-dir) SERVER_DIR=${2:-}; shift 2 ;;
        --ports) PORTS=${2:-}; shift 2 ;;
        --trust) TRUST+=("${2:-}"); shift 2 ;;
        --trust-subnets) TRUST_SUBNETS=${2:-}; shift 2 ;;
        --table) TABLE=${2:-}; shift 2 ;;
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

print_plan() {
    cat <<TXT
plan
  tool          $PREFIX/mc_tarpit.py           (0755)
  config        $CONF
                  server_dir    = $SERVER_DIR
                  ports         = $PORT_LIST
                  table         = $TABLE
                  trust_subnets = ${TRUST_SUBNETS:-<empty>}
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
    text = open(path).read()
except OSError:
    sys.exit()
new = re.sub(r'\ntable inet %s \{.*?\n\}\n?' % re.escape(table), '\n', text, flags=re.S)
if new != text:
    open(path, 'w').write(new)
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
for tool in nft tcpdump python3 curl tar; do
    if command -v "$tool" >/dev/null; then
        printf '   %-8s %s\n' "$tool" "$(command -v "$tool")"
    else
        printf '   %-8s MISSING\n' "$tool"
        missing=1
    fi
done
[ "$missing" = 0 ] || { echo "install the missing tools first (apt install nftables tcpdump python3 curl)" >&2; exit 1; }

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
echo "== config -> $CONF"
[ -f "$CONF" ] && cp -a "$CONF" "$CONF.bak-$(date +%Y%m%d-%H%M%S)"
sed -e "s|^server_dir = .*|server_dir = $SERVER_DIR|" \
    -e "s|^ports = .*|ports = $PORT_LIST|" \
    -e "s|^table = .*|table = $TABLE|" \
    -e "s|^trust_subnets = .*|trust_subnets = $TRUST_SUBNETS|" \
    "$HERE/contrib/mc-tarpit.conf" > "$CONF"
chmod 0644 "$CONF"

# ---------------------------------------------------------------- nftables
echo "== nftables"
if grep -q "table inet $TABLE" "$NFT_CONF" 2>/dev/null; then
    python3 - "$NFT_CONF" "$PORT_LIST" "$TABLE" <<'PY'
import re
import sys

path, ports, table = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
pattern = r'(table inet %s \{.*?set ports \{.*?elements = \{)[^}]*(\})' % re.escape(table)
new, count = re.subn(pattern, lambda m: m.group(1) + ' ' + ports + ' ' + m.group(2),
                     text, count=1, flags=re.S)
if count:
    open(path, 'w').write(new)
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
systemctl restart nftables 2>/dev/null || nft -f "$NFT_CONF"
nft list set inet "$TABLE" tarpit >/dev/null && echo 'sets are ready'

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
