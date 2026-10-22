#!/bin/bash
# Install mc-tarpit: script, nftables table, systemd service.
#
#   sudo ./install.sh --server-dir /home/mc/server [--port 25565] [--trust IP]...
#
# --server-dir  directory with whitelist.json and ops.json (required)
# --port        Minecraft port (default 25565)
# --trust       IP to trust right away, repeatable (your own player)
set -euo pipefail

SERVER_DIR=""
PORT=25565
TRUST=()
PREFIX=/usr/local/bin
NFT_CONF=/etc/nftables.conf
UNIT=/etc/systemd/system/mc-tarpit.service

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --server-dir) SERVER_DIR=${2:-}; shift 2 ;;
        --port) PORT=${2:-}; shift 2 ;;
        --trust) TRUST+=("${2:-}"); shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ "$(id -u)" != 0 ]; then
    echo 'run as root: sudo ./install.sh --server-dir /path/to/server' >&2
    exit 1
fi
if [ -z "$SERVER_DIR" ]; then
    echo 'missing --server-dir' >&2
    exit 1
fi
for tool in nft tcpdump; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
[ -f "$SERVER_DIR/whitelist.json" ] || echo "warning: $SERVER_DIR/whitelist.json not found" >&2

HERE=$(cd "$(dirname "$0")" && pwd)

echo '== script'
install -m 0755 "$HERE/mc_tarpit.py" "$PREFIX/mc_tarpit.py"

echo '== nftables'
if grep -q 'table inet mc_tarpit' "$NFT_CONF" 2>/dev/null; then
    echo "table already present in $NFT_CONF"
else
    [ -f "$NFT_CONF" ] && cp -av "$NFT_CONF" "$NFT_CONF.bak-$(date +%Y%m%d-%H%M%S)"
    printf '\n' >> "$NFT_CONF"
    cat "$HERE/contrib/nftables.conf" >> "$NFT_CONF"
    echo "table appended to $NFT_CONF"
fi
systemctl enable nftables >/dev/null 2>&1 || true
systemctl restart nftables 2>/dev/null || nft -f "$HERE/contrib/nftables.conf"
nft list set inet mc_tarpit tarpit >/dev/null

echo '== systemd'
install -m 0644 "$HERE/contrib/mc-tarpit.service" "$UNIT"
sed -i "s|^Environment=MC_TARPIT_SERVER_DIR=.*|Environment=MC_TARPIT_SERVER_DIR=$SERVER_DIR|" "$UNIT"
if [ "$PORT" != 25565 ]; then
    sed -i "s|^Environment=MC_TARPIT_MODE=.*|&\nEnvironment=MC_TARPIT_PORT=$PORT|" "$UNIT"
fi
systemctl daemon-reload
systemctl enable mc-tarpit >/dev/null
systemctl restart mc-tarpit

echo '== trusted IPs'
if [ ${#TRUST[@]} -gt 0 ]; then
    python3 - "$SERVER_DIR" "${TRUST[@]}" <<'PY'
import json
import os
import sys
import time

server_dir, ips = sys.argv[1], sys.argv[2:]
path = os.path.join(server_dir, 'tarpit-trusted.json')
try:
    with open(path) as fh:
        data = json.load(fh)
except (OSError, ValueError):
    data = {}
now = time.time()
for ip in ips:
    data[ip] = now + 30 * 86400
with open(path, 'w') as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
print('trusted: ' + ', '.join(ips))
PY
else
    echo 'no --trust given; a player whose IP is unknown will be ping-blocked for MC_TARPIT_PING_TTL after the first ping'
fi

sleep 2
echo '== status'
systemctl is-active mc-tarpit
journalctl -u mc-tarpit --no-pager -n 5 || true
