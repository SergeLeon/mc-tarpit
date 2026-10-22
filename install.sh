#!/bin/bash
# Install mc-tarpit: script, nftables table, systemd service, config file.
#
#   sudo ./install.sh --server-dir /home/mc/server [options]
#
# --server-dir DIR   directory with whitelist.json and ops.json (required)
# --ports LIST       comma separated Minecraft ports (default 25565)
# --trust IP         IP to trust right away, repeatable (your player, LAN)
# --trust-subnets S  CIDRs never blocked, e.g. 192.168.0.0/24
# --table NAME       nftables table name (default mc_tarpit)
# --config PATH      config file to write (default /etc/mc-tarpit.conf)
# --no-start         install only, do not enable/start the service
set -euo pipefail

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

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --server-dir) SERVER_DIR=${2:-}; shift 2 ;;
        --ports) PORTS=${2:-}; shift 2 ;;
        --trust) TRUST+=("${2:-}"); shift 2 ;;
        --trust-subnets) TRUST_SUBNETS=${2:-}; shift 2 ;;
        --table) TABLE=${2:-}; shift 2 ;;
        --config) CONF=${2:-}; shift 2 ;;
        --no-start) START=0; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo 'run as root: sudo ./install.sh --server-dir DIR' >&2; exit 1; }
[ -n "$SERVER_DIR" ] || { echo 'missing --server-dir' >&2; exit 1; }
for tool in nft tcpdump python3; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
[ -f "$SERVER_DIR/whitelist.json" ] || echo "warning: $SERVER_DIR/whitelist.json not found" >&2

HERE=$(cd "$(dirname "$0")" && pwd)
PORT_LIST=$(echo "$PORTS" | tr ',' ' ' | xargs)

echo "== script -> $PREFIX/mc_tarpit.py"
install -m 0755 "$HERE/mc_tarpit.py" "$PREFIX/mc_tarpit.py"

echo "== config -> $CONF"
[ -f "$CONF" ] && cp -av "$CONF" "$CONF.bak-$(date +%Y%m%d-%H%M%S)"
sed -e "s|^server_dir = .*|server_dir = $SERVER_DIR|" \
    -e "s|^ports = .*|ports = $PORT_LIST|" \
    -e "s|^table = .*|table = $TABLE|" \
    -e "s|^trust_subnets = .*|trust_subnets = $TRUST_SUBNETS|" \
    "$HERE/contrib/mc-tarpit.conf" > "$CONF"
chmod 0644 "$CONF"

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
    [ -f "$NFT_CONF" ] && cp -av "$NFT_CONF" "$NFT_CONF.bak-$(date +%Y%m%d-%H%M%S)"
    {
        echo
        sed "s|elements = { 25565 }|elements = { $PORT_LIST }|" "$HERE/contrib/nftables.conf"
    } >> "$NFT_CONF"
    sed -i "s|^table inet mc_tarpit|table inet $TABLE|" "$NFT_CONF" 2>/dev/null || true
    echo "table appended to $NFT_CONF"
fi
systemctl enable nftables >/dev/null 2>&1 || true
systemctl restart nftables 2>/dev/null || nft -f "$NFT_CONF"
nft list set inet "$TABLE" tarpit >/dev/null && echo 'sets are ready'

echo "== systemd -> $UNIT"
install -m 0644 "$HERE/contrib/mc-tarpit.service" "$UNIT"
sed -i "s|^Environment=MC_TARPIT_CONFIG=.*|Environment=MC_TARPIT_CONFIG=$CONF|" "$UNIT"
systemctl daemon-reload
if [ "$START" = 1 ]; then
    systemctl enable mc-tarpit >/dev/null
    systemctl restart mc-tarpit
else
    systemctl enable mc-tarpit >/dev/null
fi

if [ ${#TRUST[@]} -gt 0 ]; then
    echo "== trusted IPs"
    "$PREFIX/mc_tarpit.py" --config "$CONF" trust "${TRUST[@]}"
fi

if [ "$START" = 1 ]; then
    sleep 2
    echo "== status"
    systemctl is-active mc-tarpit
    journalctl -u mc-tarpit --no-pager -n 5 || true
fi

cat <<TXT

done. next steps:
  sudo mc_tarpit.py --config $CONF status     # config, sets, trusted IPs
  sudo journalctl -u mc-tarpit -f             # live decisions
  sudo mc_tarpit.py --config $CONF replay capture.pcap   # offline test
TXT
