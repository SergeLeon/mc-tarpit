#!/usr/bin/env python3
"""mc-tarpit - drop Minecraft bots that probe your server.

Works as a passive side channel: tcpdump hands over copies of packets that go
to the Minecraft port, the tool parses the handshake and the Login Start, and
decides whether the source IP may talk to the server at all. Offenders are put
into nftables sets, the kernel then silently drops their traffic. Nothing is
ever inserted into the live connection path, so a bug can lose a decision but
never a player: every failure mode is fail-open.

Decision table
--------------

    login, name in whitelist.json / ops.json
        -> allowed, IP remembered in the trusted list for TRUST_TTL
    login, name unknown
        -> IP goes to set `tarpit` for TARPIT_TTL
    status ping from an IP that never logged in with a known name
        -> IP goes to set `pingsink` for PING_TTL
    everything else
        -> ignored

Status pings carry no username, so a stranger's very first ping is always
answered (the reply is already on the wire when we see the packet). Every
following connection from that IP is dropped, which is what keeps the server
out of bot server lists.

Configuration
-------------

All settings come from environment variables, see `CONFIG` below. The only
mandatory one is the server directory, because that is where
`whitelist.json` and `ops.json` live.

Usage
-----

    mc_tarpit.py watch                 # run as a service
    mc_tarpit.py selftest              # parser self-check, no network
    mc_tarpit.py ping                  # send a status ping to the server
    mc_tarpit.py login NAME            # send a login attempt with NAME
    mc_tarpit.py status                # show nftables sets and trusted IPs

Exit codes: 0 ok, 1 configuration/permission problem.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time

CONFIG = {
    # directory with whitelist.json and ops.json
    'server_dir': os.environ.get('MC_TARPIT_SERVER_DIR', '.'),
    # public Minecraft port to watch
    'port': int(os.environ.get('MC_TARPIT_PORT', '25565')),
    # 'drop' (real nftables drops) or 'log' (dry run)
    'mode': os.environ.get('MC_TARPIT_MODE', 'drop'),
    # nftables table and sets
    'table': os.environ.get('MC_TARPIT_TABLE', 'mc_tarpit'),
    'tarpit_set': 'tarpit',
    'pingsink_set': 'pingsink',
    # how long an offender stays blocked
    'tarpit_ttl': os.environ.get('MC_TARPIT_TARPIT_TTL', '1d'),
    'ping_ttl': os.environ.get('MC_TARPIT_PING_TTL', '15m'),
    # how long an IP that logged in with a known name is trusted
    'trust_ttl': int(os.environ.get('MC_TARPIT_TRUST_TTL', str(30 * 86400))),
    'trust_file': os.environ.get('MC_TARPIT_TRUST_FILE', 'tarpit-trusted.json'),
    # capture interface; 'any' is fine on Linux
    'iface': os.environ.get('MC_TARPIT_IFACE', 'any'),
    # protocol version used by the built-in test clients
    'protocol': int(os.environ.get('MC_TARPIT_PROTOCOL', '776')),
    # forget half-parsed flows after this many seconds
    'flow_ttl': 60.0,
    'max_buf': 4096,
}

PCAP_LINKTYPE_EN10MB = 1
PCAP_LINKTYPE_SLL = 113
PCAP_LINKTYPE_SLL2 = 276

IPV4_ETHERTYPE = 0x0800
TCP_PROTO = 6
SYN_FLAG = 0x02
LOGIN_STATE = 2


# --------------------------------------------------------------------------
# Minecraft protocol
# --------------------------------------------------------------------------
def read_varint(buf, pos):
    """Decode a VarInt, return (value, new_pos) or (None, pos) when truncated."""
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            return None, pos
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 35:
            return None, pos


def parse_client_stream(buf):
    """Parse handshake plus Login Start from the start of a client stream.

    Returns (next_state, name, raw_login):
        (None, None, None) - not enough bytes yet
        (1, None, None)    - status ping, no username available
        (2, name, raw)     - login attempt
    """
    pos = 0
    length, pos = read_varint(buf, pos)
    if length is None:
        return None, None, None
    end = pos + length
    if len(buf) < end:
        return None, None, None

    pid, q = read_varint(buf, pos)
    if pid != 0:
        return None, None, None
    _, q = read_varint(buf, q)          # protocol version
    addr_len, q = read_varint(buf, q)
    if addr_len is None:
        return None, None, None
    q += addr_len + 2                   # server address + port
    next_state, q = read_varint(buf, q)
    if next_state is None:
        return None, None, None
    if next_state != LOGIN_STATE:
        return next_state, None, None

    # Login Start: id 0x00, name (1..16 bytes), then the client UUID
    pos = end
    length, pos = read_varint(buf, pos)
    if length is None:
        return None, None, None
    if len(buf) < pos + length:
        return None, None, None
    raw = buf[pos:pos + length]
    pid, q = read_varint(raw, 0)
    if pid != 0:
        return None, None, None
    name_len, q = read_varint(raw, q)
    if name_len is None or name_len > 16:
        return None, None, None
    name = raw[q:q + name_len].decode('utf-8', 'replace')
    return LOGIN_STATE, name, raw[:40]


def encode_varint(value):
    out = b''
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def handshake(next_state, host='127.0.0.1', port=25565, protocol=776):
    body = encode_varint(0) + encode_varint(protocol) + encode_varint(len(host))
    body += host.encode() + struct.pack('>H', port) + encode_varint(next_state)
    return encode_varint(len(body)) + body


# --------------------------------------------------------------------------
# packet parsing
# --------------------------------------------------------------------------
def packet_payload(linktype, frame):
    """Return (src_ip, src_port, seq, flags, tcp_payload) for IPv4/TCP to our port."""
    if linktype == PCAP_LINKTYPE_SLL2:
        offset = 20
        if struct.unpack('>H', frame[0:2])[0] != IPV4_ETHERTYPE:
            return None
    elif linktype == PCAP_LINKTYPE_EN10MB:
        offset = 14
        if struct.unpack('>H', frame[12:14])[0] != IPV4_ETHERTYPE:
            return None
    elif linktype == PCAP_LINKTYPE_SLL:
        offset = 16
        if struct.unpack('>H', frame[14:16])[0] != IPV4_ETHERTYPE:
            return None
    else:
        return None

    ip = frame[offset:]
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != TCP_PROTO:
        return None
    header_len = (ip[0] & 0x0F) * 4
    src_ip = socket.inet_ntoa(ip[12:16])

    tcp = ip[header_len:]
    if len(tcp) < 20:
        return None
    src_port, dst_port = struct.unpack('>HH', tcp[0:4])
    if dst_port != CONFIG['port']:
        return None
    seq = struct.unpack('>I', tcp[4:8])[0]
    flags = tcp[13]
    data_offset = (tcp[12] >> 4) * 4
    return src_ip, src_port, seq, flags, tcp[data_offset:]


def read_pcap_frames(stream):
    """Yield (linktype, frame) from a classic pcap stream."""
    header = stream[:24]
    if len(header) < 24:
        return
    magic = header[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    linktype = struct.unpack(endian + 'I', header[20:24])[0]
    stream = stream[24:]
    while True:
        ph = stream[:16]
        if len(ph) < 16:
            return
        incl_len = struct.unpack(endian + 'I', ph[8:12])[0]
        frame = stream[16:16 + incl_len]
        if len(frame) < incl_len:
            return
        yield linktype, frame
        stream = stream[16 + incl_len:]


# --------------------------------------------------------------------------
# whitelist and trusted IPs
# --------------------------------------------------------------------------
def allowed_names(server_dir):
    """Names from whitelist.json and ops.json, lowercased."""
    names = set()
    for filename in ('whitelist.json', 'ops.json'):
        try:
            with open(os.path.join(server_dir, filename), encoding='utf-8') as fh:
                for item in json.load(fh):
                    name = item.get('name')
                    if name:
                        names.add(name.lower())
        except (OSError, ValueError):
            continue
    return names


def trust_path(server_dir):
    path = CONFIG['trust_file']
    return path if os.path.isabs(path) else os.path.join(server_dir, path)


def load_trusted(server_dir):
    try:
        with open(trust_path(server_dir), encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    now = time.time()
    return {ip: expiry for ip, expiry in data.items() if expiry > now}


def save_trusted(server_dir, data):
    path = trust_path(server_dir)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write('\n')
    os.replace(tmp, path)


def is_trusted(data, ip, now=None):
    return (now or time.time()) < data.get(ip, 0)


# --------------------------------------------------------------------------
# nftables
# --------------------------------------------------------------------------
def nft_add(set_name, ip, ttl):
    if CONFIG['mode'] != 'drop':
        return True
    cmd = ['nft', 'add', 'element', 'inet', CONFIG['table'], set_name,
           '{', ip, 'timeout', ttl, '}']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print('nft %s failed for %s: %s' % (set_name, ip, result.stderr.strip()))
        return False
    return True


# --------------------------------------------------------------------------
# watcher
# --------------------------------------------------------------------------
def watch():
    cmd = ['tcpdump', '-i', CONFIG['iface'], '-n', '-s', '0', '-U', '-w', '-',
           'tcp dst port %d' % CONFIG['port']]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    stream = proc.stdout

    header = stream.read(24)
    if len(header) < 24:
        print('tcpdump did not start')
        return 1
    magic = header[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    linktype = struct.unpack(endian + 'I', header[20:24])[0]

    server_dir = CONFIG['server_dir']
    names = allowed_names(server_dir)
    names_at = time.time()
    trusted = load_trusted(server_dir)
    trusted_at = time.time()
    flows = {}

    print('watching port %d, mode=%s, linktype=%d, trusted=%d'
          % (CONFIG['port'], CONFIG['mode'], linktype, len(trusted)))

    while True:
        ph = stream.read(16)
        if len(ph) < 16:
            break
        incl_len = struct.unpack(endian + 'I', ph[8:12])[0]
        frame = stream.read(incl_len)
        if len(frame) < incl_len:
            break

        packet = packet_payload(linktype, frame)
        if not packet:
            continue
        src, src_port, seq, flags, payload = packet
        now = time.time()
        key = (src, src_port)

        # Only connections whose first packet (SYN) we saw are parsed. Packets
        # of a session that was already established when we started look like
        # handshakes to a naive parser and would block real players.
        if flags & SYN_FLAG:
            flows[key] = {'buf': bytearray(), 'seq': seq + 1,
                          'at': now, 'done': False}
            continue

        flow = flows.get(key)
        if flow is None:
            continue
        if now - flow['at'] > CONFIG['flow_ttl']:
            del flows[key]
            continue
        flow['at'] = now
        if flow['done'] or not payload:
            continue

        expected = flow['seq'] + len(flow['buf'])
        if seq == expected:
            room = CONFIG['max_buf'] - len(flow['buf'])
            flow['buf'] += payload[:room]
        elif seq > expected:
            flow['done'] = True
            continue
        else:
            continue

        state, name, raw = parse_client_stream(bytes(flow['buf']))
        if state is None:
            continue
        flow['done'] = True

        if now - names_at > 30:
            names = allowed_names(server_dir)
            names_at = now
        if now - trusted_at > 300:
            trusted = load_trusted(server_dir)
            trusted_at = now

        if name is None:
            if not is_trusted(trusted, src):
                print('ping %s:%d -> %s %s (not trusted)'
                      % (src, src_port, CONFIG['pingsink_set'], CONFIG['ping_ttl']))
                nft_add(CONFIG['pingsink_set'], src, CONFIG['ping_ttl'])
            continue

        known = name.lower() in names
        print('login %s:%d name=%r %s raw=%s'
              % (src, src_port, name, 'ok' if known else 'not-whitelisted', raw.hex()))
        if known:
            if not is_trusted(trusted, src):
                trusted[src] = now + CONFIG['trust_ttl']
                save_trusted(server_dir, trusted)
                trusted_at = now
                print('trust %s (%ds)' % (src, CONFIG['trust_ttl']))
        else:
            nft_add(CONFIG['tarpit_set'], src, CONFIG['tarpit_ttl'])

        if len(flows) > 5000:
            for stale in [k for k, v in flows.items() if now - v['at'] > CONFIG['flow_ttl']]:
                del flows[stale]

    return 0


# --------------------------------------------------------------------------
# test clients and status
# --------------------------------------------------------------------------
def send_login(name, host='127.0.0.1', port=None):
    port = port or CONFIG['port']
    login = encode_varint(0) + encode_varint(len(name)) + name.encode() + b'\x00' * 16
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(handshake(2, host, port, CONFIG['protocol'])
                 + encode_varint(len(login)) + login)
    time.sleep(1)
    sock.close()
    print('sent login as %r to %s:%d' % (name, host, port))


def send_ping(host='127.0.0.1', port=None):
    port = port or CONFIG['port']
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(handshake(1, host, port, CONFIG['protocol'])
                 + encode_varint(1) + encode_varint(0))
    time.sleep(1)
    sock.close()
    print('sent status ping to %s:%d' % (host, port))


def show_status():
    for set_name in (CONFIG['tarpit_set'], CONFIG['pingsink_set']):
        cmd = ['nft', 'list', 'set', 'inet', CONFIG['table'], set_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print('%s: %s' % (set_name, result.stderr.strip() or 'unavailable'))
            continue
        print('%s:' % set_name)
        for line in result.stdout.splitlines():
            if 'elements' in line or 'timeout' in line:
                print('  ' + line.strip())
    trusted = load_trusted(CONFIG['server_dir'])
    print('trusted (%d):' % len(trusted))
    for ip, expiry in sorted(trusted.items()):
        left = int(expiry - time.time())
        print('  %s  %dd%02dh' % (ip, left // 86400, left % 86400 // 3600))


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------
def sll2_frame(src_ip, src_port, seq, payload, dst_ip='192.168.0.19'):
    ip = b'\x45\x00' + struct.pack('>H', 20 + 20 + len(payload)) + b'\x00\x00\x00\x00'
    ip += b'\x40\x06\x00\x00' + socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    tcp = struct.pack('>HHII', src_port, CONFIG['port'], seq, 0)
    tcp += b'\x50\x18\xff\xff\x00\x00\x00\x00'
    return struct.pack('>H', IPV4_ETHERTYPE) + b'\x00' * 18 + ip + tcp + payload


def selftest():
    """Offline check of the parser: no sniffing, no network, no nftables."""
    host = '127.0.0.1'
    hs = (encode_varint(0) + encode_varint(CONFIG['protocol'])
          + encode_varint(len(host)) + host.encode()
          + struct.pack('>H', CONFIG['port']) + encode_varint(2))
    login = encode_varint(0) + encode_varint(7) + b'TestBot' + b'\x00' * 16
    stream = encode_varint(len(hs)) + hs + encode_varint(len(login)) + login

    pcap = b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00' * 8
    pcap += b'\xff\xff\x00\x00' + struct.pack('<I', PCAP_LINKTYPE_SLL2)
    for offset in (0, 20, 40):
        frame = sll2_frame('203.0.113.9', 50000, 1000 + offset, stream[offset:offset + 20])
        pcap += struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame

    reassembled = b''
    name = None
    for linktype, frame in read_pcap_frames(pcap):
        packet = packet_payload(linktype, frame)
        assert packet, 'frame was not parsed'
        reassembled += packet[4]
        state, name, _ = parse_client_stream(reassembled)
        if name:
            break
    assert name == 'TestBot', 'expected TestBot, parsed %r' % (name,)
    print('ok: login start parse -> %r' % name)

    status = (encode_varint(0) + encode_varint(CONFIG['protocol'])
              + encode_varint(len(host)) + host.encode()
              + struct.pack('>H', CONFIG['port']) + encode_varint(1))
    state, _, _ = parse_client_stream(encode_varint(len(status)) + status + b'\x01\x00')
    assert state == 1, 'status ping misparsed: %r' % (state,)
    print('ok: status ping recognised')

    state, _, _ = parse_client_stream(encode_varint(len(status)) + status[:-3])
    assert state is None, 'truncated handshake must wait for more bytes'
    print('ok: truncated stream waits')

    state, _, _ = parse_client_stream(b'\x00\xff\xff\xff')
    assert state is None, 'garbage must not produce a login'
    print('ok: garbage rejected')

    names = allowed_names(CONFIG['server_dir'])
    assert 'testbot' not in names, 'whitelist read returned garbage'
    print('ok: whitelist read (%d names)' % len(names))

    now = time.time()
    fake = {'10.0.0.1': now + 60, '10.0.0.2': now - 60}
    assert is_trusted(fake, '10.0.0.1', now)
    assert not is_trusted(fake, '10.0.0.2', now)
    assert not is_trusted(fake, '10.0.0.3', now)
    print('ok: trusted ip logic')
    return 0


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='mc_tarpit',
        description='Drop Minecraft bots that probe your server (nftables side channel).')
    parser.add_argument('-d', '--server-dir', default=None,
                        help='directory with whitelist.json/ops.json '
                             '(env MC_TARPIT_SERVER_DIR, default: cwd)')
    parser.add_argument('--mode', default=None, choices=('drop', 'log'),
                        help='drop: real nftables drops, log: dry run '
                             '(env MC_TARPIT_MODE, default: drop)')
    parser.add_argument('--port', type=int, default=None,
                        help='Minecraft port (env MC_TARPIT_PORT, default: 25565)')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('watch', help='watch traffic and enforce decisions')
    sub.add_parser('selftest', help='offline parser self-check')
    sub.add_parser('status', help='show blocked and trusted IPs')
    ping = sub.add_parser('ping', help='send a status ping to the server')
    ping.add_argument('--host', default='127.0.0.1')
    login = sub.add_parser('login', help='send a login attempt with the given name')
    login.add_argument('name')
    login.add_argument('--host', default='127.0.0.1')

    args = parser.parse_args(argv)
    if args.server_dir:
        CONFIG['server_dir'] = args.server_dir
    if args.mode:
        CONFIG['mode'] = args.mode
    if args.port:
        CONFIG['port'] = args.port

    command = args.command or 'watch'
    if command == 'selftest':
        return selftest()
    if command == 'status':
        show_status()
        return 0
    if command == 'ping':
        send_ping(args.host)
        return 0
    if command == 'login':
        send_login(args.name, args.host)
        return 0
    return watch()


if __name__ == '__main__':
    sys.exit(main())
