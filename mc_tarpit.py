#!/usr/bin/env python3
"""mc-tarpit - drop Minecraft bots that probe your server.

A passive sniffer watches the Minecraft ports, parses the handshake and the
`Login Start` packet, and decides whether a source may talk to the server.
Offenders land in nftables sets that silently drop their traffic, so scanners
cannot even tell the server is alive. Nothing is inserted into the live
connection path: tcpdump hands over copies, the kernel enforces. Every failure
mode is fail-open, a broken parse never blocks anybody.

Decisions
---------

    source IP matches trust_subnets            -> always allowed, ignored
    login, name in whitelist/ops/names file    -> allowed, IP trusted for trust_ttl
    login, unknown name                        -> tarpit set, tarpit_ttl
    status ping, IP not trusted                -> pingsink set, ping_ttl
    login_policy = log                         -> unknown logins are only logged
    ping_policy  = ignore                      -> pings are never acted upon

Both IPv4 and IPv6 are supported, any number of ports, and the configuration
can come from a file, the environment and the command line (in that order of
increasing precedence).

Usage
-----

    mc_tarpit.py watch                 # run as a service
    mc_tarpit.py status                # effective config, sets, trusted IPs
    mc_tarpit.py selftest              # offline parser self-check
    mc_tarpit.py replay FILE.pcap      # replay a capture, print decisions
    mc_tarpit.py ping  [--host H]      # send a status ping
    mc_tarpit.py login NAME [--host H] # send a login attempt
    mc_tarpit.py trust IP...           # add IPs to the trusted list
    mc_tarpit.py untrust IP...         # remove them

Configuration keys (config file, `MC_TARPIT_<KEY>` env, `--<key>` CLI):

    server_dir      dir with whitelist.json / ops.json      (default: .)
    ports           comma separated Minecraft ports         (default: 25565)
    mode            drop | log                              (default: drop)
    ping_policy     sink | ignore                           (default: sink)
    login_policy    tarpit | log                            (default: tarpit)
    tarpit_ttl      nftables timeout for unknown logins     (default: 1d)
    ping_ttl        nftables timeout for untrusted pings    (default: 15m)
    trust_ttl       seconds an IP stays trusted             (default: 2592000)
    trust_file      trusted IP list, relative to server_dir (default: tarpit-trusted.json)
    names_file      extra allowed nicknames, one per line   (default: tarpit-names.txt)
    trust_subnets   CIDRs that are never blocked            (default: empty)
    table           nftables table name                     (default: mc_tarpit)
    iface           capture interface                       (default: any)
    protocol        protocol version for the test clients   (default: 776)
    log_level       debug | info | warn                     (default: info)
    log_file        append log lines to this file           (default: stdout)
"""

import argparse
import configparser
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import time

VERSION = '0.2.0'

DEFAULTS = {
    'server_dir': '.',
    'ports': '25565',
    'mode': 'drop',
    'ping_policy': 'sink',
    'login_policy': 'tarpit',
    'tarpit_ttl': '1d',
    'ping_ttl': '15m',
    'trust_ttl': '2592000',
    'trust_file': 'tarpit-trusted.json',
    'names_file': 'tarpit-names.txt',
    'trust_subnets': '',
    'table': 'mc_tarpit',
    'iface': 'any',
    'protocol': '776',
    'log_level': 'info',
    'log_file': '',
}

CHOICES = {
    'mode': ('drop', 'log'),
    'ping_policy': ('sink', 'ignore'),
    'login_policy': ('tarpit', 'log'),
    'log_level': ('debug', 'info', 'warn'),
}

LOG_LEVELS = {'debug': 0, 'info': 1, 'warn': 2}

PROTO_LOGIN = 2

PCAP_LINKTYPE_EN10MB = 1
PCAP_LINKTYPE_SLL = 113
PCAP_LINKTYPE_SLL2 = 276
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
TCP_PROTO = 6
SYN_FLAG = 0x02
IPV4_HEADER = 20
IPV6_HEADER = 40
TCP_HEADER = 20

STATE = {'level': 1, 'file': ''}


# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------
def setup_log(cfg):
    STATE['level'] = LOG_LEVELS[cfg['log_level']]
    STATE['file'] = cfg['log_file']


def log(message, level='info'):
    if LOG_LEVELS[level] < STATE['level']:
        return
    line = '%s %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), message)
    if STATE['file']:
        try:
            with open(STATE['file'], 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
            return
        except OSError:
            pass
    print(line, flush=True)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
def read_config_file(path):
    """Read an INI file, any section name, only known keys are used."""
    parser = configparser.ConfigParser()
    if not parser.read(path):
        raise SystemExit('config file not readable: %s' % path)
    values = {}
    for section in parser.sections():
        for key, value in parser.items(section):
            key = key.replace('-', '_')
            if key in DEFAULTS:
                values[key] = value
    return values


def load_config(config_path=None, overrides=None):
    """defaults < config file < environment < command line"""
    cfg = dict(DEFAULTS)
    path = config_path or os.environ.get('MC_TARPIT_CONFIG')
    if path:
        cfg.update(read_config_file(path))
    for key in DEFAULTS:
        env = 'MC_TARPIT_' + key.upper()
        if env in os.environ:
            cfg[key] = os.environ[env]
    if 'MC_TARPIT_PORT' in os.environ and 'MC_TARPIT_PORTS' not in os.environ:
        cfg['ports'] = os.environ['MC_TARPIT_PORT']
    for key, value in (overrides or {}).items():
        if value is not None and key in DEFAULTS:
            cfg[key] = value
    return normalize(cfg)


def normalize(cfg):
    ports = str(cfg['ports']).replace(',', ' ').split()
    try:
        cfg['ports'] = sorted({int(p) for p in ports})
    except ValueError:
        raise SystemExit('ports must be numbers: %r' % cfg['ports'])
    if not cfg['ports']:
        raise SystemExit('at least one port is required')
    for key in ('trust_ttl', 'protocol'):
        try:
            cfg[key] = int(cfg[key])
        except ValueError:
            raise SystemExit('%s must be an integer: %r' % (key, cfg[key]))
    for key, allowed in CHOICES.items():
        if cfg[key] not in allowed:
            raise SystemExit('%s must be one of %s, got %r'
                             % (key, '/'.join(allowed), cfg[key]))
    subnets = []
    for item in str(cfg['trust_subnets']).replace(',', ' ').split():
        try:
            subnets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise SystemExit('bad subnet in trust_subnets: %r' % item)
    cfg['subnets'] = subnets
    return cfg


def describe_config(cfg):
    rows = [('server_dir', cfg['server_dir']),
            ('ports', ','.join(str(p) for p in cfg['ports'])),
            ('mode', cfg['mode']),
            ('ping_policy', cfg['ping_policy']),
            ('login_policy', cfg['login_policy']),
            ('tarpit_ttl', cfg['tarpit_ttl']),
            ('ping_ttl', cfg['ping_ttl']),
            ('trust_ttl', '%d s' % cfg['trust_ttl']),
            ('trust_file', trust_path(cfg)),
            ('names_file', names_path(cfg)),
            ('trust_subnets', ','.join(str(s) for s in cfg['subnets']) or '-'),
            ('table', cfg['table']),
            ('iface', cfg['iface']),
            ('protocol', cfg['protocol']),
            ('log_level', cfg['log_level']),
            ('log_file', cfg['log_file'] or '-')]
    return rows


# --------------------------------------------------------------------------
# Minecraft protocol
# --------------------------------------------------------------------------
def read_varint(buf, pos):
    """Read a Minecraft varint: at most five bytes (32 bit)."""
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
        if shift > 28:
            return None, pos


def parse_client_stream(buf):
    """(next_state, name, raw_login) from handshake + Login Start.

    (None, None, None) - not enough bytes yet
    (1, None, None)    - status ping
    (2, name, raw)     - login attempt
    """
    pos = 0
    length, pos = read_varint(buf, pos)
    if length is None:
        return None, None, None
    end = pos + length
    if len(buf) < end:
        return None, None, None

    pid, cursor = read_varint(buf, pos)
    if pid != 0:
        return None, None, None
    _, cursor = read_varint(buf, cursor)
    addr_len, cursor = read_varint(buf, cursor)
    if addr_len is None:
        return None, None, None
    cursor += addr_len + 2
    next_state, cursor = read_varint(buf, cursor)
    if next_state is None:
        return None, None, None
    if next_state != PROTO_LOGIN:
        return next_state, None, None

    pos = end
    length, pos = read_varint(buf, pos)
    if length is None:
        return None, None, None
    if len(buf) < pos + length:
        return None, None, None
    raw = buf[pos:pos + length]
    pid, cursor = read_varint(raw, 0)
    if pid != 0:
        return None, None, None
    name_len, cursor = read_varint(raw, cursor)
    if name_len is None or name_len > 16:
        return None, None, None
    return PROTO_LOGIN, raw[cursor:cursor + name_len].decode('utf-8', 'replace'), raw[:40]


def encode_varint(value):
    out = b''
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def handshake(next_state, host, port, protocol):
    body = encode_varint(0) + encode_varint(protocol) + encode_varint(len(host))
    body += host.encode() + struct.pack('>H', port) + encode_varint(next_state)
    return encode_varint(len(body)) + body


# --------------------------------------------------------------------------
# packet parsing
# --------------------------------------------------------------------------
def _transport_offset(linktype, frame):
    """Return (ethertype, ip_offset) for a frame, or (None, 0).

    Ethernet frames may carry VLAN / QinQ tags, so the ethertype is read where
    it actually is instead of assuming it sits at a fixed offset.
    """
    if linktype == PCAP_LINKTYPE_SLL2:
        if len(frame) < 22:
            return None, 0
        return struct.unpack('>H', frame[0:2])[0], 20
    if linktype == PCAP_LINKTYPE_SLL:
        if len(frame) < 16:
            return None, 0
        return struct.unpack('>H', frame[14:16])[0], 16
    if linktype == PCAP_LINKTYPE_EN10MB:
        if len(frame) < 14:
            return None, 0
        ethertype = struct.unpack('>H', frame[12:14])[0]
        offset = 14
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
            if len(frame) < offset + 4:
                return None, 0
            ethertype = struct.unpack('>H', frame[offset + 2:offset + 4])[0]
            offset += 4
        return ethertype, offset
    return None, 0


def packet_payload(linktype, frame, ports):
    """(src_ip, src_port, seq, flags, payload) for TCP to one of our ports.

    Every length in the headers is checked before it is used, because a frame
    from a hostile peer is just bytes: anything inconsistent returns None and
    the packet is ignored (fail-open).

    IPv6 extension headers are not followed: a packet with one is ignored.
    """
    ethertype, offset = _transport_offset(linktype, frame)
    if ethertype == ETHERTYPE_IPV4:
        ip = frame[offset:]
        if len(ip) < IPV4_HEADER or (ip[0] >> 4) != 4 or ip[9] != TCP_PROTO:
            return None
        header_len = (ip[0] & 0x0F) * 4
        if header_len < IPV4_HEADER or header_len > len(ip):
            return None
        # the total length trims the ethernet padding of a short frame
        total = struct.unpack('>H', ip[2:4])[0]
        if total < header_len + TCP_HEADER:
            return None
        src_ip = socket.inet_ntoa(ip[12:16])
        tcp = ip[header_len:min(total, len(ip))]
    elif ethertype == ETHERTYPE_IPV6:
        ip = frame[offset:]
        if len(ip) < IPV6_HEADER or (ip[0] >> 4) != 6 or ip[6] != TCP_PROTO:
            return None
        payload_len = struct.unpack('>H', ip[4:6])[0]
        end = IPV6_HEADER + payload_len
        if payload_len == 0 or end > len(ip):
            end = len(ip)      # jumbogram or truncated capture
        src_ip = socket.inet_ntop(socket.AF_INET6, ip[8:24])
        tcp = ip[IPV6_HEADER:end]
    else:
        return None

    if len(tcp) < TCP_HEADER:
        return None
    src_port, dst_port = struct.unpack('>HH', tcp[0:4])
    if dst_port not in ports:
        return None
    seq = struct.unpack('>I', tcp[4:8])[0]
    flags = tcp[13]
    data_offset = (tcp[12] >> 4) * 4
    if data_offset < TCP_HEADER or data_offset > len(tcp):
        return None
    return src_ip, src_port, seq, flags, tcp[data_offset:]


def read_pcap_frames(stream):
    """Yield (linktype, frame) from a classic pcap file given as bytes."""
    header = stream[:24]
    if len(header) < 24:
        return
    endian = '<' if header[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    linktype = struct.unpack(endian + 'I', header[20:24])[0]
    stream = stream[24:]
    while True:
        record = stream[:16]
        if len(record) < 16:
            return
        incl_len = struct.unpack(endian + 'I', record[8:12])[0]
        frame = stream[16:16 + incl_len]
        if len(frame) < incl_len:
            return
        yield linktype, frame
        stream = stream[16 + incl_len:]


# --------------------------------------------------------------------------
# flow reassembly
# --------------------------------------------------------------------------
FLOW_TIMEOUT = 60
FLOW_MAX_BYTES = 4096
FLOW_MAX_SLOTS = 8192


class FlowTracker:
    """Rebuild the client byte stream of a flow and parse it once.

    Only flows whose SYN was observed are tracked: packets of a session that
    was already established when we started look like a handshake to a naive
    parser and would block real players.
    """

    def __init__(self, ports, timeout=FLOW_TIMEOUT, max_bytes=FLOW_MAX_BYTES,
                 max_slots=FLOW_MAX_SLOTS):
        self.ports = ports
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_slots = max_slots
        self.swept = 0.0
        self.flows = {}

    def feed(self, linktype, frame, now=None):
        """(src, state, name) once a flow produced a decision, else None."""
        packet = packet_payload(linktype, frame, self.ports)
        if packet is None:
            return None
        src, src_port, seq, flags, payload = packet
        now = now or time.time()
        key = (src, src_port)

        if flags & SYN_FLAG:
            self.open(key, seq + 1, now)
            return None

        flow = self.flows.get(key)
        if flow is None:
            return None
        if now - flow['at'] > self.timeout:
            del self.flows[key]
            return None
        flow['at'] = now
        if flow['done'] or not payload:
            return None

        expected = flow['seq'] + len(flow['buf'])
        if seq > expected:
            flow['done'] = True        # gap: the stream is unusable
            return None
        if seq < expected:
            return None                # a retransmission we already have

        flow['buf'] += payload[:self.max_bytes - len(flow['buf'])]
        state, name, raw = parse_client_stream(bytes(flow['buf']))
        if state is None:
            return None
        flow['done'] = True
        if raw:
            log('raw %s name=%r %s' % (src, name, raw.hex()), 'debug')
        return src, state, name

    def open(self, key, seq, now):
        """Track a new flow, keeping the table inside max_slots."""
        if len(self.flows) >= self.max_slots:
            self.sweep(now)
        while len(self.flows) >= self.max_slots:
            self.flows.pop(next(iter(self.flows)))   # oldest flow first
        self.flows[key] = {'buf': bytearray(), 'seq': seq, 'at': now, 'done': False}

    def sweep(self, now):
        """Forget expired flows at most once a second.

        Without a cap a SYN flood from many sources grows the table without
        limit; the FIFO eviction in open() keeps memory flat, this keeps it
        from evicting flows that still matter.
        """
        if now - self.swept < 1.0:
            return
        self.swept = now
        for key in [k for k, v in self.flows.items() if now - v['at'] > self.timeout]:
            del self.flows[key]


# --------------------------------------------------------------------------
# names and trusted IPs
# --------------------------------------------------------------------------
def names_path(cfg):
    path = cfg['names_file']
    return path if os.path.isabs(path) else os.path.join(cfg['server_dir'], path)


def trust_path(cfg):
    path = cfg['trust_file']
    return path if os.path.isabs(path) else os.path.join(cfg['server_dir'], path)


def allowed_names(cfg):
    """Nicknames from whitelist.json, ops.json and the extra names file."""
    names = set()
    for filename in ('whitelist.json', 'ops.json'):
        try:
            with open(os.path.join(cfg['server_dir'], filename), encoding='utf-8') as fh:
                for item in json.load(fh):
                    name = item.get('name')
                    if name:
                        names.add(name.lower())
        except (OSError, ValueError):
            continue
    try:
        with open(names_path(cfg), encoding='utf-8') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()
                if line:
                    names.add(line.lower())
    except OSError:
        pass
    return names


def load_trusted(cfg):
    try:
        with open(trust_path(cfg), encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    now = time.time()
    return {ip: expiry for ip, expiry in data.items()
            if isinstance(expiry, (int, float)) and expiry > now}


def save_trusted(cfg, data):
    path = trust_path(cfg)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write('\n')
    os.replace(tmp, path)


def is_trusted(data, ip, now=None):
    return (now or time.time()) < data.get(ip, 0)


def is_ignored(subnets, ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in subnet for subnet in subnets)


# --------------------------------------------------------------------------
# nftables
# --------------------------------------------------------------------------
def nft_set_name(kind, ip):
    return kind + ('6' if ':' in ip else '')


def nft_add(cfg, kind, ip, ttl):
    if cfg['mode'] != 'drop':
        return True
    set_name = nft_set_name(kind, ip)
    cmd = ['nft', 'add', 'element', 'inet', cfg['table'], set_name,
           '{', ip, 'timeout', ttl, '}']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log('nft %s failed for %s: %s' % (set_name, ip, result.stderr.strip()), 'warn')
        return False
    return True


def tarpit(cfg, ip, ttl):
    log('tarpit %s -> %s %s' % (ip, nft_set_name('tarpit', ip), ttl))
    nft_add(cfg, 'tarpit', ip, ttl)


def ping_sink(cfg, ip):
    log('ping %s -> %s %s (not trusted)' % (ip, nft_set_name('pingsink', ip), cfg['ping_ttl']))
    nft_add(cfg, 'pingsink', ip, cfg['ping_ttl'])


# --------------------------------------------------------------------------
# decision making (shared by watch and replay)
# --------------------------------------------------------------------------
class Decider:
    """Turn parsed streams into actions, with the config cached."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.names = allowed_names(cfg)
        self.names_at = time.time()
        self.trusted = load_trusted(cfg)
        self.trusted_at = time.time()

    def refresh(self, now):
        if now - self.names_at > 30:
            self.names = allowed_names(self.cfg)
            self.names_at = now
        if now - self.trusted_at > 300:
            self.trusted = load_trusted(self.cfg)
            self.trusted_at = now

    def decide(self, ip, state, name):
        cfg = self.cfg
        now = time.time()
        self.refresh(now)

        if is_ignored(cfg['subnets'], ip):
            log('ignore %s (trust_subnets)' % ip, 'debug')
            return 'ignore'

        if name is None:
            if cfg['ping_policy'] == 'ignore':
                log('ping %s (ping_policy=ignore)' % ip, 'debug')
                return 'ignore'
            if is_trusted(self.trusted, ip):
                log('ping %s (trusted)' % ip, 'debug')
                return 'allow'
            ping_sink(cfg, ip)
            return 'pingsink'

        known = name.lower() in self.names
        log('login %s name=%r %s' % (ip, name, 'ok' if known else 'not-whitelisted'))
        if known:
            if not is_trusted(self.trusted, ip):
                self.trusted[ip] = now + cfg['trust_ttl']
                save_trusted(cfg, self.trusted)
                self.trusted_at = now
                log('trust %s (%ds)' % (ip, cfg['trust_ttl']))
            return 'allow'
        if cfg['login_policy'] == 'log':
            log('login %s ignored (login_policy=log)' % ip)
            return 'ignore'
        tarpit(cfg, ip, cfg['tarpit_ttl'])
        return 'tarpit'


# --------------------------------------------------------------------------
# watching live traffic
# --------------------------------------------------------------------------
def tcpdump_filter(ports):
    return ' or '.join('tcp dst port %d' % port for port in ports)


def watch(cfg):
    cmd = ['tcpdump', '-i', cfg['iface'], '-n', '-s', '0', '-U',
           '-w', '-', tcpdump_filter(cfg['ports'])]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    header = proc.stdout.read(24)
    if len(header) < 24:
        log('tcpdump did not start', 'warn')
        return 1
    endian = '<' if header[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    linktype = struct.unpack(endian + 'I', header[20:24])[0]

    decider = Decider(cfg)
    tracker = FlowTracker(set(cfg['ports']))
    log('watching ports=%s mode=%s ping_policy=%s login_policy=%s linktype=%d trusted=%d'
        % (','.join(str(p) for p in cfg['ports']), cfg['mode'], cfg['ping_policy'],
           cfg['login_policy'], linktype, len(decider.trusted)))

    while True:
        record = proc.stdout.read(16)
        if len(record) < 16:
            break
        incl_len = struct.unpack(endian + 'I', record[8:12])[0]
        frame = proc.stdout.read(incl_len)
        if len(frame) < incl_len:
            break

        decision = tracker.feed(linktype, frame)
        if decision:
            decider.decide(*decision)

    return 0


def replay(cfg, path):
    """Run the decision logic over a saved capture, without touching nftables."""
    log_only = dict(cfg)
    log_only['mode'] = 'log'
    # keep the output one line per connection: the summary below says enough
    setup_log(dict(log_only, log_level='warn'))
    decider = Decider(log_only)
    tracker = FlowTracker(set(log_only['ports']))
    with open(path, 'rb') as fh:
        data = fh.read()
    for linktype, frame in read_pcap_frames(data):
        decision = tracker.feed(linktype, frame)
        if not decision:
            continue
        src, state, name = decision
        print('%s %s%s' % (src, 'login ' + name if name else 'ping',
                           ' -> ' + decider.decide(src, state, name)))
    return 0


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------
def show_status(cfg):
    print('mc-tarpit %s' % VERSION)
    print('config:')
    for key, value in describe_config(cfg):
        print('  %-14s %s' % (key, value))
    for kind in ('tarpit', 'pingsink'):
        for family in ('', '6'):
            set_name = kind + family
            result = subprocess.run(
                ['nft', 'list', 'set', 'inet', cfg['table'], set_name],
                capture_output=True, text=True)
            if result.returncode != 0:
                continue
            print('%s:' % set_name)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('elements') or line.startswith('timeout'):
                    print('  ' + line)
    trusted = load_trusted(cfg)
    print('trusted (%d):' % len(trusted))
    for ip, expiry in sorted(trusted.items()):
        left = max(0, int(expiry - time.time()))
        print('  %-40s %dd%02dh' % (ip, left // 86400, left % 86400 // 3600))
    names = allowed_names(cfg)
    print('allowed names (%d): %s' % (len(names), ', '.join(sorted(names)) or '-'))
    print('trust_subnets: %s' % (', '.join(str(s) for s in cfg['subnets']) or '-'))
    return 0


# --------------------------------------------------------------------------
# test clients
# --------------------------------------------------------------------------
def send_login(cfg, name, host='127.0.0.1', port=None):
    port = port or cfg['ports'][0]
    login = encode_varint(0) + encode_varint(len(name)) + name.encode() + b'\x00' * 16
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(handshake(2, host, port, cfg['protocol'])
                 + encode_varint(len(login)) + login)
    time.sleep(1)
    sock.close()
    print('sent login as %r to %s:%d' % (name, host, port))


def send_ping(cfg, host='127.0.0.1', port=None):
    port = port or cfg['ports'][0]
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(handshake(1, host, port, cfg['protocol'])
                 + encode_varint(1) + encode_varint(0))
    time.sleep(1)
    sock.close()
    print('sent status ping to %s:%d' % (host, port))


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------
def sll2_frame(ethertype, payload, src_ip=None, src_port=50000, seq=1000,
               dst_ip='192.168.0.19', flags=0x18):
    tcp_body = bytes([0x50, flags]) + b'\xff\xff\x00\x00\x00\x00'
    if ethertype == ETHERTYPE_IPV4:
        ip = b'\x45\x00' + struct.pack('>H', 20 + 20 + len(payload)) + b'\x00\x00\x00\x00'
        ip += b'\x40\x06\x00\x00'
        ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        tcp = struct.pack('>HHII', src_port, 25565, seq, 0) + tcp_body
    else:
        ip = b'\x60\x00\x00\x00' + struct.pack('>H', 20 + len(payload)) + b'\x06\x40'
        ip += socket.inet_pton(socket.AF_INET6, src_ip)
        ip += socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        tcp = struct.pack('>HHII', src_port, 25565, seq, 0) + tcp_body
    return struct.pack('>H', ethertype) + b'\x00' * 18 + ip + tcp + payload


def selftest(cfg):
    """Offline check of the parser and the decision helpers."""
    host = '127.0.0.1'
    hs = (encode_varint(0) + encode_varint(cfg['protocol'])
          + encode_varint(len(host)) + host.encode()
          + struct.pack('>H', 25565) + encode_varint(2))
    login = encode_varint(0) + encode_varint(7) + b'TestBot' + b'\x00' * 16
    stream = encode_varint(len(hs)) + hs + encode_varint(len(login)) + login

    pcap = b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00' * 8
    pcap += b'\xff\xff\x00\x00' + struct.pack('<I', PCAP_LINKTYPE_SLL2)
    syn = sll2_frame(ETHERTYPE_IPV4, b'', src_ip='203.0.113.9', seq=999,
                     flags=SYN_FLAG)
    pcap += struct.pack('<IIII', 0, 0, len(syn), len(syn)) + syn
    for offset in (0, 20, 40):
        frame = sll2_frame(ETHERTYPE_IPV4, stream[offset:offset + 20],
                           src_ip='203.0.113.9', seq=1000 + offset)
        pcap += struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame

    ports = set(cfg['ports'])
    tracker = FlowTracker(ports)
    name = None
    for linktype, frame in read_pcap_frames(pcap):
        assert packet_payload(linktype, frame, ports), 'frame was not parsed'
        decision = tracker.feed(linktype, frame)
        if decision:
            name = decision[2]
            break
    assert name == 'TestBot', 'expected TestBot, parsed %r' % (name,)
    print('ok: login start parse -> %r' % name)

    status = (encode_varint(0) + encode_varint(cfg['protocol'])
              + encode_varint(len(host)) + host.encode()
              + struct.pack('>H', 25565) + encode_varint(1))
    state, _, _ = parse_client_stream(encode_varint(len(status)) + status + b'\x01\x00')
    assert state == 1, 'status ping misparsed: %r' % (state,)
    print('ok: status ping recognised')

    state, _, _ = parse_client_stream(encode_varint(len(status)) + status[:-3])
    assert state is None, 'truncated handshake must wait for more bytes'
    print('ok: truncated stream waits')

    state, _, _ = parse_client_stream(b'\x00\xff\xff\xff')
    assert state is None, 'garbage must not produce a login'
    print('ok: garbage rejected')

    ipv6_frame = sll2_frame(ETHERTYPE_IPV6, stream, src_ip='2001:db8::42')
    packet = packet_payload(PCAP_LINKTYPE_SLL2, ipv6_frame, ports)
    assert packet and packet[0] == '2001:db8::42', 'IPv6 frame not parsed: %r' % (packet,)
    print('ok: IPv6 frame parsed -> %s' % packet[0])

    multi = dict(cfg)
    multi['ports'] = [25565, 25566]
    assert packet_payload(PCAP_LINKTYPE_SLL2, ipv6_frame, {25565, 25566}), 'multi-port fails'
    print('ok: port list honoured')

    assert is_ignored([ipaddress.ip_network('192.168.0.0/24')], '192.168.0.5')
    assert not is_ignored([ipaddress.ip_network('192.168.0.0/24')], '203.0.113.9')
    print('ok: trust_subnets matching')

    assert nft_set_name('tarpit', '203.0.113.9') == 'tarpit'
    assert nft_set_name('tarpit', '2001:db8::42') == 'tarpit6'
    print('ok: nftables set names')

    names = allowed_names(cfg)
    assert 'testbot' not in names, 'whitelist read returned garbage'
    print('ok: allowed names read (%d)' % len(names))

    now = time.time()
    fake = {'10.0.0.1': now + 60, '10.0.0.2': now - 60}
    assert is_trusted(fake, '10.0.0.1', now)
    assert not is_trusted(fake, '10.0.0.2', now)
    print('ok: trusted ip logic')

    merged = load_config(config_path=None,
                         overrides={'ports': '25565,25566', 'ping_policy': 'ignore'})
    assert merged['ports'] == [25565, 25566]
    assert merged['ping_policy'] == 'ignore'
    print('ok: config overrides')
    return 0


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog='mc_tarpit.py',
        description='Drop Minecraft bots that probe your server (nftables side channel).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Configuration: defaults < config file < MC_TARPIT_* env < CLI flags.\n'
               'Config file: mc_tarpit.py --config /etc/mc-tarpit.conf watch')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--config', default=None, help='INI config file')
    parser.add_argument('--server-dir', default=None, help='dir with whitelist.json/ops.json')
    parser.add_argument('--ports', default=None, help='comma separated ports')
    parser.add_argument('--mode', default=None, choices=CHOICES['mode'])
    parser.add_argument('--ping-policy', default=None, choices=CHOICES['ping_policy'])
    parser.add_argument('--login-policy', default=None, choices=CHOICES['login_policy'])
    parser.add_argument('--trust-subnets', default=None, help='CIDRs never blocked')
    parser.add_argument('--trust-ttl', default=None, help='seconds an IP stays trusted')
    parser.add_argument('--tarpit-ttl', default=None)
    parser.add_argument('--ping-ttl', default=None)
    parser.add_argument('--table', default=None, help='nftables table name')
    parser.add_argument('--iface', default=None, help='capture interface')
    parser.add_argument('--log-level', default=None, choices=CHOICES['log_level'])
    parser.add_argument('--log-file', default=None)
    parser.add_argument('--protocol', default=None, help='protocol for test clients')

    sub = parser.add_subparsers(dest='command')
    sub.add_parser('watch', help='watch traffic and enforce decisions')
    sub.add_parser('selftest', help='offline self-check')
    sub.add_parser('status', help='effective config, sets and trusted IPs')
    replay_cmd = sub.add_parser('replay', help='replay a pcap file, log decisions only')
    replay_cmd.add_argument('path')
    ping_cmd = sub.add_parser('ping', help='send a status ping')
    ping_cmd.add_argument('--host', default='127.0.0.1')
    login_cmd = sub.add_parser('login', help='send a login attempt with NAME')
    login_cmd.add_argument('name')
    login_cmd.add_argument('--host', default='127.0.0.1')
    trust_cmd = sub.add_parser('trust', help='add IPs to the trusted list')
    trust_cmd.add_argument('ips', nargs='+')
    untrust_cmd = sub.add_parser('untrust', help='remove IPs from the trusted list')
    untrust_cmd.add_argument('ips', nargs='+')
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    overrides = {
        'server_dir': args.server_dir,
        'ports': args.ports,
        'mode': args.mode,
        'ping_policy': args.ping_policy,
        'login_policy': args.login_policy,
        'trust_subnets': args.trust_subnets,
        'trust_ttl': args.trust_ttl,
        'tarpit_ttl': args.tarpit_ttl,
        'ping_ttl': args.ping_ttl,
        'table': args.table,
        'iface': args.iface,
        'log_level': args.log_level,
        'log_file': args.log_file,
        'protocol': args.protocol,
    }
    cfg = load_config(args.config, overrides)
    setup_log(cfg)

    command = args.command or 'watch'
    if command == 'selftest':
        return selftest(cfg)
    if command == 'status':
        return show_status(cfg)
    if command == 'replay':
        return replay(cfg, args.path)
    if command == 'ping':
        send_ping(cfg, args.host)
        return 0
    if command == 'login':
        send_login(cfg, args.name, args.host)
        return 0
    if command in ('trust', 'untrust'):
        trusted = load_trusted(cfg)
        now = time.time()
        for ip in args.ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise SystemExit('not an IP address: %r' % ip)
            if command == 'trust':
                trusted[ip] = now + cfg['trust_ttl']
            else:
                trusted.pop(ip, None)
        save_trusted(cfg, trusted)
        print('%s: %d IPs in %s' % (command, len(trusted), trust_path(cfg)))
        return 0
    if command == 'watch':
        return watch(cfg)
    parser.error('unknown command: %s' % command)


if __name__ == '__main__':
    sys.exit(main())
