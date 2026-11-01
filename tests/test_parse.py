"""Tests for mc-tarpit: parser, config, decisions, trusted IPs.

No frameworks, no network, no nftables:

    python3 tests/test_parse.py
    python3 -m unittest discover -s tests
"""
import importlib.util
import ipaddress
import json
import os
import socket
import struct
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location('mc_tarpit', os.path.join(ROOT, 'mc_tarpit.py'))
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)


def make_cfg(**overrides):
    values = dict(mc.DEFAULTS)
    values.update({'mode': 'log', 'server_dir': tempfile.mkdtemp(), 'log_level': 'warn'})
    values.update(overrides)
    return mc.normalize(values)


def login_stream(name, protocol=776, host='127.0.0.1', port=25565, next_state=2):
    hs = (mc.encode_varint(0) + mc.encode_varint(protocol)
          + mc.encode_varint(len(host)) + host.encode()
          + struct.pack('>H', port) + mc.encode_varint(next_state))
    packet = mc.encode_varint(len(hs)) + hs
    if next_state == 2:
        body = mc.encode_varint(0) + mc.encode_varint(len(name)) + name.encode()
        body += b'\x00' * 16
        packet += mc.encode_varint(len(body)) + body
    else:
        packet += b'\x01\x00'
    return packet


def frame_ipv4(src_ip, payload, src_port=50000, seq=1000, dst_port=25565):
    ip = b'\x45\x00' + struct.pack('>H', 20 + 20 + len(payload)) + b'\x00\x00\x00\x00'
    ip += b'\x40\x06\x00\x00'
    ip += socket.inet_aton(src_ip) + socket.inet_aton('192.168.0.19')
    tcp = struct.pack('>HHII', src_port, dst_port, seq, 0) + b'\x50\x18\xff\xff\x00\x00\x00\x00'
    return struct.pack('>H', 0x0800) + b'\x00' * 18 + ip + tcp + payload


def frame_ipv6(src_ip, payload, src_port=50000, seq=1000, dst_port=25565):
    ip = b'\x60\x00\x00\x00' + struct.pack('>H', 20 + len(payload)) + b'\x06\x40'
    ip += socket.inet_pton(socket.AF_INET6, src_ip)
    ip += socket.inet_pton(socket.AF_INET6, '2001:db8::1')
    tcp = struct.pack('>HHII', src_port, dst_port, seq, 0) + b'\x50\x18\xff\xff\x00\x00\x00\x00'
    return struct.pack('>H', 0x86DD) + b'\x00' * 18 + ip + tcp + payload


def frame_ethernet(src_ip, payload, vlan=False, dst_port=25565):
    ip = b'\x45\x00' + struct.pack('>H', 20 + 20 + len(payload)) + b'\x00\x00\x00\x00'
    ip += b'\x40\x06\x00\x00'
    ip += socket.inet_aton(src_ip) + socket.inet_aton('192.168.0.19')
    tcp = struct.pack('>HHII', 50000, dst_port, 1000, 0) + b'\x50\x18\xff\xff\x00\x00\x00\x00'
    header = b'\xaa' * 6 + b'\xbb' * 6
    if vlan:
        header += struct.pack('>HH', mc.ETHERTYPE_VLAN, 100)
    header += struct.pack('>H', mc.ETHERTYPE_IPV4)
    return header + ip + tcp + payload


class VarIntTests(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(mc.encode_varint(0), b'\x00')

    def test_roundtrip(self):
        for value in (0, 1, 127, 128, 255, 300, 25565, 776, 2097151):
            encoded = mc.encode_varint(value)
            decoded, pos = mc.read_varint(encoded, 0)
            self.assertEqual(decoded, value)
            self.assertEqual(pos, len(encoded))

    def test_truncated(self):
        value, _ = mc.read_varint(b'\x80', 0)
        self.assertIsNone(value)

    def test_five_bytes_is_the_limit(self):
        value, pos = mc.read_varint(b'\xff\xff\xff\xff\x0f', 0)
        self.assertEqual(value, 0xFFFFFFFF)
        self.assertEqual(pos, 5)

    def test_six_bytes_rejected(self):
        value, _ = mc.read_varint(b'\xff\xff\xff\xff\xff\x0f', 0)
        self.assertIsNone(value)


class ParseTests(unittest.TestCase):
    def test_login_name(self):
        state, name, raw = mc.parse_client_stream(login_stream('SergeLeon'))
        self.assertEqual(state, 2)
        self.assertEqual(name, 'SergeLeon')
        self.assertTrue(raw.startswith(b'\x00'))

    def test_status_ping(self):
        state, name, _ = mc.parse_client_stream(login_stream('', next_state=1))
        self.assertEqual(state, 1)
        self.assertIsNone(name)

    def test_truncated_waits(self):
        state, name, _ = mc.parse_client_stream(login_stream('SergeLeon')[:-4])
        self.assertIsNone(state)
        self.assertIsNone(name)

    def test_garbage(self):
        state, name, _ = mc.parse_client_stream(b'\x00\xff\xff\xff\xff')
        self.assertIsNone(state)
        self.assertIsNone(name)

    def test_long_name_rejected(self):
        state, name, _ = mc.parse_client_stream(login_stream('a' * 17))
        self.assertIsNone(state)

    def test_split_stream(self):
        data = login_stream('nubik')
        for cut in range(1, len(data)):
            state, name, _ = mc.parse_client_stream(data[:cut])
            if state is None:
                self.assertIsNone(name)
            else:
                self.assertEqual(name, 'nubik')


class FrameTests(unittest.TestCase):
    def test_ipv4_frame(self):
        packet = mc.packet_payload(mc.PCAP_LINKTYPE_SLL2,
                                   frame_ipv4('203.0.113.9', b'hello'), {25565})
        src, sport, seq, flags, payload = packet
        self.assertEqual(src, '203.0.113.9')
        self.assertEqual(sport, 50000)
        self.assertEqual(payload, b'hello')

    def test_ipv6_frame(self):
        packet = mc.packet_payload(mc.PCAP_LINKTYPE_SLL2,
                                   frame_ipv6('2001:db8::42', b'hello'), {25565})
        src, sport, seq, flags, payload = packet
        self.assertEqual(src, '2001:db8::42')
        self.assertEqual(payload, b'hello')

    def test_foreign_port_ignored(self):
        frame = frame_ipv4('203.0.113.9', b'hello', dst_port=25566)
        self.assertIsNone(mc.packet_payload(mc.PCAP_LINKTYPE_SLL2, frame, {25565}))
        self.assertIsNotNone(mc.packet_payload(mc.PCAP_LINKTYPE_SLL2, frame, {25565, 25566}))

    def test_reassembly_over_pcap(self):
        stream = login_stream('TestBot')
        pcap = b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00' * 8
        pcap += b'\xff\xff\x00\x00' + struct.pack('<I', mc.PCAP_LINKTYPE_SLL2)
        for offset in range(0, len(stream), 20):
            frame = frame_ipv4('203.0.113.9', stream[offset:offset + 20], seq=1000 + offset)
            pcap += struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame
        collected = b''
        name = None
        for linktype, frame in mc.read_pcap_frames(pcap):
            packet = mc.packet_payload(linktype, frame, {25565})
            collected += packet[4]
            _, name, _ = mc.parse_client_stream(collected)
            if name:
                break
        self.assertEqual(name, 'TestBot')

    def test_set_names(self):
        self.assertEqual(mc.nft_set_name('tarpit', '203.0.113.9'), 'tarpit')
        self.assertEqual(mc.nft_set_name('tarpit', '2001:db8::42'), 'tarpit6')
        self.assertEqual(mc.nft_set_name('pingsink', '2001:db8::42'), 'pingsink6')

    def test_ethernet_frame(self):
        packet = mc.packet_payload(mc.PCAP_LINKTYPE_EN10MB,
                                   frame_ethernet('203.0.113.9', b'hello'), {25565})
        self.assertEqual(packet[0], '203.0.113.9')
        self.assertEqual(packet[4], b'hello')

    def test_vlan_tag_is_skipped(self):
        frame = frame_ethernet('203.0.113.9', b'hello', vlan=True)
        packet = mc.packet_payload(mc.PCAP_LINKTYPE_EN10MB, frame, {25565})
        self.assertIsNotNone(packet)
        self.assertEqual(packet[0], '203.0.113.9')
        self.assertEqual(packet[4], b'hello')

    def test_bad_ipv4_header_length_rejected(self):
        for ihl in (0, 4, 15):
            frame = bytearray(frame_ethernet('203.0.113.9', b'hello'))
            frame[14] = 0x40 | ihl          # version 4, ihl from the loop
            self.assertIsNone(mc.packet_payload(mc.PCAP_LINKTYPE_EN10MB, bytes(frame), {25565}))

    def test_bad_total_length_rejected(self):
        frame = bytearray(frame_ethernet('203.0.113.9', b'hello'))
        frame[16:18] = struct.pack('>H', 20)   # less than one TCP header
        self.assertIsNone(mc.packet_payload(mc.PCAP_LINKTYPE_EN10MB, bytes(frame), {25565}))

    def test_ethernet_padding_is_trimmed(self):
        frame = frame_ethernet('203.0.113.9', b'hi')
        frame += b'\x00' * 18                   # padding to the 60 byte minimum
        packet = mc.packet_payload(mc.PCAP_LINKTYPE_EN10MB, frame, {25565})
        self.assertEqual(packet[4], b'hi')

    def test_bad_tcp_header_length_rejected(self):
        frame = bytearray(frame_ethernet('203.0.113.9', b'hello'))
        frame[14 + 20 + 12] = 0x30              # data offset 3, below the minimum
        self.assertIsNone(mc.packet_payload(mc.PCAP_LINKTYPE_EN10MB, bytes(frame), {25565}))


class ConfigTests(unittest.TestCase):
    def test_ports_csv(self):
        cfg = make_cfg(ports='25565, 25566 25567')
        self.assertEqual(cfg['ports'], [25565, 25566, 25567])

    def test_bad_ports(self):
        with self.assertRaises(SystemExit):
            make_cfg(ports='abc')

    def test_bad_choice(self):
        with self.assertRaises(SystemExit):
            make_cfg(mode='nonsense')

    def test_subnets(self):
        cfg = make_cfg(trust_subnets='192.168.0.0/24, 10.0.0.0/8')
        self.assertEqual(len(cfg['subnets']), 2)
        with self.assertRaises(SystemExit):
            make_cfg(trust_subnets='not-a-subnet')

    def test_file_then_env_then_cli(self):
        with tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False) as fh:
            fh.write('[mc-tarpit]\nports = 25570\nmode = log\nping_policy = ignore\n')
            path = fh.name
        try:
            os.environ.pop('MC_TARPIT_PORTS', None)
            from_file = mc.load_config(path)
            self.assertEqual(from_file['ports'], [25570])
            self.assertEqual(from_file['ping_policy'], 'ignore')
            os.environ['MC_TARPIT_PORTS'] = '25571'
            from_env = mc.load_config(path)
            self.assertEqual(from_env['ports'], [25571])
            from_env_and_cli = mc.load_config(path, {'ports': '25572'})
            self.assertEqual(from_env_and_cli['ports'], [25572])
        finally:
            os.environ.pop('MC_TARPIT_PORTS', None)
            os.unlink(path)

    def test_defaults(self):
        cfg = mc.normalize(dict(mc.DEFAULTS))
        self.assertEqual(cfg['ports'], [25565])
        self.assertEqual(cfg['mode'], 'drop')


class TrustTests(unittest.TestCase):
    def test_expiry(self):
        now = time.time()
        data = {'1.2.3.4': now + 60, '5.6.7.8': now - 60}
        self.assertTrue(mc.is_trusted(data, '1.2.3.4', now))
        self.assertFalse(mc.is_trusted(data, '5.6.7.8', now))
        self.assertFalse(mc.is_trusted(data, '9.9.9.9', now))

    def test_subnet_match(self):
        subnets = [ipaddress.ip_network('192.168.0.0/24'), ipaddress.ip_network('2001:db8::/32')]
        self.assertTrue(mc.is_ignored(subnets, '192.168.0.5'))
        self.assertTrue(mc.is_ignored(subnets, '2001:db8::42'))
        self.assertFalse(mc.is_ignored(subnets, '203.0.113.9'))
        self.assertFalse(mc.is_ignored(subnets, 'garbage'))

    def test_save_load(self):
        cfg = make_cfg()
        mc.save_trusted(cfg, {'1.2.3.4': time.time() + 60})
        loaded = mc.load_trusted(cfg)
        self.assertIn('1.2.3.4', loaded)
        loaded['5.6.7.8'] = time.time() - 60
        mc.save_trusted(cfg, loaded)
        self.assertNotIn('5.6.7.8', mc.load_trusted(cfg))


class NamesTests(unittest.TestCase):
    def test_whitelist_ops_and_extra(self):
        cfg = make_cfg()
        with open(os.path.join(cfg['server_dir'], 'whitelist.json'), 'w') as fh:
            json.dump([{'name': 'SergeLeon'}], fh)
        with open(os.path.join(cfg['server_dir'], 'ops.json'), 'w') as fh:
            json.dump([{'name': 'Admin'}], fh)
        with open(mc.names_path(cfg), 'w') as fh:
            fh.write('# comment\nFriend\n\n')
        names = mc.allowed_names(cfg)
        self.assertEqual(names, {'sergeleon', 'admin', 'friend'})


class DecisionTests(unittest.TestCase):
    def decider(self, **overrides):
        cfg = make_cfg(**overrides)
        with open(os.path.join(cfg['server_dir'], 'whitelist.json'), 'w') as fh:
            json.dump([{'name': 'SergeLeon'}], fh)
        return cfg, mc.Decider(cfg)

    def test_unknown_login_tarpit(self):
        _, decider = self.decider()
        self.assertEqual(decider.decide('203.0.113.9', 2, 'FishNet'), 'tarpit')

    def test_known_login_trusts(self):
        cfg, decider = self.decider()
        self.assertEqual(decider.decide('203.0.113.9', 2, 'sergeleon'), 'allow')
        self.assertIn('203.0.113.9', mc.load_trusted(cfg))
        self.assertEqual(decider.decide('203.0.113.9', 1, None), 'allow')

    def test_unknown_ping_sink(self):
        _, decider = self.decider()
        self.assertEqual(decider.decide('203.0.113.9', 1, None), 'pingsink')

    def test_ping_policy_ignore(self):
        _, decider = self.decider(ping_policy='ignore')
        self.assertEqual(decider.decide('203.0.113.9', 1, None), 'ignore')

    def test_login_policy_ignore(self):
        _, decider = self.decider(login_policy='log')
        self.assertEqual(decider.decide('203.0.113.9', 2, 'FishNet'), 'ignore')

    def test_subnet_is_ignored(self):
        _, decider = self.decider(trust_subnets='203.0.113.0/24')
        self.assertEqual(decider.decide('203.0.113.9', 2, 'FishNet'), 'ignore')

    def test_replay_runs(self):
        cfg, _ = self.decider()
        stream = login_stream('TestBot')
        pcap = b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00' * 8
        pcap += b'\xff\xff\x00\x00' + struct.pack('<I', mc.PCAP_LINKTYPE_SLL2)
        for offset in (0, 20):
            chunk = stream[offset:offset + 20]
            frame = frame_ipv4('203.0.113.9', chunk, seq=1000 + offset)
            pcap += struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame
        path = os.path.join(cfg['server_dir'], 'capture.pcap')
        with open(path, 'wb') as fh:
            fh.write(pcap)
        self.assertEqual(mc.replay(cfg, path), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
