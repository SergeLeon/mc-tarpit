"""Tests for the packet parser and the trusted IP helpers.

No frameworks, no network, no nftables: run with

    python3 tests/test_parse.py

or

    python3 -m unittest discover -s tests
"""
import importlib.util
import os
import socket
import struct
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location('mc_tarpit', os.path.join(ROOT, 'mc_tarpit.py'))
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)


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


def sll2_frame(src_ip, src_port, seq, payload, dst_ip='192.168.0.19', dst_port=25565):
    ip = b'\x45\x00' + struct.pack('>H', 20 + 20 + len(payload)) + b'\x00\x00\x00\x00'
    ip += b'\x40\x06\x00\x00' + socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    tcp = struct.pack('>HHII', src_port, dst_port, seq, 0)
    tcp += b'\x50\x18\xff\xff\x00\x00\x00\x00'
    return struct.pack('>H', 0x0800) + b'\x00' * 18 + ip + tcp + payload


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
    def test_sll2_frame(self):
        frame = sll2_frame('203.0.113.9', 50000, 1000, b'hello')
        src, sport, seq, flags, payload = mc.packet_payload(mc.PCAP_LINKTYPE_SLL2, frame)
        self.assertEqual(src, '203.0.113.9')
        self.assertEqual(sport, 50000)
        self.assertEqual(seq, 1000)
        self.assertEqual(payload, b'hello')

    def test_foreign_port_ignored(self):
        frame = sll2_frame('203.0.113.9', 50000, 1000, b'hello', dst_port=25566)
        self.assertIsNone(mc.packet_payload(mc.PCAP_LINKTYPE_SLL2, frame))

    def test_reassembly_over_pcap(self):
        stream = login_stream('TestBot')
        pcap = b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00' * 8
        pcap += b'\xff\xff\x00\x00' + struct.pack('<I', mc.PCAP_LINKTYPE_SLL2)
        for offset in range(0, len(stream), 20):
            chunk = stream[offset:offset + 20]
            frame = sll2_frame('203.0.113.9', 50000, 1000 + offset, chunk)
            pcap += struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame
        collected = b''
        name = None
        for linktype, frame in mc.read_pcap_frames(pcap):
            packet = mc.packet_payload(linktype, frame)
            collected += packet[4]
            _, name, _ = mc.parse_client_stream(collected)
            if name:
                break
        self.assertEqual(name, 'TestBot')


class TrustTests(unittest.TestCase):
    def test_expiry(self):
        now = time.time()
        data = {'1.2.3.4': now + 60, '5.6.7.8': now - 60}
        self.assertTrue(mc.is_trusted(data, '1.2.3.4', now))
        self.assertFalse(mc.is_trusted(data, '5.6.7.8', now))
        self.assertFalse(mc.is_trusted(data, '9.9.9.9', now))


if __name__ == '__main__':
    unittest.main(verbosity=2)
