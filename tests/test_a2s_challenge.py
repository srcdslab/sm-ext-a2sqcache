#!/usr/bin/env python3
"""
A2S anti-spoofing challenge check for sm-ext-a2sqcache (>= 1.4.0).

Raw UDP, standard library only. Run it against a TEST server, never production:

    python3 test_a2s_challenge.py 127.0.0.1:27015
    python3 test_a2s_challenge.py 127.0.0.1:27015 --rcon-password secret   # + case 6

Cases:
  1. A2S_INFO without challenge          -> 9-byte S2C_CHALLENGE ('A'), no 'I'
  2. A2S_INFO with the received challenge -> full S2A_INFO ('I')
  3. A2S_INFO with an invented challenge  -> 'A' again
  4. A2S_PLAYER with ip ^ 0x55AADD88      -> refused ('A')
  5. A2S_PLAYER with the received challenge -> S2A_PLAYER ('D')
  6. sv_qcache_a2s_challenge 0 (via RCON) -> legacy behaviour, then restored to 1
Extra: a 5-byte A2S_PLAYER gets no answer (would be amplified).

The server rate limits queries per source IP (sv_max_queries_sec / _window); keep
--delay above ~0.3s or answers get dropped.
"""

import argparse
import socket
import struct
import sys
import time

HEADER = b"\xFF\xFF\xFF\xFF"
A2S_INFO = HEADER + b"TSource Engine Query\x00"
A2S_PLAYER = HEADER + b"U"
LEGACY_XOR = 0x55AADD88


class Tester:
    def __init__(self, host, port, delay, timeout):
        self.addr = (host, port)
        self.delay = delay
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.connect(self.addr)
        self.failures = 0

    def query(self, payload):
        time.sleep(self.delay)
        # Drop anything late from a previous query.
        self.sock.setblocking(False)
        try:
            while self.sock.recv(65535):
                pass
        except (BlockingIOError, ConnectionRefusedError):
            pass
        self.sock.setblocking(True)
        self.sock.settimeout(self.timeout)
        self.sock.send(payload)
        try:
            return self.sock.recv(65535)
        except socket.timeout:
            return None

    def check(self, name, ok, detail):
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        if not ok:
            self.failures += 1


def kind(resp):
    if resp is None:
        return "no answer"
    if len(resp) < 5 or resp[:4] != HEADER:
        return f"garbage ({len(resp)} bytes)"
    return f"'{chr(resp[4])}' ({len(resp)} bytes)"


def is_type(resp, t, size=None):
    return resp is not None and len(resp) >= 5 and resp[:4] == HEADER and resp[4] == ord(t) \
        and (size is None or len(resp) == size)


def challenge_of(resp):
    return struct.unpack("<i", resp[5:9])[0]


def legacy_challenge(ip):
    # extension.cpp (<= 1.3.0): *(int32_t *)&packet->from.ip ^ 0x55AADD88 on little endian
    raw = struct.unpack("<I", socket.inet_aton(ip))[0]
    return struct.unpack("<i", struct.pack("<I", raw ^ LEGACY_XOR))[0]


def ip_from_legacy_challenge(challenge):
    raw = struct.unpack("<I", struct.pack("<i", challenge))[0] ^ LEGACY_XOR
    return socket.inet_ntoa(struct.pack("<I", raw))


def rcon(host, port, password, command):
    """Minimal Source RCON (TCP). Returns the response body."""
    def packet(req_id, req_type, body):
        data = struct.pack("<ii", req_id, req_type) + body.encode() + b"\x00\x00"
        return struct.pack("<i", len(data)) + data

    def read(s):
        size = struct.unpack("<i", recv_exact(s, 4))[0]
        data = recv_exact(s, size)
        req_id, req_type = struct.unpack("<ii", data[:8])
        return req_id, req_type, data[8:-2].decode(errors="replace")

    def recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("RCON connection closed")
            buf += chunk
        return buf

    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(packet(1, 3, password))  # SERVERDATA_AUTH
        while True:
            req_id, req_type, _ = read(s)
            if req_type == 2:  # SERVERDATA_AUTH_RESPONSE
                if req_id == -1:
                    raise PermissionError("RCON authentication failed")
                break
        s.sendall(packet(2, 2, command))  # SERVERDATA_EXECCOMMAND
        return read(s)[2]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("server", help="host:port of the TEST server")
    ap.add_argument("--public-ip", help="our IP as seen by the server (default: learnt via RCON, else local socket IP)")
    ap.add_argument("--rcon-password", help="enables case 6 (toggles sv_qcache_a2s_challenge)")
    ap.add_argument("--delay", type=float, default=0.4, help="seconds between queries (rate limit)")
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()

    host, _, port = args.server.rpartition(":")
    host = socket.gethostbyname(host)
    port = int(port)

    t = Tester(host, port, args.delay, args.timeout)
    my_ip = args.public_ip or t.sock.getsockname()[0]

    # Behind NAT (docker, ...) the server sees another source IP. The legacy challenge
    # leaks it (ip ^ 0x55AADD88), which is exactly the flaw being fixed: use it.
    if args.rcon_password and not args.public_ip:
        try:
            rcon(host, port, args.rcon_password, "sv_qcache_a2s_challenge 0")
            r = t.query(A2S_PLAYER + struct.pack("<i", -1))
            if is_type(r, "A", 9):
                my_ip = ip_from_legacy_challenge(challenge_of(r))
        finally:
            rcon(host, port, args.rcon_password, "sv_qcache_a2s_challenge 1")
    print(f"     source IP as seen by the server = {my_ip}")

    # 1. A2S_INFO without challenge
    r = t.query(A2S_INFO)
    t.check("1 A2S_INFO without challenge", is_type(r, "A", 9), kind(r))
    if not is_type(r, "A", 9):
        sys.exit("No challenge received; is sv_qcache_a2s_challenge 1 and the extension >= 1.4.0 loaded?")
    challenge = challenge_of(r)
    print(f"     challenge = {challenge & 0xFFFFFFFF:#010x}")

    # 2. A2S_INFO with the received challenge
    r = t.query(A2S_INFO + struct.pack("<i", challenge))
    t.check("2 A2S_INFO with challenge", is_type(r, "I"), kind(r))
    if is_type(r, "I"):
        name = r[6:].split(b"\x00", 1)[0].decode(errors="replace")
        print(f"     hostname = {name!r}")

    # 3. A2S_INFO with an invented challenge
    bogus = challenge ^ 0x13371337
    r = t.query(A2S_INFO + struct.pack("<i", bogus))
    t.check("3 A2S_INFO with invented challenge", is_type(r, "A", 9), kind(r))

    # 4. A2S_PLAYER with the legacy, computable challenge
    legacy = legacy_challenge(my_ip)
    r = t.query(A2S_PLAYER + struct.pack("<i", legacy))
    ok = is_type(r, "A", 9) and challenge_of(r) != legacy
    t.check(f"4 A2S_PLAYER with ip^0x55AADD88 ({my_ip})", ok, kind(r))

    # 5. A2S_PLAYER with the received challenge (ask for a fresh one first, like a client)
    r = t.query(A2S_PLAYER + struct.pack("<i", -1))
    t.check("5a A2S_PLAYER challenge request (-1)", is_type(r, "A", 9), kind(r))
    if is_type(r, "A", 9):
        r = t.query(A2S_PLAYER + struct.pack("<i", challenge_of(r)))
        t.check("5b A2S_PLAYER with challenge", is_type(r, "D"), kind(r))
        if is_type(r, "D"):
            print(f"     players = {r[5]}")

    # Extra: never answer more bytes than received
    r = t.query(A2S_PLAYER)
    t.check("x  A2S_PLAYER 5 bytes (no challenge)", r is None, kind(r))

    # 6. Legacy behaviour with sv_qcache_a2s_challenge 0
    if args.rcon_password:
        try:
            rcon(host, port, args.rcon_password, "sv_qcache_a2s_challenge 0")
            r = t.query(A2S_INFO)
            t.check("6a [challenge 0] A2S_INFO without challenge", is_type(r, "I"), kind(r))
            r = t.query(A2S_PLAYER + struct.pack("<i", legacy))
            t.check("6b [challenge 0] A2S_PLAYER with ip^0x55AADD88", is_type(r, "D"), kind(r))
        finally:
            rcon(host, port, args.rcon_password, "sv_qcache_a2s_challenge 1")
        r = t.query(A2S_INFO)
        t.check("6c [challenge 1 restored] A2S_INFO without challenge", is_type(r, "A", 9), kind(r))
    else:
        print("[SKIP] 6 needs --rcon-password")

    print(f"\n{'OK' if t.failures == 0 else f'{t.failures} FAILURE(S)'}")
    sys.exit(1 if t.failures else 0)


if __name__ == "__main__":
    main()
