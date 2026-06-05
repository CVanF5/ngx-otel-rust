#!/usr/bin/env python3
"""
Minimal UDP DNS stub for ngx-otel-rust integration testing.

Usage: python3 dns_stub.py <port> <ipv4>

Listens on 127.0.0.1:<port> (UDP).  For every A query (QTYPE=1) returns
<ipv4> as the answer regardless of the queried name; for every AAAA query
(QTYPE=28) or other type returns NXDOMAIN.  This is intentional: the test
controls what is being resolved via the nginx.conf endpoint URL, and the
stub does not need to validate the hostname.

Exits on SIGTERM.  Designed to be run as a background process:

    python3 dns_stub.py 15353 127.0.0.1 &
    DNS_PID=$!
    ...
    kill $DNS_PID
"""

import socket
import struct
import sys
import signal


def _sigterm_handler(signum, frame):
    sys.exit(0)


def run(port: int, ipv4: str) -> None:
    signal.signal(signal.SIGTERM, _sigterm_handler)

    packed_ip = socket.inet_aton(ipv4)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(1.0)

    while True:
        try:
            data, addr = sock.recvfrom(512)
        except socket.timeout:
            continue
        except OSError:
            break

        if len(data) < 17:
            # Too short to be a valid DNS query — ignore.
            continue

        # Transaction ID (2 bytes at offset 0).
        tid = data[:2]

        # Walk the question's QNAME labels (starts at offset 12).
        pos = 12
        while pos < len(data) and data[pos] != 0:
            label_len = data[pos]
            pos += 1 + label_len
        pos += 1  # consume the null terminator

        # QTYPE is two bytes immediately after the QNAME.
        if pos + 4 > len(data):
            continue
        qtype = struct.unpack("!H", data[pos : pos + 2])[0]

        # Copy the question section (used in both response branches).
        question = data[12 : pos + 4]

        if qtype == 1:
            # A record — answer with the configured IPv4.
            # Flags: QR=1 AA=1 OPCODE=0 TC=0 RD=1 RA=1 RCODE=0 → 0x8580
            resp = tid + b"\x85\x80"
            resp += data[4:6]            # QDCOUNT (echo from request)
            resp += b"\x00\x01"          # ANCOUNT = 1
            resp += b"\x00\x00\x00\x00"  # NSCOUNT=0 ARCOUNT=0
            resp += question             # question section
            resp += b"\xc0\x0c"          # name pointer → offset 12
            resp += b"\x00\x01\x00\x01"  # TYPE A, CLASS IN
            resp += b"\x00\x00\x00\x3c"  # TTL = 60 s
            resp += b"\x00\x04"          # RDLENGTH = 4
            resp += packed_ip
        else:
            # AAAA / anything else → NXDOMAIN.
            # Flags: QR=1 AA=1 RCODE=NXDOMAIN(3) → 0x8583
            resp = tid + b"\x85\x83"
            resp += data[4:6]
            resp += b"\x00\x00\x00\x00\x00\x00"  # all counts 0
            resp += question

        try:
            sock.sendto(resp, addr)
        except OSError:
            pass

    sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <ipv4>", file=sys.stderr)
        sys.exit(1)
    run(int(sys.argv[1]), sys.argv[2])
