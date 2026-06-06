#!/usr/bin/env python3
"""
Minimal UDP DNS stub for ngx-otel-rust integration testing.

Usage:
    python3 dns_stub.py <port> <ipv4>           # A → ipv4, AAAA → NXDOMAIN
    python3 dns_stub.py <port> aaaa <ipv6>      # AAAA → ipv6, A → NXDOMAIN
    python3 dns_stub.py <port> nxdomain         # all queries → NXDOMAIN

Listens on 127.0.0.1:<port> (UDP).  Mode is controlled by the second positional
argument:
  - An IPv4 address string (e.g. "127.0.0.1"): A-mode — answers A queries with
    that address; AAAA and all other types → NXDOMAIN.  (Original behaviour;
    used by TEST A.)
  - The literal string "aaaa" followed by an IPv6 address (e.g. "::1"): AAAA-mode
    — answers AAAA queries with that address; A and all other types → NXDOMAIN.
    (Used by TEST C — DNS→v6.)
  - The literal string "nxdomain": NXDOMAIN-mode — all query types → NXDOMAIN
    regardless of name.  (Used by TEST D — unresolvable name.)

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


def _nxdomain_response(tid: bytes, qdcount_bytes: bytes, question: bytes) -> bytes:
    """Build a NXDOMAIN response for the given question."""
    # Flags: QR=1 AA=1 RCODE=NXDOMAIN(3) → 0x8583
    resp = tid + b"\x85\x83"
    resp += qdcount_bytes
    resp += b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT=NSCOUNT=ARCOUNT=0
    resp += question
    return resp


def run(port: int, mode: str, addr_arg: str | None) -> None:
    signal.signal(signal.SIGTERM, _sigterm_handler)

    # Pre-compute the answer payload for the configured mode.
    packed_ipv4: bytes | None = None
    packed_ipv6: bytes | None = None
    if mode == "v4" and addr_arg is not None:
        packed_ipv4 = socket.inet_aton(addr_arg)
    elif mode == "aaaa" and addr_arg is not None:
        packed_ipv6 = socket.inet_pton(socket.AF_INET6, addr_arg)

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
        qdcount_bytes = data[4:6]  # echo QDCOUNT from request

        if mode == "nxdomain":
            # All queries → NXDOMAIN regardless of type.
            resp = _nxdomain_response(tid, qdcount_bytes, question)

        elif mode == "v4" and qtype == 1:
            # A record — answer with the configured IPv4.
            # Flags: QR=1 AA=1 OPCODE=0 TC=0 RD=1 RA=1 RCODE=0 → 0x8580
            assert packed_ipv4 is not None
            resp = tid + b"\x85\x80"
            resp += qdcount_bytes           # QDCOUNT (echo from request)
            resp += b"\x00\x01"             # ANCOUNT = 1
            resp += b"\x00\x00\x00\x00"    # NSCOUNT=0 ARCOUNT=0
            resp += question                # question section
            resp += b"\xc0\x0c"            # name pointer → offset 12
            resp += b"\x00\x01\x00\x01"    # TYPE A, CLASS IN
            resp += b"\x00\x00\x00\x3c"    # TTL = 60 s
            resp += b"\x00\x04"            # RDLENGTH = 4
            resp += packed_ipv4

        elif mode == "aaaa" and qtype == 1:
            # A query in AAAA mode → NOERROR + empty answer.
            # "The name exists but has no A record" (NOT NXDOMAIN — NXDOMAIN
            # means the name doesn't exist at all, which causes nginx's resolver
            # to abort without using the AAAA response).
            # Flags: QR=1 AA=1 RCODE=0 (NOERROR) → 0x8580
            resp = tid + b"\x85\x80"
            resp += qdcount_bytes           # QDCOUNT (echo from request)
            resp += b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT=NSCOUNT=ARCOUNT=0
            resp += question

        elif mode == "aaaa" and qtype == 28:
            # AAAA record — answer with the configured IPv6.
            # Flags: QR=1 AA=1 RCODE=0 → 0x8580
            assert packed_ipv6 is not None
            resp = tid + b"\x85\x80"
            resp += qdcount_bytes           # QDCOUNT (echo from request)
            resp += b"\x00\x01"             # ANCOUNT = 1
            resp += b"\x00\x00\x00\x00"    # NSCOUNT=0 ARCOUNT=0
            resp += question                # question section
            resp += b"\xc0\x0c"            # name pointer → offset 12
            resp += b"\x00\x1c\x00\x01"    # TYPE AAAA (28), CLASS IN
            resp += b"\x00\x00\x00\x3c"    # TTL = 60 s
            resp += b"\x00\x10"            # RDLENGTH = 16
            resp += packed_ipv6

        else:
            # Any other type in v4/aaaa mode → NXDOMAIN.
            resp = _nxdomain_response(tid, qdcount_bytes, question)

        try:
            sock.sendto(resp, addr)
        except OSError:
            pass

    sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            f"Usage:\n"
            f"  {sys.argv[0]} <port> <ipv4>          # A → ipv4, AAAA → NXDOMAIN\n"
            f"  {sys.argv[0]} <port> aaaa <ipv6>     # AAAA → ipv6, A → NXDOMAIN\n"
            f"  {sys.argv[0]} <port> nxdomain        # all → NXDOMAIN",
            file=sys.stderr,
        )
        sys.exit(1)

    port_arg = int(sys.argv[1])
    second = sys.argv[2]

    if second == "nxdomain":
        run(port_arg, "nxdomain", None)
    elif second == "aaaa":
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} <port> aaaa <ipv6>", file=sys.stderr)
            sys.exit(1)
        run(port_arg, "aaaa", sys.argv[3])
    else:
        # Original interface: second arg is an IPv4 address.
        run(port_arg, "v4", second)
