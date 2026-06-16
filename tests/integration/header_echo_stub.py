#!/usr/bin/env python3
"""
Minimal HTTP/1.1 backend that records the *request headers* it receives.

Usage: python3 header_echo_stub.py <port> <output_file>

Listens on 127.0.0.1:<port> (TCP), accepts HTTP/1.1 requests, and appends the
full raw request header block of each request to <output_file>, each delimited
by a "===REQUEST===" marker line.  Responds 200 OK for every request.

Used by run_redirect_safe.sh to assert that an upstream-bound request
carries EXACTLY ONE `traceparent` header (the find-then-update injection must
overwrite the inbound header in place, not append a duplicate).

Exits on SIGTERM or after a 5-second idle gap with no incoming connections.
"""

import socket
import sys
import signal


def _sigterm_handler(signum, frame):
    sys.exit(0)


def run(port: int, output: str) -> None:
    signal.signal(signal.SIGTERM, _sigterm_handler)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    srv.settimeout(5.0)

    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            break
        except OSError:
            break

        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk

            hdr_end = buf.find(b"\r\n\r\n")
            if hdr_end < 0:
                hdr_end = len(buf)
            headers_raw = buf[:hdr_end].decode("utf-8", errors="replace")

            with open(output, "a") as f:
                f.write("===REQUEST===\n")
                f.write(headers_raw)
                f.write("\n")

            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    srv.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <output_file>", file=sys.stderr)
        sys.exit(1)
    run(int(sys.argv[1]), sys.argv[2])
