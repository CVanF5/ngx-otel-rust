#!/usr/bin/env python3
"""
Minimal IPv6 HTTP/1.1 stub for ngx-otel-rust integration testing.

Usage: python3 v6_http_stub.py <port> <output_file>

Listens on [::1]:<port> (TCP) and accepts HTTP/1.1 POST requests.
Each received request body is appended to <output_file>.  Responds with
HTTP/1.1 200 OK for every request.  Exits on SIGTERM or after a 5-second
idle gap with no incoming connections.

Designed to be run as a background process during IPv6 literal endpoint tests:

    python3 v6_http_stub.py 14318 /tmp/v6-received.bin &
    V6_PID=$!
    ...
    kill $V6_PID
    # Then check that /tmp/v6-received.bin is non-empty.
"""

import socket
import sys
import signal
import os


def _sigterm_handler(signum, frame):
    sys.exit(0)


def run(port: int, output: str) -> None:
    signal.signal(signal.SIGTERM, _sigterm_handler)

    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # IPV6_V6ONLY=1: only accept IPv6 on this socket; don't dual-bind.
    srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    srv.bind(("::1", port, 0, 0))
    srv.listen(16)
    # 5-second accept timeout: if no connection arrives, the stub exits.
    # In tests, nginx connects within the otel_metric_interval window.
    srv.settimeout(5.0)

    received_bytes = 0
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            # Idle gap — stub's job is done.
            break
        except OSError:
            break

        try:
            buf = b""
            # Read until the HTTP header/body separator.
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk

            hdr_end = buf.find(b"\r\n\r\n") + 4
            headers_raw = buf[:hdr_end].decode("utf-8", errors="replace")

            content_length = 0
            for line in headers_raw.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                    break

            body = buf[hdr_end:]
            while len(body) < content_length:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk

            # Append body to output file so the test script can verify receipt.
            with open(output, "ab") as f:
                f.write(body)
            received_bytes += len(body)

            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    srv.close()
    print(f"v6_http_stub: received {received_bytes} bytes total", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <output_file>", file=sys.stderr)
        sys.exit(1)
    run(int(sys.argv[1]), sys.argv[2])
