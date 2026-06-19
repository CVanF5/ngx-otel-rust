#!/usr/bin/env python3
"""
Programmable HTTP/1.1 OTLP collector stub for delivery-outcome integration tests.

Usage:
    python3 programmable_collector_stub.py <port> <scenario_file> <request_count_file>

The stub listens on 127.0.0.1:<port> and serves HTTP responses according to a
scenario file.  The scenario file is read fresh for each request so it can be
updated by the controlling test script at runtime.

Scenario file format (one directive per line, first matching line wins):
    503 Retry-After: 2       # respond 503 with Retry-After: 2 (seconds)
    503                      # respond 503 with no Retry-After
    400                      # respond 400 (Bad Request)
    401                      # respond 401 (Unauthorized)
    403                      # respond 403 (Forbidden)
    200                      # respond 200 (Accepted)
    200 N                    # respond 200 for the next N requests then re-read

The request_count_file is appended to after each request:
    <status_code>\\n
This allows the test script to track how many requests were made and
with what outcome.

Exits on SIGTERM or after a 30-second idle gap with no incoming connections.

Notes:
- Responds with a minimal valid OTLP ExportMetricsServiceResponse body on 200.
- On 503 + Retry-After the response header is: Retry-After: <value>
- This stub ONLY handles the HTTP/1.1 framing needed for OTLP/HTTP POST.
  It does not validate the OTLP protobuf body.
"""

import os
import socket
import sys
import signal
import time


def _sigterm_handler(signum, frame):
    sys.exit(0)


def _read_scenario(scenario_file: str) -> tuple[int, dict]:
    """Read the scenario file and return (status_code, extra_headers).

    Supported directives (first non-comment line wins):
        503 Retry-After: 2   — respond 503 with a Retry-After header
        503                  — respond 503 with no extra headers
        400 / 401 / 403      — respond with that status
        200                  — respond 200
        200 N                — respond 200 for the next N requests;
                               the file is rewritten to 200 N-1 (or bare 200
                               when N reaches 1) so subsequent reads decrement
                               the counter automatically.
    """
    with open(scenario_file) as f:
        line = f.readline().strip()

    if not line or line.startswith("#"):
        return 200, {}

    parts = line.split(None, 2)
    code = int(parts[0])  # ValueError propagates — caller must not swallow it
    extra: dict[str, str] = {}

    if len(parts) == 1:
        # Bare status code, e.g. "200" or "503".
        return code, extra

    # parts[1] is either a plain integer (the N in "200 N") or the start of a
    # header value (e.g. "Retry-After:" in "503 Retry-After: 2").
    remainder = parts[1]

    if remainder.isdigit():
        # "200 N" form: serve 200 and decrement the counter in the file.
        n = int(remainder)
        if n > 1:
            with open(scenario_file, "w") as f:
                f.write(f"{code} {n - 1}\n")
        else:
            # Counter exhausted — rewrite to a bare status so the next read
            # re-evaluates the scenario without a countdown.
            with open(scenario_file, "w") as f:
                f.write(f"{code}\n")
        return code, extra

    # Header continuation: reassemble the full header value from the split.
    # "503 Retry-After: 2" → parts = ["503", "Retry-After:", "2"]
    full_remainder = line[len(parts[0]):].strip()
    hdr_name, hdr_val = full_remainder.split(":", 1)
    extra[hdr_name.strip()] = hdr_val.strip()
    return code, extra


def _record_request(count_file: str, status: int) -> None:
    """Append status code to the request count file."""
    try:
        with open(count_file, "a") as f:
            f.write(f"{status}\n")
    except Exception:
        pass


def _build_response(status: int, extra_headers: dict) -> bytes:
    """Build a minimal HTTP/1.1 response for the given status."""
    reasons = {200: "OK", 400: "Bad Request", 401: "Unauthorized",
               403: "Forbidden", 429: "Too Many Requests",
               503: "Service Unavailable", 504: "Gateway Timeout"}
    reason = reasons.get(status, "Unknown")

    # A minimal valid OTLP ExportMetricsServiceResponse protobuf (empty = all accepted).
    # Proto3: empty message serializes to zero bytes — Content-Length: 0 is valid.
    body = b""

    hdrs = [
        f"HTTP/1.1 {status} {reason}\r\n",
        "Content-Type: application/x-protobuf\r\n",
        f"Content-Length: {len(body)}\r\n",
    ]
    for name, val in extra_headers.items():
        hdrs.append(f"{name}: {val}\r\n")
    hdrs.append("\r\n")

    return "".join(hdrs).encode() + body


def run(port: int, scenario_file: str, count_file: str) -> None:
    signal.signal(signal.SIGTERM, _sigterm_handler)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(32)
    srv.settimeout(30.0)

    print(f"programmable_collector_stub: listening on 127.0.0.1:{port}", flush=True)

    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            print("programmable_collector_stub: idle timeout — exiting", flush=True)
            break
        except OSError:
            break

        try:
            buf = b""
            # Read until end of HTTP headers.
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk

            if b"\r\n\r\n" not in buf:
                conn.close()
                continue

            hdr_end = buf.find(b"\r\n\r\n") + 4
            headers_raw = buf[:hdr_end].decode("utf-8", errors="replace")

            # Determine Content-Length and drain the body (don't process it).
            content_length = 0
            for hdr_line in headers_raw.split("\r\n"):
                if hdr_line.lower().startswith("content-length:"):
                    try:
                        content_length = int(hdr_line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                    break

            body_so_far = buf[hdr_end:]
            while len(body_so_far) < content_length:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                body_so_far += chunk

            # Read the current scenario.
            status, extra_headers = _read_scenario(scenario_file)

            # Build and send the response.
            resp = _build_response(status, extra_headers)
            conn.sendall(resp)

            # Record the outcome.
            _record_request(count_file, status)
            print(f"programmable_collector_stub: served {status} (extra={extra_headers})", flush=True)

        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    srv.close()
    print("programmable_collector_stub: done", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} <port> <scenario_file> <request_count_file>",
            file=sys.stderr,
        )
        sys.exit(1)
    run(int(sys.argv[1]), sys.argv[2], sys.argv[3])
