# test-harness — local OTel collector for ngx-otel-rust

A minimal OTLP collector that `ngx-otel-rust` integration and benchmark
tests target.  Self-contained: one `docker compose up -d` and you're ready.

## What you get

- OTLP/HTTP receiver on `127.0.0.1:4318` (used by the OTLP/HTTP transport tests).
- OTLP/gRPC receiver on `127.0.0.1:4317` (used by the OTLP/gRPC transport tests).
- **Debug exporter** with `verbosity: detailed` — every received payload
  is printed to the collector container logs.
- **File exporter** writing JSON-encoded payloads to
  `test-harness/logs/metrics.json` for after-the-fact assertions.
  Append-only across runs; the integration scripts snapshot the file
  size before each run and inspect only the appended portion.
- Container name: `ngx-otel-test-collector`.

## How to run it

Manually:

```sh
cd test-harness && docker compose up -d        # start (idempotent)
docker compose logs -f otel-collector          # tail
docker compose down                            # stop
```

Or via the Makefile from the repo root:

```sh
make collector-up        # start (idempotent)
make collector-status    # show container status
make collector-down      # stop
```

The integration scripts under `tests/integration/` and `tests/bench/`
**auto-start the collector** when they detect it's not already
running.  Set `OTEL_COLLECTOR_AUTOSTART=0` to skip auto-start (useful
in CI environments that manage the collector externally).

## Quick sanity test

Once running, send a minimal OTLP/HTTP metrics payload as JSON:

```sh
curl -i -X POST http://127.0.0.1:4318/v1/metrics \
  -H 'Content-Type: application/json' \
  --data '{
    "resourceMetrics": [{
      "resource": {"attributes":[{"key":"service.name","value":{"stringValue":"smoke-test"}}]},
      "scopeMetrics": [{
        "scope": {"name":"smoke","version":"1.0"},
        "metrics": [{
          "name": "smoke.counter",
          "sum": {
            "isMonotonic": true,
            "aggregationTemporality": 2,
            "dataPoints": [{
              "timeUnixNano": "1700000000000000000",
              "asInt": "42"
            }]
          }
        }]
      }]
    }]
  }'
```

You should see a `200 OK` response and the payload printed in the
collector logs (look for `Metric #0`, `Name: smoke.counter`,
`Value: 42`).  The `ngx-otel-rust` module submits the same shape as
protobuf to the same endpoint.
