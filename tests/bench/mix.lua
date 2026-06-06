-- Weighted request mix for the soak (moderate, sustained — not a flood).
-- Exercises every telemetry path:
--   /            200 -> metric histograms + exemplar reservoir
--   /notfound    404 -> access exception tail (is-interesting gate)
--   /fail        500 -> access exception tail
--   /flood{,2,3} dead upstreams -> nginx error-log events (3 distinct templates,
--                                   so coalescing still yields visible samples)
-- ~30% of requests carry a W3C traceparent so exemplars capture a trace_id.
-- delay() throttles each connection to a realistic think-time so access-tail
-- records flow without pathologically flooding the per-worker ring.
math.randomseed(os.time())

local paths = {}
local function add(p, n) for _ = 1, n do paths[#paths + 1] = p end end
add("/", 88)
add("/notfound", 3)
add("/fail", 3)
add("/flood", 2)
add("/flood2", 2)
add("/flood3", 2)

local hexchars = "0123456789abcdef"
local function hex(n)
  local s = ""
  for _ = 1, n do
    local k = math.random(1, 16)
    s = s .. hexchars:sub(k, k)
  end
  return s
end

request = function()
  local p = paths[math.random(#paths)]
  if math.random(100) <= 30 then
    return wrk.format("GET", p, { ["traceparent"] = "00-" .. hex(32) .. "-" .. hex(16) .. "-01" })
  end
  return wrk.format("GET", p)
end

-- Per-connection think-time (ms), jittered. With ~50 connections this caps
-- throughput in the low tens of thousands of RPS — a busy-but-realistic nginx.
function delay()
  return math.random(3, 12)
end
