# webappfirewall

A WAF (Web Application Firewall) in Rust, set up as a transparent reverse proxy. I'm building it for my portfolio/thesis: the goal is to detect SQLi, XSS and path traversal/LFI, and to apply rate limiting and bot detection.

## Architecture

```
client → [Rate limiter] → [Normalizer] → [Rule engine] → [Decision] → backend
                                                          ↓ block
                                                    403 + audit log
```

What the proxy does today: it limits each IP to 50 requests/second (`429`), buffers the body with a 1 MiB cap (`413`) and, if `JEV_API_KEY` is in the environment, screens each request with a regex fast path (basic SQLi/XSS/LFI) and only asks Jev when something looks suspicious. If Jev rates `threat_level` ≥ 2 the request is blocked with `403` plus an audit log line; otherwise the verdict is just logged. The remaining layers get added on top of the same pipeline. See `PLAN.md`.

## Current status

| Phase | Description | Status |
|------|-------------|--------|
| 0 | Setup (Rust, concepts, test backend) | ✅ |
| 1 | Transparent proxy (forwards method, path, query, headers and body) | ✅ |
| 2 | Normalization (double-encoding, lowercase, null bytes, `//`, `..\`, SQL comments) | ✅ |
| 2.5 | Jev client detect-only (`jev.rs`, `playground.html`) | ✅ |
| 3 | Full inspection via Jev (buffered body, timeout, fail-open) | ✅ |
| 4 | Decision (`trait Detector`, threshold, 403 + audit log) | ◐ |
| 5 | Rate limiting (token bucket per IP, `429`) and bots (User-Agent, consecutive 404s) | ◐ |
| 6 | Configuration (`waf.toml`, CLI, `detect-only`/`block`/anomaly score modes) | ⬜ |
| 7 | Logging and audit (`tracing` JSON, log per block) | ⬜ |
| 8 | Evaluation (payload corpus, detection %, false positives, benchmark) | ⬜ |
| 9 | Demo and documentation (docker-compose, local sqlmap/nikto, integration tests) | ⬜ |

## Stack

What I'm using so far: `tokio`, `axum`, `reqwest`, `serde_json`, `percent-encoding`, `governor` for the token bucket per IP and `regex` for the fast path. The checklist plans to add `toml`, `tracing` and `clap`, plus `criterion` for benchmarks.

## Usage

To try it locally:

1. Start a test backend:

   ```sh
   python3 -m http.server 9000
   ```

2. Run the WAF (listens on `0.0.0.0:8081`, upstream `http://127.0.0.1:9000`):

   ```sh
   cargo run
   ```

3. Verify that traffic passes through untouched:

   ```sh
   curl -v http://127.0.0.1:8081/
   ```

If the upstream doesn't respond, the WAF returns `502 Bad Gateway`. With `JEV_API_KEY` in the environment, every request gets classified and the verdict is printed to stderr.

## Tests

```sh
cargo test
```

The integration tests (`tests.rs`) spin up a stub upstream on a free port and check:

- GET: status, headers and body arrive intact.
- POST: the body arrives intact.
- Going over the rate limit → `429`.
- Body larger than 1 MiB → `413`.
- Upstream down → `502`.

## Structure

```
main.rs    axum server on :8081, fallback to proxy::handler
proxy.rs   proxy handler: rate limit, buffers the body, fast-path screen, asks Jev, forwards to upstream
fast_path.rs  regex fast path: basic SQLi/XSS/LFI patterns, skips Jev on benign traffic
rate_limiter.rs  token bucket per IP (governor): 50 rps, 429 when exceeded
jev.rs     Jev client (typed responses): state, questions and detect-only verdict (enabled with JEV_API_KEY)
tests.rs   integration tests against a stub upstream
PLAN.md      design plan (Jev as the detection engine)
CHECKLIST.md work checklist by phase
```
