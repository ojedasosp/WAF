# web application firewall

A web application firewall (WAF) in Rust, built as a transparent reverse proxy. It sits in front of an origin server, screens each request for SQL injection, XSS and path traversal / LFI, and applies per-IP rate limiting.

## How a request flows

```
client → [rate limiter] → [body buffer] → [normalizer + fast-path regex]
       → [Jev classification (if JEV_API_KEY set)] → [decision] → upstream
                                                       ↓ block
                                                 403 + audit line
```

1. **Rate limit** — token bucket per IP (`governor`), 50 requests/second. Over the limit → `429`.
2. **Body buffer** — the body is buffered with a 1 MiB cap before anything else runs. Bigger than that → `413`.
3. **Fast path** — if `JEV_API_KEY` is in the environment, the path is normalized (repeated percent-decoding up to 10 passes, lowercasing, null bytes and SQL comments stripped, `//` collapsed, `..\` → `../`) and the normalized path + raw query + body are screened against a small set of regexes for basic SQLi, XSS and LFI. Benign traffic skips Jev entirely.
4. **Jev classification** — only when the fast path flags something, the request state (method, path, query, headers, body) is sent to the Jev API (`jev-latest` model, 10 s timeout). Jev answers typed questions: attack type (`benign`/`sqli`/`xss`/`lfi`), a maliciousness score, and a threat level 0–2.
5. **Decision** — `threat_level >= 2` blocks the request: one audit line on stderr plus a `403` with a simple HTML page naming the rule that fired (`sqli`=1, `xss`=2, `lfi`=3). Lower scores are logged as detect-only. If Jev errors out, the WAF fails open and forwards the request.
6. **Forward** — method, path, query, headers and body are passed through to the upstream untouched (redirects are disabled, 300 s upstream timeout). Upstream unreachable → `502`.

## Status codes

| Code | When |
|------|------|
| `429` | IP over the 50 req/s rate limit |
| `413` | Body larger than 1 MiB |
| `403` | Jev threat level ≥ 2 (simple block page + audit line) |
| `502` | Upstream down or unreachable |
| `200`/upstream status | Everything else, forwarded as-is |

## Running it

1. Start a test backend:

   ```sh
   python3 -m http.server 9000
   ```

2. Run the WAF (listens on `0.0.0.0:8081`, upstream `http://127.0.0.1:9000`):

   ```sh
   cargo run
   ```

3. Verify traffic passes through untouched:

   ```sh
   curl -v http://127.0.0.1:8081/
   ```

4. Optionally set `JEV_API_KEY` to enable detection:

   ```sh
   JEV_API_KEY=jev_test_... cargo run
   ```

   With the key set, every fast-path hit is classified by Jev and the verdict is printed to stderr; blocks print an `[audit]` line.

`playground.html` is a manual test page (served at `http://127.0.0.1:8081/playground.html`) that runs sample requests through the WAF and can ask Jev about the last one.

## Tests

```sh
cargo test
```

- Unit tests per module: normalization (double-encoding, case, comments, null bytes, `//`, `..\`), fast-path regexes (SQLi/XSS/LFI + benign), Jev answer mapping, rate limiter quota.
- Integration tests (`tests.rs`) spin up a stub upstream on a free port and check: GET status/headers/body arrive intact, POST body arrives intact, over the rate limit → `429`, body > 1 MiB → `413`, upstream down → `502`.
- `proxy.rs` has a unit test for the block path: `403` with the rule ID in the page body.

## Files

```
main.rs          axum server on 0.0.0.0:8081, fallback to proxy::handler
proxy.rs         handler: rate limit, body buffer, fast path, Jev, decision, forward; blocked() = 403 + page + audit line
fast_path.rs     regex fast path: basic SQLi/XSS/LFI patterns
normalization.rs path normalization (percent-decode, lowercase, null bytes, comments, //, ..\)
jev.rs           Jev client: state builder, typed questions, verdict formatting
detector.rs      Detector trait + JevDetector: maps Jev answers to a Match (rule_id, score, location)
rate_limiter.rs  token bucket per IP (governor): 50 rps
tests.rs         integration tests against a stub upstream
playground.html  manual test page
```

## Stack

`tokio`, `axum`, `reqwest`, `serde_json`, `percent-encoding`, `governor` (token bucket), `regex` (fast path).
