# webappfirewall

Un WAF (Web Application Firewall) en Rust, montado como proxy inverso transparente. Lo estoy armando para portafolio/tesis: la meta es detectar SQLi, XSS y path traversal/LFI, y aplicar rate limiting y detección de bots.

## Arquitectura

```
cliente → [Rate limiter] → [Normalizador] → [Motor de reglas] → [Decisión] → backend
                                                                    ↓ bloquear
                                                              403 + log de auditoría
```

Hoy el proxy solo reenvía el tráfico tal cual (fase 1). El resto de capas se va sumando sobre ese mismo pipeline.

## Estado actual

| Fase | Descripción | Estado |
|------|-------------|--------|
| 0 | Preparación (Rust, conceptos, backend de prueba) | ✅ |
| 1 | Proxy transparente (reenvía método, path, query, headers y body) | ✅ |
| 2 | Normalización (doble-encoding, minúsculas, null bytes, `//`, `..\`, comentarios SQL) | ✅ |
| 3 | Motor de reglas (`trait Detector`, `Match { rule_id, score, location }`) | ⬜ |
| 4 | Detectores (path traversal/LFI, SQLi, XSS) | ⬜ |
| 5 | Rate limiting (token bucket por IP) y bots (User-Agent, 404 seguidos) | ⬜ |
| 6 | Configuración (`waf.toml`, CLI, modos `detect-only`/`block`/anomaly score) | ⬜ |
| 7 | Logging y auditoría (`tracing` JSON, log por bloqueo) | ⬜ |
| 8 | Evaluación (corpus de payloads, % detección, falsos positivos, benchmark) | ⬜ |
| 9 | Demo y documentación (docker-compose, sqlmap/nikto local, tests de integración) | ⬜ |

## Stack

Por ahora: `tokio`, `axum` y `reqwest`. El checklist planea sumar `regex`, `percent-encoding`, `serde` + `toml`, `tracing`, `dashmap` y `clap`; y `criterion` para benchmarks.

## Uso

Para probarlo localmente:

1. Levanta un backend de prueba:

   ```sh
   python3 -m http.server 9000
   ```

2. Corre el WAF (escucha en `0.0.0.0:8081`, upstream `http://127.0.0.1:9000`):

   ```sh
   cargo run
   ```

3. Verifica que el tráfico pasa intacto:

   ```sh
   curl -v http://127.0.0.1:8081/
   ```

Si el upstream no responde, el WAF devuelve `502 Bad Gateway`.

## Tests

```sh
cargo test
```

Los tests de integración (`tests.rs`) levantan un stub upstream en un puerto libre y comprueban:

- GET: status, headers y body llegan intactos.
- POST: el body llega intacto.
- Upstream caído → `502`.

## Estructura

```
main.rs    servidor axum en :8081, fallback a proxy::handler
proxy.rs   handler del proxy: reenvía la petición al upstream y devuelve la respuesta
jev.rs     cliente Jev (respuestas tipadas): state, preguntas y veredicto detect-only (activa con JEV_API_KEY)
tests.rs   tests de integración contra un stub upstream
CHECKLIST.md  plan de trabajo por fases
```
