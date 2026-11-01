# webappfirewall

Un WAF (Web Application Firewall) en Rust, montado como proxy inverso transparente. Lo estoy armando para portafolio/tesis: la meta es detectar SQLi, XSS y path traversal/LFI, y aplicar rate limiting y detección de bots.

## Arquitectura

```
cliente → [Rate limiter] → [Normalizador] → [Motor de reglas] → [Decisión] → backend
                                                                    ↓ bloquear
                                                              403 + log de auditoría
```

Hoy el proxy reenvía el tráfico tal cual y, con `JEV_API_KEY`, pregunta a Jev y loguea el veredicto (detect-only). El resto de capas se va sumando sobre ese mismo pipeline. Ver `PLAN.md`.

## Estado actual

| Fase | Descripción | Estado |
|------|-------------|--------|
| 0 | Preparación (Rust, conceptos, backend de prueba) | ✅ |
| 1 | Proxy transparente (reenvía método, path, query, headers y body) | ✅ |
| 2 | Normalización (doble-encoding, minúsculas, null bytes, `//`, `..\`, comentarios SQL) | ✅ |
| 2.5 | Cliente Jev detect-only (`jev.rs`, `playground.html`) | ✅ |
| 3 | Inspección completa vía Jev (body bufferizado, timeout, fail-open) | ⬜ |
| 4 | Decisión (`trait Detector`, umbral, 403 + log de auditoría) | ⬜ |
| 5 | Rate limiting (token bucket por IP) y bots (User-Agent, 404 seguidos) | ⬜ |
| 6 | Configuración (`waf.toml`, CLI, modos `detect-only`/`block`/anomaly score) | ⬜ |
| 7 | Logging y auditoría (`tracing` JSON, log por bloqueo) | ⬜ |
| 8 | Evaluación (corpus de payloads, % detección, falsos positivos, benchmark) | ⬜ |
| 9 | Demo y documentación (docker-compose, sqlmap/nikto local, tests de integración) | ⬜ |

## Stack

Por ahora: `tokio`, `axum`, `reqwest`, `serde_json` y `percent-encoding`. El checklist planea sumar `regex`, `toml`, `tracing`, `dashmap` y `clap`; y `criterion` para benchmarks.

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
PLAN.md      plan de diseño (Jev como motor de detección)
CHECKLIST.md checklist de trabajo por fases
```
