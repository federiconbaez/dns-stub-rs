# dns-stub-rs

Resolver DNS stub para registros A/AAAA: pregunta a un servidor recursivo por UDP, cae a TCP si la respuesta viene truncada, sigue cadenas CNAME y cachea respuestas positivas y negativas según su TTL. Solo `std`, sin dependencias.

Stub DNS resolver for A/AAAA records: asks one recursive server over UDP, falls back to TCP when the answer is truncated, follows CNAME chains and caches positive and negative answers by TTL. `std` only, no dependencies.

```rust
let mut r = Resolver::new(Config::new("1.1.1.1:53".parse()?));
match r.lookup("www.github.com", QType::A)? {
    Answer::Addrs { addrs, canonical, ttl } => { /* ... */ }
    Answer::NxDomain { ttl } | Answer::NoData { ttl } => { /* negative, cached for ttl */ }
}
```

```
$ cargo run -- www.microsoft.com --server 1.1.1.1:53
```

## Español

**Qué hace**

- Parser del formato de red (RFC 1035) que nunca entra en pánico: compresión de nombres con punteros que deben apuntar **estrictamente hacia atrás** del tramo de etiquetas que cierran (los destinos decrecen, no hay ciclos posibles) más un tope de 64 saltos; nombres de hasta 255 octetos; conteos imposibles se rechazan antes de reservar memoria; RDATA de A/AAAA/CNAME/SOA validada contra su longitud; etiquetas escapadas (`\.`, `\DDD`) y en minúsculas.
- Aceptación estricta: solo desde la dirección del servidor, con el id de la consulta (aleatorio por consulta, puerto origen efímero), QR=1, opcode 0 y la misma pregunta. Lo demás se cuenta en `stats.ignored` y se sigue esperando hasta el timeout; luego reintenta.
- TC=1 → la misma consulta por TCP con prefijo de longitud.
- CNAME: sigue la cadena dentro de la respuesta (hasta 16 saltos, detecta ciclos); el TTL es el mínimo de la cadena.
- Negativos (RFC 2308): NXDOMAIN y NODATA con TTL = min(TTL del SOA, MINIMUM). Sin SOA no se cachea. SERVFAIL y otros errores nunca se cachean. TTL con el bit alto en 1 vale 0 (RFC 2181). Tope configurable (`max_ttl`, 1 día por defecto).
- Caché con capacidad: purga vencidas y si sigue llena saca la que vence antes. Reloj inyectable para tests.

**Pruebas** (`cargo test`, sin red)

- Las respuestas en `tests/fixtures/` son **reales**, grabadas el 22/10/2026 de Cloudflare (`1.1.1.1`) por DNS-over-HTTPS en formato de red: el UDP 53 de la máquina de desarrollo estaba interceptado y devolvía direcciones falsas (198.18.0.1), así que no servía para grabar. `examples/record_fixture.rs` graba por UDP donde el puerto 53 sea directo.
- Resolver (12): servidores UDP/TCP locales con guion que reproducen esas respuestas: A con caché que envejece y vence; AAAA y tipo como parte de la clave; cadenas CNAME reales (www.microsoft.com → edgekey → akamaiedge, TTL 1; www.github.com, TTL 27); NODATA de github.com AAAA (TTL 3517 del SOA); example.com, que responde NOERROR+SOA a nombres inexistentes; NXDOMAIN de un TLD inexistente con TTL recortado a `max_ttl`; **5 paquetes falsos** antes del bueno (id equivocado, otra pregunta, QR=0, cortado, otra dirección de origen) todos ignorados; reintento tras paquete perdido y timeout; fallback a TCP; SERVFAIL no cacheado; ciclo CNAME y cadena de 19 saltos rechazados; TTL con bit alto; nombres inválidos sin enviar nada; desalojo de la caché.
- Robustez (5): cada fixture cortada en **cada** byte falla limpio; 5248 mutaciones de un byte sin pánico (4044 siguen parseando); cadena de 5000 punteros legales cortada por el tope de saltos en menos de 100 ms; proptest con 8000 mensajes aleatorios.
- Unitarias (5): bytes exactos de la consulta, límites de nombres (63/255), punteros, escapes, conteos absurdos.
- Fuzzing: `cargo fuzz` del parser + interpretación, 60 s en CI; localmente 2,69 M ejecuciones en 61 s sin fallos.
- Mutaciones de control: sin chequeo de la pregunta, o sin chequeo de la dirección de origen, falla el test de paquetes falsos; sin la regla de punteros hacia atrás falla el unitario de punteros (los demás tests no lo notan porque el tope de saltos igual corta).

**Límites**: un solo servidor, sin EDNS(0) (respuestas UDP de hasta 512 bytes según el servidor), sin DNSSEC, sin `/etc/resolv.conf` ni búsqueda por dominios, solo clase IN y tipos A/AAAA. Un atacante en el camino que ve la consulta puede falsificar la respuesta; esto solo dificulta el ataque ciego.

## English

**What it does**

- Wire-format parser (RFC 1035) that never panics: name compression with pointers that must point **strictly backwards** of the label run they end (targets decrease, so loops are impossible) plus a 64-jump cap; names up to 255 octets; impossible counts rejected before allocating; A/AAAA/CNAME/SOA RDATA checked against its length; labels escaped (`\.`, `\DDD`) and lowercased.
- Strict acceptance: only from the server's address, with the query id (random per query, ephemeral source port), QR=1, opcode 0 and the same question. Anything else is counted in `stats.ignored` and the resolver keeps waiting until the timeout, then retries.
- TC=1 → the same query over length-prefixed TCP.
- CNAME: follows the chain inside the answer (up to 16 hops, detects loops); the TTL is the chain minimum.
- Negative (RFC 2308): NXDOMAIN and NODATA with TTL = min(SOA TTL, MINIMUM). No SOA, no caching. SERVFAIL and other errors are never cached. A TTL with the top bit set is 0 (RFC 2181). Configurable cap (`max_ttl`, one day by default).
- Bounded cache: purges expired entries and, if still full, evicts the soonest to expire. Injectable clock for tests.

**Tests** (`cargo test`, no network)

- The responses in `tests/fixtures/` are **real**, recorded on 2026-10-22 from Cloudflare (`1.1.1.1`) over DNS-over-HTTPS in wire format: UDP port 53 on the development machine was intercepted and returned fake addresses (198.18.0.1), so it was useless for recording. `examples/record_fixture.rs` records over UDP where port 53 is direct.
- Resolver (12): scripted local UDP/TCP servers replaying those responses: A with a cache that ages and expires; AAAA and type as part of the key; real CNAME chains (www.microsoft.com → edgekey → akamaiedge, TTL 1; www.github.com, TTL 27); NODATA for github.com AAAA (TTL 3517 from the SOA); example.com, which answers nonexistent names with NOERROR+SOA; NXDOMAIN for a nonexistent TLD with the TTL clamped to `max_ttl`; **5 bogus packets** before the good one (wrong id, other question, QR=0, cut short, other source address) all ignored; retry after a lost packet and timeout; TCP fallback; SERVFAIL not cached; CNAME loop and a 19-hop chain rejected; top-bit TTL; invalid names rejected before sending; cache eviction.
- Robustness (5): every fixture cut at **every** byte fails cleanly; 5,248 single-byte mutations without a panic (4,044 still parse); a chain of 5,000 legal pointers stopped by the jump cap in under 100 ms; proptest with 8,000 random messages.
- Unit (5): exact query bytes, name limits (63/255), pointers, escapes, absurd counts.
- Fuzzing: `cargo fuzz` over parse + interpret, 60 s in CI; locally 2.69 M runs in 61 s without a failure.
- Control mutations: without the question check, or without the source-address check, the bogus-packet test fails; without the backwards-pointer rule the pointer unit test fails (the other tests do not notice because the jump cap still stops it).

**Limits**: one server, no EDNS(0) (UDP answers up to 512 bytes, server-dependent), no DNSSEC, no `/etc/resolv.conf` or search domains, class IN and A/AAAA only. An on-path attacker who sees the query can still forge the answer; this only makes blind spoofing harder.

## License

Apache-2.0
