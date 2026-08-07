# Plan: cu HTTP sans-IO refactor

## Scope

Refactor `cu/http_client.h` from a monolithic `cu_http_fetch` (send →
read-loop → parse → buffer body → return) into a **sans-IO state machine
+ driver pump**, mirroring the BearSSL engine model already used by
cu/tls. This is the foundation for SSE streaming (Epic 6 P0) and gives
one consistent "engine + pump" shape across the whole cu wire stack.

Baseline: cu v0.1.0 (tagged before this refactor).

## Architecture

- **Data layer:**
  - `cu_http_parser_t` — opaque parser: owns `HttpMessage` (cosmo header
    state), `HttpUnchunker` (chunk state), receive buffer, framing enum
    (NONE / CONTENT_LENGTH / CHUNKED / UNFRAMED), header-end offset,
    consumed-count, event queue
  - Events: `CU_HTTP_EV_HEADERS` / `CU_HTTP_EV_BODY` / `CU_HTTP_EV_DONE` /
    `CU_HTTP_EV_ERROR` (enum in the header)
  - Body slices are returned by reference into the parser's buffer
    (caller copies if it needs them past the next feed)
- **Function layer (parser — pure, no I/O):**
  - `cu_http_parser_init(p, type)` — response or request
  - `cu_http_parser_feed(p, bytes, len)` → bytes consumed; advances the
    state machine (headers via `ParseHttpMessage`, body framing via
    `Unchunk` for chunked / count-down for content-length / pass-through
    for unframed)
  - `cu_http_parser_next(p)` → next event (HEADERS once, BODY per chunk,
    DONE when the response is complete, ERROR)
  - Accessors: `cu_http_parser_status(p)`, `cu_http_parser_headers(p,
    arr, cap)` (fills caller k/v array, NUL-terminating slices in place),
    `cu_http_parser_body(p, &len)` (current body slice)
  - `cu_http_parser_reset(p)` — reuse for keep-alive (amortize allocs)
- **Driver layer (pump — the only I/O):**
  - `cu_http_pump(parser, transport, want_event)` — reads from the
    transport, feeds the parser, returns when the wanted event fires (or
    EOF/error). Mirrors `cu_tls_pump`'s shape.
  - `cu_http_fetch(transport, req, rhdrs, cap)` — convenience: build
    request, drive the pump to DONE, assemble the existing
    `cu_http_response_t`. **Preserved unchanged** so current callers keep
    working.
- **Context layer:** parser state is per-request; reset() reuses it
  across keep-alive requests. The pump is per-request too. No globals.

## Units of Work

1. **Parser state machine**
   - What: `cu_http_parser_t` + init/feed/next/accessors in
     http_client.c (new). Framing-aware: content-length count-down,
     chunked via Unchunk, unframed pass-through. Incremental — feed may
     be called with arbitrarily split bytes.
   - Verification: unit test feeds a framed response one byte at a time
     and one event at a time; asserts HEADERS→BODY×N→DONE sequence and
     exact body.
   - Dependencies: none.

2. **Pump driver + fetch preservation**
   - What: `cu_http_pump` + rewrite `cu_http_fetch` as a driver over it.
     Drop forced `Connection: close` (add `keep_alive` flag on the
     request so streaming can hold the connection).
   - Verification: existing loopback tests (framed/chunked/unframed/
     keep-alive/large/custom-headers/response-headers) all pass unchanged;
     DeepSeek smoke parity.
   - Dependencies: unit 1.

3. **Byte-sequence tests**
   - What: extend the test suite — split every response at every byte
     boundary (or a stride), assert identical parse result. This is the
     property that proves incremental correctness (SSE depends on it).
   - Verification: new tests pass; 15/15 existing cu tests stay green.
   - Dependencies: units 1–2.

## Verification Strategy

- **Parser (function layer):** byte-at-a-time feeding yields the same
  events as whole-buffer feeding; framing branches (cl/chunked/unframed)
  each emit correct BODY chunks and DONE at the right boundary.
- **Driver (context layer):** `cu_http_fetch` output identical to v0.1.0
  for all existing loopback cases (parity regression).
- **API layer:** header/status accessors match the old response struct
  fields; keep-alive reset() reuses the parser across two requests.

## References

- BearSSL engine model (`br_ssl_engine_current_state`) — the sans-IO
  pattern cu/tls already follows
- cosmocc `ParseHttpMessage` / `Unchunk` — the incremental primitives
- Browser fetch `ReadableStream` — the pull-consumer mental model
- cu v0.1.0 tag — the pre-refactor baseline

## Status

- **Stage:** 3 (Unit complete)
- **Current unit:** all done — parser + pump + incremental tests
- **Last checkpoint:** 17/17 tests (9 HTTP incl. byte-at-a-time split
  tests), live example 200. Fixed: ParseHttpMessage capacity arg (rx.cap
  not rx.len — the parser errors on full buffers), request blank-line
  terminator, header NUL-termination + take_buf for response lifetime.
- **Next action:** squash-merge to cu main, bump past v0.1.0, then
  feature/cu-sse-parser
