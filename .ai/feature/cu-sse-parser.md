# Plan: cu SSE parser (feature/cu-sse-parser)

## Scope

Add a generic Server-Sent Events parser to cu, consuming the byte stream
from the sans-IO HTTP parser's `CU_HTTP_EV_BODY` slices and emitting
complete SSE events. This is the wire-format layer — standard SSE fields
only, zero LLM assumptions (`[DONE]`, delta-JSON interpretation stay in
the ACP dialect layer).

Baseline: cu main @ 98d1b0c (sans-IO HTTP parser merged).

## Architecture

- **Data layer:**
  - `cu_sse_parser_t` — caller-allocated handle (same pattern as
    cu_http_parser_t): internal state holds a line buffer (events can
    span reads), current field values (data/event/id/retry), and event
    count
  - `cu_sse_event_t` — a complete event: `data` (accumulated across
    multiple data: lines, newline-joined), `event` name, `id`,
    optional `retry` (ms). Owned slices into the parser's buffer, valid
    until the next feed.
- **Function layer (pure, sans-IO):**
  - `cu_sse_parser_init(p)` / `cu_sse_parser_destroy(p)`
  - `cu_sse_parser_feed(p, bytes, len)` — consume bytes; internal state
    machine splits lines, handles `data:`/`event:`/`id:`/`retry:`/`:` 
    comment lines, and dispatches an event on the blank line
  - `cu_sse_parser_next(p)` — returns 1 if a complete event is ready
    (accessors fill it), 0 if more data is needed
  - `cu_sse_parser_event(p, cu_sse_event_t *out)` — copy the pending
    event out
- **Context layer:** per-stream state (a stream of events on one HTTP
  body). The caller (cu HTTP streaming consumer or the LLM dialect)
  feeds BODY slices in and pulls events.

## SSE format (WHATWG)

- Lines: `field: value`, `field` alone (empty value), `:comment`
- Fields: `data` (accumulate; multiple data lines join with \n),
  `event`, `id`, `retry`
- Event dispatched on the blank line (or EOF)
- Line ending: \r\n, \n, or \r — all accepted
- Unknown fields are ignored

## Units of Work

1. **Parser state machine**
   - What: `cu_sse.h` (new header) + `cu_sse.c` — line splitter, field
     handling, event dispatch on blank line. Handles events split across
     arbitrary feed boundaries.
   - Verification: unit tests — single event, multi-line data (joined
     with \n), event name, id, retry, comments ignored, \r\n and lone \r
     line endings, event split across multiple feeds byte-at-a-time.
   - Dependencies: none (standalone; uses cosmo str helpers where handy).

2. **Integration with HTTP streaming**
   - What: wire the SSE parser to consume `cu_http_parser` BODY events.
     A small example or test: stream an HTTP response with
     `Content-Type: text/event-stream` (chunked or unframed), drive both
     parsers, collect events.
   - Verification: loopback test serves an SSE response; the two-parser
     pipeline yields the expected events.
   - Dependencies: unit 1 + the sans-IO HTTP parser (merged).

## Verification Strategy

- **Parser (function layer):** byte-at-a-time and whole-buffer feeds
  yield identical events (same property the HTTP parser proved); every
  field handled; event split across feeds.
- **Pipeline (integration):** loopback SSE response → HTTP BODY chunks →
  SSE events, correct data/event/id.
- **API layer:** the cu SSE parser exposes no LLM concepts — the ACP
  dialect maps events to acp_llm_chunk_t later.

## References

- WHATWG SSE spec (field syntax, line endings, data accumulation)
- cu/http_client sans-IO parser (the pattern to mirror)
- Epic 6: `.ai/backlog/6.md` (feature/cu-sse-parser)

## Status

- **Stage:** 3 (Unit complete)
- **Current unit:** all done — parser + integration
- **Last checkpoint:** 27/27 tests. SSE parser handles data/event/id/
  retry, comments, \r\n/\n/\r endings, multi-line data, split feeds
  (byte-at-a-time proven). Integration test drives HTTP BODY events
  through the SSE parser over a loopback text/event-stream response.
- **Note:** SSE event pointers are valid until the next event() call
  (each read releases the previous event's storage) — consumers copy
  strings out.
- **Next action:** squash-merge to cu main, then ACP feature/http-sse
  (LLM dialect: SSE events -> acp_llm_chunk_t, replace the non-streaming
  fallback)
