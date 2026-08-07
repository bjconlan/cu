#ifndef CU_SSE_H
#define CU_SSE_H

#include <stdbool.h>
#include <stddef.h>

/*===========================================================================
 * Server-Sent Events (SSE) parser — sans-IO.
 *
 * A pure state machine (no I/O, same model as cu_http_parser_t): feed it
 * the raw event-stream body bytes, pull complete events. Handles events
 * split across arbitrary feed boundaries.
 *
 * Generic wire-format layer: standard SSE fields only (data/event/id/
 * retry, comments). No application semantics — `[DONE]`, delta-JSON
 * interpretation, etc. belong to the consumer (e.g. the LLM dialect in
 * ACP).
 *
 * Spec: WHATWG Server-Sent Events. Lines end with \r\n, \n, or \r.
 * Multiple `data:` lines accumulate and join with a single \n. An event
 * is dispatched on the blank line or at EOF.
 *===========================================================================*/

/* A complete SSE event. data/event/id point into parser storage, valid
 * until the NEXT cu_sse_parser_event call (each event() releases the
 * previous event's storage) or destroy. Copy the strings out if you need
 * them longer. */
typedef struct cu_sse_event {
  const char *data; /* accumulated data (multiple data: lines joined) */
  size_t data_len;
  const char *event; /* event name ("" = default "message") */
  const char *id;    /* last event id ("" = none) */
  bool has_id;
  long retry_ms; /* -1 = not set */
} cu_sse_event_t;

/* Caller-allocated handle; opaque internals. */
typedef struct cu_sse_parser {
  void *_p;
} cu_sse_parser_t;

/* Initialize / destroy. */
void cu_sse_parser_init(cu_sse_parser_t *p);
void cu_sse_parser_destroy(cu_sse_parser_t *p);
void cu_sse_parser_reset(cu_sse_parser_t *p);

/* Feed bytes; events may become ready. Never blocks. */
void cu_sse_parser_feed(cu_sse_parser_t *p, const char *bytes, size_t len);

/* Returns 1 if a complete event is ready (call cu_sse_parser_event), 0 if
 * more data is needed. Call repeatedly after feeding. */
int cu_sse_parser_next(cu_sse_parser_t *p);

/* Copy the pending event into *out. Valid until the next feed. */
void cu_sse_parser_event(const cu_sse_parser_t *p, cu_sse_event_t *out);

#endif /* CU_SSE_H */
