#ifndef CU_HTTP_CLIENT_H
#define CU_HTTP_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h> /* ssize_t */

/*===========================================================================
 * HTTP/1.1 client — single-file dep.
 *
 * Talks to a generic TRANSPORT (read/write function pointers); it has zero
 * knowledge of TLS or sockets. HTTPS is simply "HTTP through a TLS
 * transport" — the caller picks the transport (see the wiring layer).
 *
 * Framing is exact (content-length / chunked / unframed), so the transport
 * survives each response and can be reused (keep-alive). fetch never
 * closes the transport — the caller owns its lifetime.
 *
 * Parsing uses cosmocc primitives: ParseHttpMessage (incremental header
 * parse), Unchunk (in-place chunked decode), GetHttpHeader. The 32KB
 * ParseHttpMessage cap applies to the header; bodies are assembled
 * separately and are not truncated.
 *
 * Header naming follows cosmo: cu_http_header_t uses k (name) / v (value),
 * and header arrays are caller-owned pointer + count (like cosmo's
 * HttpHeaders n/c pattern).
 *===========================================================================*/

/*--- Header --------------------------------------------------------------*/

typedef struct {
  const char *k; /* header name */
  const char *v; /* header value */
} cu_http_header_t;

/*--- Transport -----------------------------------------------------------*/

typedef struct cu_http_transport {
  ssize_t (*read)(void *ctx, void *buf, size_t len);
  ssize_t (*write)(void *ctx, const void *buf, size_t len);
  void *ctx;
} cu_http_transport_t;

/*--- Request -------------------------------------------------------------*/

typedef struct {
  const char *method;              /* default "GET" */
  const char *path;                /* e.g. "/v1/chat/completions" */
  const char *host;                /* for the Host header */
  const cu_http_header_t *headers; /* optional, caller-owned array */
  size_t num_headers;
  const char *body;
  size_t body_len;
  bool keep_alive; /* default false: sends Connection: close. Set true to
                    * hold the connection open (streaming/SSE). */
} cu_http_request_t;

/*--- Response ------------------------------------------------------------*/

typedef struct {
  int status_code; /* 200, 400, 401, etc. */
  char *body;      /* malloc'd response body (NUL-terminated) */
  size_t body_len;
  int parse_error; /* non-zero if parsing failed */
  /* Response headers (filled when rhdrs passed to fetch): k/v point into
   * internal storage, valid until cu_http_response_free. */
  cu_http_header_t *headers;
  size_t num_headers;
  size_t headers_cap;
  void *_buf; /* internal: header/recv storage, freed by cu_http_response_free */
} cu_http_response_t;

/*--- sans-IO parser ------------------------------------------------------*/

/* Parser events. The parser is a pure state machine — no I/O. Feed it
 * bytes with cu_http_parser_feed(), pull events with
 * cu_http_parser_next(). HEADERS fires once, BODY once per decoded
 * chunk, DONE when the response is complete (connection reusable). */
typedef enum {
  CU_HTTP_EV_HEADERS,   /* status + headers available */
  CU_HTTP_EV_BODY,      /* one body chunk (slice via cu_http_parser_body) */
  CU_HTTP_EV_DONE,      /* response complete; reset() to reuse */
  CU_HTTP_EV_NEED_MORE, /* no event without more input — feed + retry */
  CU_HTTP_EV_ERROR,     /* malformed input */
} cu_http_event_t;

/* Parser type: what the parser is parsing. Mirrors cosmo's
 * kHttpResponse/kHttpRequest (1 = response, 0 = request). */
enum { CU_HTTP_RESPONSE = 1, CU_HTTP_REQUEST = 0 };

/* Parser handle — caller-allocated (declare on the stack), opaque internals.
 * The parser heap-allocates its receive buffer on demand; destroy frees it. */
typedef struct cu_http_parser {
  void *_p; /* internal state */
} cu_http_parser_t;

/* Initialize a parser for response (kHttpResponse) or request parsing. */
void cu_http_parser_init(cu_http_parser_t *p, int type);

/* Reset for keep-alive reuse (same parser, next response). */
void cu_http_parser_reset(cu_http_parser_t *p, int type);

/* Feed bytes; returns bytes consumed (may be < len if the response ends
 * early or the buffer is exhausted). Never blocks. */
size_t cu_http_parser_feed(cu_http_parser_t *p, const char *bytes, size_t len);

/* Pull the next event. Returns CU_HTTP_EV_ERROR on malformed input. */
cu_http_event_t cu_http_parser_next(cu_http_parser_t *p);

/* Valid after CU_HTTP_EV_HEADERS. */
int cu_http_parser_status(const cu_http_parser_t *p);

/* Fill headers[0..cap) with response headers (k/v pointing into parser
 * storage, valid until the next feed). Returns the count written. */
size_t cu_http_parser_headers(const cu_http_parser_t *p, cu_http_header_t *headers,
                              size_t cap);

/* Current BODY slice (valid until the next feed). Returns a pointer into
 * parser storage; sets *len. */
const char *cu_http_parser_body(const cu_http_parser_t *p, size_t *len);

/* Was the response body unframed (no content-length, no chunked)? */
bool cu_http_parser_unframed(const cu_http_parser_t *p);

/* Detach the parser's receive buffer (caller owns it now) — keeps header
 * k/v pointers valid past destroy. */
char *cu_http_parser_take_buf(cu_http_parser_t *p);

/* Destroy (frees the parser's buffer). */
void cu_http_parser_destroy(cu_http_parser_t *p);

/*--- API ----------------------------------------------------------------*/

/*
 * Send one HTTP request over the borrowed transport and read the full
 * response. Returns a malloc'd response (free via cu_http_response_free)
 * or NULL on transport/parse failure. The transport is NOT closed.
 *
 * rhdrs/rhdrs_cap: optional caller-owned array; fetch fills it with the
 * response headers in arrival order (rhdrs_cap == 0 to skip).
 */
cu_http_response_t *cu_http_fetch(cu_http_transport_t *t, const cu_http_request_t *req,
                                  cu_http_header_t *rhdrs, size_t rhdrs_cap);

/*
 * Free a response.
 */
void cu_http_response_free(cu_http_response_t *resp);

#endif /* CU_HTTP_CLIENT_H */
