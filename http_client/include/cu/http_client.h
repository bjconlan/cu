#ifndef CU_HTTP_CLIENT_H
#define CU_HTTP_CLIENT_H

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
