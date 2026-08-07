#define _POSIX_C_SOURCE 200809L
#include "cu/http_client.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/http/http.h>

/*===========================================================================
 * HTTP/1.1 client — sans-IO parser + driver pump.
 *
 * The PARSER (cu_http_parser_t) is a pure state machine: no I/O. Feed it
 * bytes, pull events (HEADERS / BODY / DONE / ERROR). Framing is exact:
 * content-length (count-down), chunked (Unchunk), unframed (pass-through
 * until EOF). This mirrors BearSSL's engine model (cu/tls is the same
 * shape: engine + pump).
 *
 * The DRIVER (cu_http_fetch) wires the parser to a transport, mirroring
 * cu_tls_pump. fetch is preserved as a convenience for the common
 * buffer-the-body case; streaming callers drive the parser directly.
 *===========================================================================*/

/*--- Receive buffer (owned by the parser) --------------------------------*/

typedef struct cu_http_rx {
  char *buf;
  size_t len;
  size_t cap;
} cu_http_rx;

static int rx_reserve(cu_http_rx *r, size_t extra) {
  size_t need = r->len + extra + 1; /* +1 for NUL */
  if (need <= r->cap)
    return 0;
  size_t cap = r->cap ? r->cap : 4096;
  while (cap < need)
    cap *= 2;
  char *q = realloc(r->buf, cap);
  if (!q)
    return -1;
  r->buf = q;
  r->cap = cap;
  return 0;
}

/*--- Parser --------------------------------------------------------------*/

typedef enum cu_http_phase {
  CU_HTTP_PH_HEADERS, /* parsing the header block */
  CU_HTTP_PH_BODY,    /* parsing the body (framing-aware) */
  CU_HTTP_PH_DONE,    /* complete; DONE emitted */
  CU_HTTP_PH_ERROR,   /* malformed */
} cu_http_phase_t;

typedef enum cu_http_frame {
  CU_HTTP_FRAME_NONE,  /* no body (e.g. 204) */
  CU_HTTP_FRAME_LEN,   /* content-length */
  CU_HTTP_FRAME_CHUNK, /* transfer-encoding: chunked */
  CU_HTTP_FRAME_EOF,   /* unframed: until close */
} cu_http_frame_t;

struct cu_http_parser_state {
  int type; /* kHttpRequest | kHttpResponse */
  cu_http_phase_t phase;
  cu_http_frame_t frame;
  cu_http_rx rx;      /* receive buffer; header slices point into it */
  struct HttpMessage msg;  /* cosmo header state (incremental) */
  struct HttpUnchunker u;  /* cosmo chunk state (incremental) */
  size_t hdr_end;     /* offset of body start in rx.buf */
  size_t body_consumed; /* bytes of body already emitted */
  int64_t content_len;  /* for FRAME_LEN */
  int status;
  cu_http_event_t ev;   /* pending event, or -1 */
  int parsed_headers;   /* HEADERS event already emitted */
  int unframed;         /* response had no framing headers */
};

static void state_init(struct cu_http_parser_state *s, int type) {
  memset(s, 0, sizeof *s);
  s->type = type;
  s->phase = CU_HTTP_PH_HEADERS;
  s->frame = CU_HTTP_FRAME_NONE;
  s->content_len = -1;
  s->ev = (cu_http_event_t)-1;
}

void cu_http_parser_init(cu_http_parser_t *p, int type) {
  p->_p = calloc(1, sizeof(struct cu_http_parser_state));
  if (p->_p)
    state_init((struct cu_http_parser_state *)p->_p, type);
}

void cu_http_parser_reset(cu_http_parser_t *p, int type) {
  struct cu_http_parser_state *s = (struct cu_http_parser_state *)p->_p;
  if (s)
    state_init(s, type);
}

/* Detach the parser's receive buffer (caller owns it now). Used by
 * cu_http_fetch so response header k/v pointers stay valid until free. */
char *cu_http_parser_take_buf(cu_http_parser_t *p) {
  struct cu_http_parser_state *s = (struct cu_http_parser_state *)p->_p;
  char *buf = s->rx.buf;
  s->rx.buf = NULL;
  s->rx.len = 0;
  s->rx.cap = 0;
  return buf;
}

void cu_http_parser_destroy(cu_http_parser_t *p) {
  struct cu_http_parser_state *s = (struct cu_http_parser_state *)p->_p;
  if (s) {
    if (s->rx.buf)
      free(s->rx.buf);
    free(s);
  }
  p->_p = NULL;
}

/* Parse the header block from rx.buf. Returns >0 = header end offset,
 * 0 = need more data, <0 = malformed. */
static int parse_headers(struct cu_http_parser_state *s) {
  struct HttpMessage *msg = &s->msg;
  int rc;
  InitHttpMessage(msg, s->type);
  rc = ParseHttpMessage(msg, s->rx.buf, s->rx.len, s->rx.cap);
  if (rc <= 0)
    return rc;
  if (s->type == kHttpResponse) {
    s->status = msg->status;
    struct HttpSlice h = msg->headers[kHttpContentLength];
    if (h.a)
      s->content_len = ParseContentLength(s->rx.buf + h.a, (size_t)(h.b - h.a));
    h = msg->headers[kHttpTransferEncoding];
    if (h.a && (size_t)(h.b - h.a) >= 7 && memcmp(s->rx.buf + h.a, "chunked", 7) == 0)
      s->frame = CU_HTTP_FRAME_CHUNK;
    else if (s->content_len >= 0)
      s->frame = CU_HTTP_FRAME_LEN;
    else if (msg->status >= 200 && msg->status != 204 && msg->status != 304)
      s->frame = CU_HTTP_FRAME_EOF; /* unframed */
    s->unframed = (s->frame == CU_HTTP_FRAME_EOF);
  }
  return rc;
}

size_t cu_http_parser_feed(cu_http_parser_t *p, const char *bytes, size_t len) {
  struct cu_http_parser_state *s = (struct cu_http_parser_state *)p->_p;
  if (s->phase == CU_HTTP_PH_DONE || s->phase == CU_HTTP_PH_ERROR)
    return 0; /* terminal */
  if (rx_reserve(&s->rx, len) != 0) {
    s->phase = CU_HTTP_PH_ERROR;
    s->ev = CU_HTTP_EV_ERROR;
    return 0;
  }
  memcpy(s->rx.buf + s->rx.len, bytes, len);
  s->rx.len += len;
  return len; /* we buffer everything; events are pulled */
}

cu_http_event_t cu_http_parser_next(cu_http_parser_t *p) {
  struct cu_http_parser_state *s = (struct cu_http_parser_state *)p->_p;
  if (s->ev != (cu_http_event_t)-1) {
    cu_http_event_t e = s->ev;
    s->ev = (cu_http_event_t)-1;
    return e;
  }
  if (s->phase == CU_HTTP_PH_ERROR)
    return CU_HTTP_EV_ERROR;

  if (s->phase == CU_HTTP_PH_HEADERS) {
    if (s->rx.len == 0) {
      return CU_HTTP_EV_NEED_MORE; /* nothing to parse yet */
    }
    int rc = parse_headers(s);
    if (rc < 0) {
      s->phase = CU_HTTP_PH_ERROR;
      return CU_HTTP_EV_ERROR;
    }
    if (rc == 0)
      return CU_HTTP_EV_NEED_MORE; /* headers incomplete */
    s->parsed_headers = 1;
    s->hdr_end = (size_t)rc;
    if (s->frame == CU_HTTP_FRAME_CHUNK)
      memset(&s->u, 0, sizeof s->u);
    s->phase = CU_HTTP_PH_BODY;
    return CU_HTTP_EV_HEADERS;
  }

  /* BODY / DONE phase */
  switch (s->frame) {
  case CU_HTTP_FRAME_NONE:
    s->phase = CU_HTTP_PH_DONE;
    return CU_HTTP_EV_DONE;

  case CU_HTTP_FRAME_LEN: {
    size_t want = s->hdr_end + (size_t)s->content_len;
    if (s->rx.len >= want) {
      s->body_consumed = want;
      s->phase = CU_HTTP_PH_DONE;
      s->ev = CU_HTTP_EV_DONE;
      return CU_HTTP_EV_BODY; /* exact body as one BODY */
    }
    return CU_HTTP_EV_NEED_MORE;
  }

  case CU_HTTP_FRAME_CHUNK: {
    size_t decoded = 0;
    ssize_t rc = Unchunk(&s->u, s->rx.buf + s->hdr_end, s->rx.len - s->hdr_end, &decoded);
    if (rc < 0) {
      s->phase = CU_HTTP_PH_ERROR;
      return CU_HTTP_EV_ERROR;
    }
    size_t decoded_so_far = s->body_consumed - s->hdr_end;
    if (rc > 0) {
      /* terminal chunk seen: decoded holds the full body */
      s->body_consumed = s->hdr_end + decoded;
      s->phase = CU_HTTP_PH_DONE;
      s->ev = CU_HTTP_EV_DONE;
      return CU_HTTP_EV_BODY;
    }
    if (decoded > decoded_so_far) {
      /* new decoded bytes available */
      s->body_consumed = s->hdr_end + decoded;
      return CU_HTTP_EV_BODY;
    }
    return CU_HTTP_EV_NEED_MORE;
  }

  default: /* FRAME_EOF */
    if (s->rx.len > s->body_consumed) {
      s->body_consumed = s->rx.len;
      return CU_HTTP_EV_BODY;
    }
    return CU_HTTP_EV_NEED_MORE;
  }
}

int cu_http_parser_status(const cu_http_parser_t *p) {
  const struct cu_http_parser_state *s = (const struct cu_http_parser_state *)p->_p;
  return s->status;
}

size_t cu_http_parser_headers(const cu_http_parser_t *p, cu_http_header_t *headers,
                              size_t cap) {
  const struct cu_http_parser_state *s = (const struct cu_http_parser_state *)p->_p;
  const struct HttpMessage *msg = &s->msg;
  size_t n = 0;
  char *buf = s->rx.buf; /* mutable: NUL-terminate slices in place */
  for (int h = 0; h < kHttpHeadersMax && n < cap; h++) {
    struct HttpSlice s = msg->headers[h];
    if (s.a == 0)
      continue;
    const char *name = GetHttpHeaderName(h);
    if (name == NULL)
      continue;
    buf[s.b] = 0; /* terminate the value at its end */
    headers[n].k = name;
    headers[n].v = buf + s.a;
    n++;
  }
  for (size_t h = 0; h < msg->xheaders.n && n < cap; h++) {
    buf[msg->xheaders.p[h].k.b] = 0;
    buf[msg->xheaders.p[h].v.b] = 0;
    headers[n].k = buf + msg->xheaders.p[h].k.a;
    headers[n].v = buf + msg->xheaders.p[h].v.a;
    n++;
  }
  return n;
}

const char *cu_http_parser_body(const cu_http_parser_t *p, size_t *len) {
  const struct cu_http_parser_state *s = (const struct cu_http_parser_state *)p->_p;
  /* For chunked, Unchunk compacts decoded bytes to [hdr_end, ...) — the
   * whole decoded region is the body. For LEN/EOF it's [hdr_end, rx.len). */
  *len = (s->body_consumed > s->hdr_end ? s->body_consumed : s->rx.len) - s->hdr_end;
  return s->rx.buf + s->hdr_end;
}

bool cu_http_parser_unframed(const cu_http_parser_t *p) {
  const struct cu_http_parser_state *s = (const struct cu_http_parser_state *)p->_p;
  return s->unframed != 0;
}

/*--- Request serialization ------------------------------------------------*/

static int request_write(const cu_http_request_t *req, char *buf, size_t cap) {
  const char *method = req->method && req->method[0] ? req->method : "GET";
  size_t body_len = req->body ? req->body_len : 0;
  int n = snprintf(buf, cap,
                   "%s %s HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Content-Length: %zu\r\n",
                   method, req->path ? req->path : "/", req->host ? req->host : "", body_len);
  if (n < 0 || (size_t)n >= cap)
    return -1;
  for (size_t i = 0; i < req->num_headers; i++) {
    int hn = snprintf(buf + n, cap - (size_t)n, "%s: %s\r\n", req->headers[i].k,
                      req->headers[i].v);
    if (hn < 0 || (size_t)hn >= cap - (size_t)n)
      return -1;
    n += hn;
  }
  if (!req->keep_alive) {
    int hn = snprintf(buf + n, cap - (size_t)n, "Connection: close\r\n");
    if (hn < 0 || (size_t)hn >= cap - (size_t)n)
      return -1;
    n += hn;
  }
  { /* blank line terminates the header block */
    int hn = snprintf(buf + n, cap - (size_t)n, "\r\n");
    if (hn < 0 || (size_t)hn >= cap - (size_t)n)
      return -1;
    n += hn;
  }
  return n;
}

/*--- Driver (pump) --------------------------------------------------------*/

/* Drive the parser from the transport until the wanted event fires or the
 * connection closes. Returns the event that terminated the loop. */
static cu_http_event_t http_pump(cu_http_parser_t *p, cu_http_transport_t *t,
                                 cu_http_event_t want) {
  struct cu_http_parser_state *st = (struct cu_http_parser_state *)p->_p;
  char tmp[4096];
  for (;;) {
    cu_http_event_t ev = cu_http_parser_next(p);
    if (ev == want || ev == CU_HTTP_EV_ERROR)
      return ev;
    if (ev == CU_HTTP_EV_DONE)
      return ev; /* terminal */
    if (ev != CU_HTTP_EV_NEED_MORE)
      continue; /* BODY/HEADERS: loop to the next event */
    /* need more data: read from the transport and feed the parser */
    ssize_t n = t->read(t->ctx, tmp, sizeof tmp);
    if (n == 0) {
      /* EOF: unframed bodies end here; framed ones are truncated */
      if (st->phase == CU_HTTP_PH_BODY && st->frame == CU_HTTP_FRAME_EOF)
        return CU_HTTP_EV_DONE;
      return CU_HTTP_EV_ERROR;
    }
    if (n < 0)
      return CU_HTTP_EV_ERROR;
    cu_http_parser_feed(p, tmp, (size_t)n);
  }
}

cu_http_response_t *cu_http_fetch(cu_http_transport_t *t, const cu_http_request_t *req,
                                  cu_http_header_t *rhdrs, size_t rhdrs_cap) {
  cu_http_response_t *resp = NULL;
  cu_http_parser_t p;
  char head[4096];
  int head_len;

  if (!t || !t->read || !t->write || !req || !req->path)
    return NULL;

  /* Serialize + send the request. */
  head_len = request_write(req, head, sizeof head);
  if (head_len < 0)
    return NULL;
  {
    const char *b = head;
    size_t left = (size_t)head_len;
    while (left > 0) {
      ssize_t n = t->write(t->ctx, b, left);
      if (n <= 0)
        return NULL;
      b += n;
      left -= (size_t)n;
    }
    b = req->body;
    left = req->body ? req->body_len : 0;
    while (left > 0) {
      ssize_t n = t->write(t->ctx, b, left);
      if (n <= 0)
        return NULL;
      b += n;
      left -= (size_t)n;
    }
  }

  /* Drive the parser to completion. */
  cu_http_parser_init(&p, kHttpResponse);
  cu_http_event_t ev = http_pump(&p, t, CU_HTTP_EV_DONE);
  if (ev == CU_HTTP_EV_ERROR)
    goto out;

  /* Assemble the response. */
  resp = (cu_http_response_t *)calloc(1, sizeof *resp);
  if (!resp)
    goto out;
  resp->status_code = cu_http_parser_status(&p);
  resp->headers = rhdrs;
  resp->headers_cap = rhdrs_cap;
  resp->num_headers = cu_http_parser_headers(&p, rhdrs, rhdrs_cap);

  {
    size_t blen;
    const char *bslice = cu_http_parser_body(&p, &blen);
    /* body slice covers [hdr_end, rx.len) — the full body */
    resp->body = (char *)malloc(blen + 1);
    if (!resp->body)
      goto out;
    memcpy(resp->body, bslice, blen);
    resp->body[blen] = 0;
    resp->body_len = blen;
    /* header k/v point into the parser's buffer — take it so they stay
     * valid until cu_http_response_free */
    resp->_buf = cu_http_parser_take_buf(&p);
  }

  cu_http_parser_destroy(&p);
  return resp;

out:
  cu_http_parser_destroy(&p);
  if (resp) {
    free(resp->body);
    free(resp);
  }
  return NULL;
}

void cu_http_response_free(cu_http_response_t *resp) {
  if (resp) {
    free(resp->_buf);
    free(resp->body);
    free(resp);
  }
}
