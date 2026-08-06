#define _POSIX_C_SOURCE 200809L
#include "cu/http_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/http/http.h>

/*===========================================================================
 * HTTP/1.1 client — transport-agnostic, built on cosmocc parsing.
 *
 * Header parsing via ParseHttpMessage (incremental; returns bytes consumed
 * when the header block completes). Body assembly:
 *   - content-length: exact read of N bytes after the header
 *   - chunked: Unchunk in-place over the body region
 *   - unframed: read until EOF (Connection: close)
 * Exact framing keeps the transport reusable across requests.
 *===========================================================================*/

/* A read chunk that grows the receive buffer on demand. */
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

/* Serialize the request head into buf. Returns length, or -1 if it
 * doesn't fit. */
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
    int hn = snprintf(buf + n, cap - (size_t)n, "%s: %s\r\n", req->headers[i].k, req->headers[i].v);
    if (hn < 0 || (size_t)hn >= cap - (size_t)n)
      return -1;
    n += hn;
  }
  {
    int hn = snprintf(buf + n, cap - (size_t)n, "Connection: close\r\n\r\n");
    if (hn < 0 || (size_t)hn >= cap - (size_t)n)
      return -1;
    n += hn;
  }
  return n;
}

static int parse_headers(struct HttpMessage *msg, const char *buf, size_t len, int *status_out,
                         int64_t *content_len_out, int *chunked_out) {
  int rc;
  *content_len_out = -1;
  *chunked_out = 0;
  InitHttpMessage(msg, kHttpResponse);
  rc = ParseHttpMessage(msg, buf, len, len);
  if (rc <= 0)
    return rc; /* -1 error, 0 need more data */
  *status_out = msg->status;
  {
    struct HttpSlice s = msg->headers[kHttpContentLength];
    if (s.a) {
      *content_len_out = ParseContentLength(buf + s.a, (size_t)(s.b - s.a));
    }
  }
  {
    struct HttpSlice s = msg->headers[kHttpTransferEncoding];
    if (s.a && (size_t)(s.b - s.a) >= 7 && memcmp(buf + s.a, "chunked", 7) == 0)
      *chunked_out = 1;
  }
  return rc;
}

cu_http_response_t *cu_http_fetch(cu_http_transport_t *t, const cu_http_request_t *req,
                                  cu_http_header_t *rhdrs, size_t rhdrs_cap) {
  cu_http_response_t *resp = NULL;
  cu_http_rx rx = {0};
  char head[4096];
  int head_len;
  struct HttpMessage msg;
  int status = 0;
  int64_t content_len = -1;
  int chunked = 0;
  size_t body_start = 0;

  if (!t || !t->read || !t->write || !req || !req->path)
    return NULL;

  /* Serialize + send the request. */
  head_len = request_write(req, head, sizeof head);
  if (head_len < 0)
    return NULL;
  {
    const char *p = head;
    int left = head_len;
    if (req->body && req->body_len) {
      /* header then body in one logical write via two calls */
    }
    while (left > 0) {
      ssize_t n = t->write(t->ctx, p, (size_t)left);
      if (n <= 0)
        goto out;
      p += n;
      left -= (int)n;
    }
    if (req->body && req->body_len) {
      const char *b = req->body;
      size_t bleft = req->body_len;
      while (bleft > 0) {
        ssize_t n = t->write(t->ctx, b, bleft);
        if (n <= 0)
          goto out;
        b += n;
        bleft -= (size_t)n;
      }
    }
  }

  /* Receive until the header block completes. */
  for (;;) {
    int rc;
    if (rx_reserve(&rx, 4096) != 0)
      goto out;
    ssize_t n = t->read(t->ctx, rx.buf + rx.len, rx.cap - rx.len - 1);
    if (n == 0) {
      if (rx.len == 0)
        goto out; /* EOF before any data */
      break;
    }
    if (n < 0)
      goto out;
    rx.len += (size_t)n;
    rc = parse_headers(&msg, rx.buf, rx.len, &status, &content_len, &chunked);
    if (rc > 0) {
      body_start = (size_t)rc;
      break;
    }
    if (rc < 0)
      goto out;
    /* rc == 0: need more data */
  }
  if (body_start == 0 && rx.len > 0) {
    /* headers may have completed exactly at the last read; retry parse */
    int rc = parse_headers(&msg, rx.buf, rx.len, &status, &content_len, &chunked);
    if (rc > 0)
      body_start = (size_t)rc;
    else if (rc < 0)
      goto out;
    else
      goto out; /* incomplete header at EOF */
  }

  resp = (cu_http_response_t *)calloc(1, sizeof *resp);
  if (!resp)
    goto out;
  resp->status_code = status;
  resp->headers = rhdrs;
  resp->headers_cap = rhdrs_cap;

  /* Collect response headers into the caller's array (if provided).
   * The parser stores length-delimited slices; NUL-terminate each value
   * in place (parsing is complete, the buffer is ours). */
  for (int h = 0; h < kHttpHeadersMax && resp->headers_cap > resp->num_headers; h++) {
    struct HttpSlice s = msg.headers[h];
    if (s.a == 0)
      continue;
    const char *name = GetHttpHeaderName(h);
    if (name == NULL)
      continue;
    rx.buf[s.b] = 0;
    resp->headers[resp->num_headers].k = name;
    resp->headers[resp->num_headers].v = rx.buf + s.a;
    resp->num_headers++;
  }
  /* repeatable/unknown headers spilled into xheaders */
  for (size_t h = 0; h < msg.xheaders.n && resp->headers_cap > resp->num_headers; h++) {
    rx.buf[msg.xheaders.p[h].k.b] = 0;
    rx.buf[msg.xheaders.p[h].v.b] = 0;
    resp->headers[resp->num_headers].k = rx.buf + msg.xheaders.p[h].k.a;
    resp->headers[resp->num_headers].v = rx.buf + msg.xheaders.p[h].v.a;
    resp->num_headers++;
  }

  if (chunked) {
    /* Decode chunked body in place over the body region. */
    struct HttpUnchunker u;
    memset(&u, 0, sizeof u);
    for (;;) {
      size_t decoded = 0;
      ssize_t rc = Unchunk(&u, rx.buf + body_start, rx.len - body_start, &decoded);
      if (rc < 0) {
        resp->parse_error = -1;
        goto out;
      }
      if (rc > 0) {
        resp->body = (char *)malloc(decoded + 1);
        if (!resp->body)
          goto out;
        memcpy(resp->body, rx.buf + body_start, decoded);
        resp->body[decoded] = 0;
        resp->body_len = decoded;
        goto done;
      }
      /* need more chunk data */
      if (rx_reserve(&rx, 4096) != 0)
        goto out;
      ssize_t n = t->read(t->ctx, rx.buf + rx.len, rx.cap - rx.len - 1);
      if (n == 0) {
        resp->parse_error = -1; /* truncated chunked body */
        goto out;
      }
      if (n < 0) {
        resp->parse_error = -1;
        goto out;
      }
      rx.len += (size_t)n;
    }
  } else if (content_len >= 0) {
    /* Exact content-length read. */
    size_t want = body_start + (size_t)content_len;
    while (rx.len < want) {
      if (rx_reserve(&rx, 4096) != 0)
        goto out;
      ssize_t n = t->read(t->ctx, rx.buf + rx.len, rx.cap - rx.len - 1);
      if (n == 0)
        break; /* premature EOF */
      if (n < 0)
        goto out;
      rx.len += (size_t)n;
    }
    if (rx.len < want) {
      resp->parse_error = -1; /* truncated body */
      goto out;
    }
    resp->body = (char *)malloc((size_t)content_len + 1);
    if (!resp->body)
      goto out;
    memcpy(resp->body, rx.buf + body_start, (size_t)content_len);
    resp->body[(size_t)content_len] = 0;
    resp->body_len = (size_t)content_len;
  } else {
    /* Unframed: read until EOF, everything after the header is body. */
    for (;;) {
      if (rx_reserve(&rx, 4096) != 0)
        goto out;
      ssize_t n = t->read(t->ctx, rx.buf + rx.len, rx.cap - rx.len - 1);
      if (n == 0)
        break;
      if (n < 0)
        goto out;
      rx.len += (size_t)n;
    }
    size_t blen = rx.len - body_start;
    resp->body = (char *)malloc(blen + 1);
    if (!resp->body)
      goto out;
    memcpy(resp->body, rx.buf + body_start, blen);
    resp->body[blen] = 0;
    resp->body_len = blen;
  }

done:
  /* the receive buffer is owned by the response (header k/v point into
   * it) — freed by cu_http_response_free */
  if (resp)
    resp->_buf = rx.buf;
  else if (rx.buf)
    free(rx.buf);
  return resp;

out:
  if (resp && !resp->body)
    resp->parse_error = resp->parse_error ? resp->parse_error : -1;
  if (rx.buf)
    free(rx.buf);
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
