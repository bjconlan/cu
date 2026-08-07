/*
 * HTTP client loopback tests: a fork-based HTTP server on 127.0.0.1
 * serves scripted responses over a PLAIN fd transport (no TLS — the HTTP
 * dep must not know about TLS). Covers framing (content-length, chunked,
 * unframed), keep-alive reuse, and large bodies (>32KB ParseHttpMessage
 * cap).
 */
#define _POSIX_C_SOURCE 200809L
#include "cu/http_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tests/greatest.h"

/* --- fd transport (the wiring layer's plain-HTTP adapter) --- */

typedef struct fd_ctx {
  int fd;
} fd_ctx_t;

static ssize_t fd_read(void *ctx, void *buf, size_t len) {
  fd_ctx_t *c = (fd_ctx_t *)ctx;
  return recv(c->fd, buf, len, 0);
}

static ssize_t fd_write(void *ctx, const void *buf, size_t len) {
  fd_ctx_t *c = (fd_ctx_t *)ctx;
  const char *p = buf;
  size_t left = len;
  while (left > 0) {
    ssize_t n = send(c->fd, p, left, 0);
    if (n <= 0)
      return -1;
    p += n;
    left -= (size_t)n;
  }
  return (ssize_t)len;
}

/* --- scripted HTTP server --- */

typedef struct resp_script {
  const char *resp; /* complete raw response */
  int times;        /* serve this many times (-1 = until close) */
} resp_script_t;

static int bind_loopback(int *out_port) {
  struct sockaddr_in addr;
  socklen_t alen = sizeof addr;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 4) != 0 ||
      getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
    close(fd);
    return -1;
  }
  *out_port = ntohs(addr.sin_port);
  return fd;
}

static int wait_child(pid_t pid, int *status, int timeout_ms) {
  int waited = 0;
  for (;;) {
    pid_t r = waitpid(pid, status, WNOHANG);
    if (r == pid)
      return 0;
    if (r < 0)
      return -1;
    if (waited >= timeout_ms) {
      kill(pid, SIGKILL);
      waitpid(pid, status, 0);
      return -1;
    }
    struct timespec ts = {0, 10 * 1000 * 1000};
    nanosleep(&ts, NULL);
    waited += 10;
  }
}

/* Serve exactly `nconns` connections; for each, read the request, then
 * write the scripted responses (keep-alive: each response `times` times
 * per connection). Exit after nconns connections so wait_child returns. */
static void server_serve(int listen_fd, const resp_script_t *scripts, int nscripts, int nconns) {
  int served = 0;
  while (served < nconns) {
    int conn = accept(listen_fd, NULL, NULL);
    char reqbuf[4096];
    size_t reqlen = 0;
    int si;
    if (conn < 0)
      _exit(2);
    served++;
    /* read the request head */
    for (;;) {
      ssize_t n = recv(conn, reqbuf + reqlen, sizeof reqbuf - reqlen, 0);
      if (n <= 0)
        break;
      reqlen += (size_t)n;
      /* look for the \r\n\r\n header terminator */
      if (reqlen >= 4) {
        size_t i;
        int found = 0;
        for (i = 0; i + 4 <= reqlen; i++) {
          if (reqbuf[i] == '\r' && reqbuf[i + 1] == '\n' && reqbuf[i + 2] == '\r' &&
              reqbuf[i + 3] == '\n') {
            found = 1;
            break;
          }
        }
        if (found)
          break;
      }
    }
    /* serve each script the requested number of times */
    for (si = 0; si < nscripts; si++) {
      int times = scripts[si].times;
      if (times < 0)
        times = 1;
      for (int i = 0; i < times; i++) {
        const char *p = scripts[si].resp;
        size_t left = strlen(p);
        while (left > 0) {
          ssize_t n = send(conn, p, left, 0);
          if (n <= 0)
            break;
          p += n;
          left -= (size_t)n;
        }
      }
    }
    close(conn);
  }
  _exit(0);
}

/* Connect a client fd to the loopback server. */
static int client_connect(int port) {
  struct sockaddr_in addr;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

/* Spawn the server, run fn(port), reap. Returns 0 on success. */
static int with_server(const resp_script_t *scripts, int nscripts, int (*fn)(int port, void *ud),
                       void *ud) {
  int port;
  int listen_fd = bind_loopback(&port);
  pid_t pid;
  int status;
  if (listen_fd < 0)
    return -1;
  pid = fork();
  if (pid < 0) {
    close(listen_fd);
    return -1;
  }
  if (pid == 0) {
    server_serve(listen_fd, scripts, nscripts, 1);
  }
  int rc = fn(port, ud);
  int w = wait_child(pid, &status, 5000);
  close(listen_fd);
  if (rc == 0 && w != 0)
    rc = -1;
  return rc;
}

/* --- tests --- */

#define FRAMED_RESP                                                                                \
  "HTTP/1.1 200 OK\r\n"                                                                            \
  "Content-Type: text/plain\r\n"                                                                   \
  "Content-Length: 12\r\n"                                                                         \
  "\r\n"                                                                                           \
  "hello world!"

#define CHUNKED_RESP                                                                               \
  "HTTP/1.1 200 OK\r\n"                                                                            \
  "Transfer-Encoding: chunked\r\n"                                                                 \
  "\r\n"                                                                                           \
  "6\r\nhello \r\n"                                                                                \
  "7\r\nchunked\r\n"                                                                               \
  "0\r\n\r\n"

#define UNFRAMED_RESP                                                                              \
  "HTTP/1.1 200 OK\r\n"                                                                            \
  "\r\n"                                                                                           \
  "no length here"

static int do_fetch(int port, void *ud) {
  cu_http_response_t *r;
  fd_ctx_t ctx;
  cu_http_transport_t t;
  cu_http_request_t req;
  (void)ud;
  ctx.fd = client_connect(port);
  if (ctx.fd < 0)
    return -1;
  t.read = fd_read;
  t.write = fd_write;
  t.ctx = &ctx;

  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";

  r = cu_http_fetch(&t, &req, NULL, 0);
  close(ctx.fd);
  if (!r)
    return -1;
  int ok = (r->status_code == 200 && r->body_len == 12 && memcmp(r->body, "hello world!", 12) == 0);
  cu_http_response_free(r);
  return ok ? 0 : -1;
}

TEST test_framed(void) {
  resp_script_t s = {FRAMED_RESP, 1};
  ASSERT(with_server(&s, 1, do_fetch, NULL) == 0);
  PASS();
}

static int do_fetch_chunked(int port, void *ud) {
  cu_http_response_t *r;
  fd_ctx_t ctx;
  cu_http_transport_t t;
  cu_http_request_t req;
  (void)ud;
  ctx.fd = client_connect(port);
  if (ctx.fd < 0)
    return -1;
  t.read = fd_read;
  t.write = fd_write;
  t.ctx = &ctx;
  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";

  r = cu_http_fetch(&t, &req, NULL, 0);
  close(ctx.fd);
  if (!r)
    return -1;
  int ok =
      (r->status_code == 200 && r->body_len == 13 && memcmp(r->body, "hello chunked", 13) == 0);
  cu_http_response_free(r);
  return ok ? 0 : -1;
}

TEST test_chunked(void) {
  resp_script_t s = {CHUNKED_RESP, 1};
  ASSERT(with_server(&s, 1, do_fetch_chunked, NULL) == 0);
  PASS();
}

static int do_fetch_unframed(int port, void *ud) {
  cu_http_response_t *r;
  fd_ctx_t ctx;
  cu_http_transport_t t;
  cu_http_request_t req;
  (void)ud;
  ctx.fd = client_connect(port);
  if (ctx.fd < 0)
    return -1;
  t.read = fd_read;
  t.write = fd_write;
  t.ctx = &ctx;
  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";

  r = cu_http_fetch(&t, &req, NULL, 0);
  close(ctx.fd);
  if (!r)
    return -1;
  int ok =
      (r->status_code == 200 && r->body_len == 14 && memcmp(r->body, "no length here", 14) == 0);
  cu_http_response_free(r);
  return ok ? 0 : -1;
}

TEST test_unframed(void) {
  resp_script_t s = {UNFRAMED_RESP, 1};
  ASSERT(with_server(&s, 1, do_fetch_unframed, NULL) == 0);
  PASS();
}

/* Keep-alive: two requests over ONE transport; the server answers each
 * request with one framed response (script times=2). */
static int do_keepalive(int port, void *ud) {
  cu_http_response_t *r1, *r2;
  fd_ctx_t ctx;
  cu_http_transport_t t;
  cu_http_request_t req;
  (void)ud;
  ctx.fd = client_connect(port);
  if (ctx.fd < 0)
    return -1;
  t.read = fd_read;
  t.write = fd_write;
  t.ctx = &ctx;
  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";

  r1 = cu_http_fetch(&t, &req, NULL, 0);
  if (!r1) {
    close(ctx.fd);
    return -1;
  }
  r2 = cu_http_fetch(&t, &req, NULL, 0);
  close(ctx.fd);
  if (!r2) {
    cu_http_response_free(r1);
    return -1;
  }
  int ok = r1->status_code == 200 && r1->body_len == 12 && r2->status_code == 200 &&
           r2->body_len == 12 && memcmp(r2->body, "hello world!", 12) == 0;
  cu_http_response_free(r1);
  cu_http_response_free(r2);
  return ok ? 0 : -1;
}

TEST test_keepalive(void) {
  /* server writes the framed response twice per connection */
  resp_script_t s = {FRAMED_RESP, 2};
  ASSERT(with_server(&s, 1, do_keepalive, NULL) == 0);
  PASS();
}

/* Large body > 32KB: the ParseHttpMessage cap must not truncate it. */
#define BIG_BODY_LEN (40 * 1024)

static int do_large(int port, void *ud) {
  cu_http_response_t *r;
  fd_ctx_t ctx;
  cu_http_transport_t t;
  cu_http_request_t req;
  (void)ud;
  ctx.fd = client_connect(port);
  if (ctx.fd < 0)
    return -1;
  t.read = fd_read;
  t.write = fd_write;
  t.ctx = &ctx;
  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";

  r = cu_http_fetch(&t, &req, NULL, 0);
  close(ctx.fd);
  if (!r)
    return -1;
  int ok = (r->status_code == 200 && r->body_len == BIG_BODY_LEN && r->body[0] == 'A' &&
            r->body[BIG_BODY_LEN - 1] == 'Z');
  cu_http_response_free(r);
  return ok ? 0 : -1;
}

TEST test_large_body(void) {
  static char big[64 * 1024];
  int n = snprintf(big, sizeof big,
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Length: %d\r\n"
                   "\r\n",
                   BIG_BODY_LEN);
  memset(big + n, 'A', (size_t)(BIG_BODY_LEN / 2));
  memset(big + n + BIG_BODY_LEN / 2, 'A', (size_t)(BIG_BODY_LEN - BIG_BODY_LEN / 2));
  big[n + BIG_BODY_LEN - 1] = 'Z';
  big[n + BIG_BODY_LEN] = 0;
  resp_script_t s = {big, 1};
  ASSERT(with_server(&s, 1, do_large, NULL) == 0);
  PASS();
}

static int do_fetch_headers(int port, void *ud) {
  cu_http_response_t *r;
  fd_ctx_t ctx;
  cu_http_transport_t t;
  cu_http_header_t hdrs[2] = {
      {"X-Test", "value123"},
      {"Authorization", "Bearer sk-test"},
  };
  cu_http_request_t req;
  (void)ud;
  ctx.fd = client_connect(port);
  if (ctx.fd < 0)
    return -1;
  t.read = fd_read;
  t.write = fd_write;
  t.ctx = &ctx;
  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";
  req.host = "example.test";
  req.headers = hdrs;
  req.num_headers = 2;

  r = cu_http_fetch(&t, &req, NULL, 0);
  close(ctx.fd);
  if (!r)
    return -1;
  int ok = (r->status_code == 200 && r->body_len == 12 && memcmp(r->body, "hello world!", 12) == 0);
  cu_http_response_free(r);
  return ok ? 0 : -1;
}

TEST test_custom_headers(void) {
  resp_script_t s = {FRAMED_RESP, 1};
  ASSERT(with_server(&s, 1, do_fetch_headers, NULL) == 0);
  PASS();
}

/* Response headers: pass a caller array, verify k/v filled. */
static int do_fetch_resp_headers(int port, void *ud) {
  cu_http_response_t *r;
  fd_ctx_t ctx;
  cu_http_transport_t t;
  cu_http_request_t req;
  cu_http_header_t rhdrs[8];
  int found_ct = 0, found_len = 0, i;
  (void)ud;
  ctx.fd = client_connect(port);
  if (ctx.fd < 0)
    return -1;
  t.read = fd_read;
  t.write = fd_write;
  t.ctx = &ctx;
  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";
  req.host = "example.test";

  r = cu_http_fetch(&t, &req, rhdrs, 8);
  close(ctx.fd);
  if (!r)
    return -1;
  for (i = 0; i < (int)r->num_headers; i++) {
    if (strcmp(r->headers[i].k, "Content-Type") == 0 && strcmp(r->headers[i].v, "text/plain") == 0)
      found_ct = 1;
    if (strcmp(r->headers[i].k, "Content-Length") == 0 && strcmp(r->headers[i].v, "12") == 0)
      found_len = 1;
  }
  int ok = (r->status_code == 200 && r->body_len == 12 && found_ct && found_len);
  cu_http_response_free(r);
  return ok ? 0 : -1;
}

TEST test_response_headers(void) {
  resp_script_t s = {FRAMED_RESP, 1};
  ASSERT(with_server(&s, 1, do_fetch_resp_headers, NULL) == 0);
  PASS();
}

/* sans-IO: feed a response one byte at a time; assert the event sequence
 * matches a whole-buffer feed. This is the property SSE streaming
 * depends on (arbitrarily split reads). */
static void collect_events(const char *resp, size_t resp_len, int split,
                           int *status, char *body, size_t *body_len,
                           size_t *n_events) {
  cu_http_parser_t p;
  cu_http_parser_init(&p, 1); /* kHttpResponse */
  size_t fed = 0;
  *n_events = 0;
  *body_len = 0;
  *status = 0;
  while (fed < resp_len) {
    size_t chunk = 1;
    if (split > 1) {
      chunk = (size_t)split;
      if (chunk > resp_len - fed)
        chunk = resp_len - fed;
    }
    cu_http_parser_feed(&p, resp + fed, chunk);
    fed += chunk;
    for (;;) {
      cu_http_event_t ev = cu_http_parser_next(&p);
      if (ev == CU_HTTP_EV_NEED_MORE)
        break;
      if (ev == CU_HTTP_EV_ERROR)
        return;
      (*n_events)++;
      if (ev == CU_HTTP_EV_HEADERS)
        *status = cu_http_parser_status(&p);
      if (ev == CU_HTTP_EV_BODY) {
        size_t blen;
        const char *b = cu_http_parser_body(&p, &blen);
        memcpy(body + *body_len, b, blen);
        *body_len += blen;
      }
      if (ev == CU_HTTP_EV_DONE)
        goto done;
    }
  }
  /* drain remaining events after EOF */
  for (;;) {
    cu_http_event_t ev = cu_http_parser_next(&p);
    if (ev == CU_HTTP_EV_NEED_MORE)
      break;
    if (ev == CU_HTTP_EV_ERROR)
      break;
    (*n_events)++;
    if (ev == CU_HTTP_EV_DONE)
      break;
  }
done:
  cu_http_parser_destroy(&p);
}

TEST test_incremental_split(void) {
  const char *resp =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 12\r\n"
      "\r\n"
      "hello world!";
  char body1[64], body2[64];
  size_t bl1 = 0, bl2 = 0, ne1 = 0, ne2 = 0;
  int st1 = 0, st2 = 0;
  collect_events(resp, strlen(resp), 0, &st1, body1, &bl1, &ne1);
  collect_events(resp, strlen(resp), 1, &st2, body2, &bl2, &ne2);
  ASSERT_EQ(st1, st2);
  ASSERT_EQ(200, st1);
  ASSERT_EQ((int)bl1, (int)bl2);
  ASSERT_EQ(12, (int)bl1);
  ASSERT(memcmp(body1, body2, bl1) == 0);
  ASSERT(memcmp(body1, "hello world!", 12) == 0);
  /* byte-at-a-time must emit the same body and reach DONE */
  ASSERT(ne1 >= 2); /* HEADERS + BODY + DONE */
  PASS();
}

TEST test_incremental_chunked_split(void) {
  const char *resp =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "6\r\nhello \r\n7\r\nchunked\r\n0\r\n\r\n";
  char body1[64], body2[64];
  size_t bl1 = 0, bl2 = 0, ne1 = 0, ne2 = 0;
  int st1 = 0, st2 = 0;
  collect_events(resp, strlen(resp), 0, &st1, body1, &bl1, &ne1);
  collect_events(resp, strlen(resp), 1, &st2, body2, &bl2, &ne2);
  ASSERT_EQ(200, st1);
  ASSERT_EQ(13, (int)bl1);
  ASSERT(memcmp(body1, "hello chunked", 13) == 0);
  ASSERT(memcmp(body1, body2, bl1) == 0);
  ASSERT(ne1 >= 2);
  PASS();
}

SUITE(http_suite) {
  RUN_TEST(test_framed);
  RUN_TEST(test_chunked);
  RUN_TEST(test_unframed);
  RUN_TEST(test_keepalive);
  RUN_TEST(test_large_body);
  RUN_TEST(test_custom_headers);
  RUN_TEST(test_response_headers);
  RUN_TEST(test_incremental_split);
  RUN_TEST(test_incremental_chunked_split);
}
