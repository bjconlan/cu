/*
 * TLS loopback tests for the acp/tls dep: a fork-based BearSSL TLS server
 * on 127.0.0.1 serves one connection; the client is cu_tls_client_connect
 * + cu_tls_read. No network, no OpenSSL at test time — the server is
 * built from the same pinned BearSSL submodule.
 *
 * Certs in tls/tests/certs/ are LOOPBACK FIXTURES, not canonical
 * trust stores: server.crt/server.key (self-signed, CN=localhost) is what
 * the test server presents; other.crt is a different self-signed CA for
 * wrong-CA tests. Production trust anchors come from the system CA bundle
 * (see acp/tls.h).
 */
#include "cu/tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "bearssl.h"
#include "tests/greatest.h"

#define TLS_CERT "tls/tests/certs/server.crt"
#define TLS_KEY "tls/tests/certs/server.key"
#define TLS_OTHER_CA "tls/tests/certs/other.crt"
#define TLS_RESP                                                                                   \
  "HTTP/1.1 200 OK\r\n"                                                                            \
  "Content-Type: text/plain\r\n"                                                                   \
  "Content-Length: 12\r\n"                                                                         \
  "Connection: close\r\n"                                                                          \
  "\r\n"                                                                                           \
  "hello world!"

static unsigned char g_pem_dst[65536];
static size_t g_pem_len;
static unsigned char g_pem_key[65536];
static size_t g_pem_key_len;

typedef struct pem_dst {
  unsigned char *buf;
  size_t cap;
  size_t len;
} pem_dst_t;

static void pem_append(void *ctx, const void *data, size_t len) {
  pem_dst_t *d = (pem_dst_t *)ctx;
  if (d->len + len <= d->cap) {
    memcpy(d->buf + d->len, data, len);
    d->len += len;
  }
}

/* Read the first PEM object with the given name from a file into dst. */
static int read_pem_obj(const char *path, const char *name, unsigned char *dst, size_t dst_cap,
                        size_t *len_out) {
  FILE *f = fopen(path, "rb");
  br_pem_decoder_context pc;
  pem_dst_t pd = {dst, dst_cap, 0};
  unsigned char chunk[1024];
  int inobj = 0;
  if (!f)
    return -1;
  br_pem_decoder_init(&pc);
  for (;;) {
    size_t r = fread(chunk, 1, sizeof chunk, f);
    size_t off = 0;
    if (r == 0)
      break;
    while (off < r) {
      size_t n = br_pem_decoder_push(&pc, chunk + off, r - off);
      off += n;
      switch (br_pem_decoder_event(&pc)) {
      case BR_PEM_BEGIN_OBJ:
        if (strcmp(br_pem_decoder_name(&pc), name) == 0) {
          pd.len = 0;
          br_pem_decoder_setdest(&pc, pem_append, &pd);
          inobj = 1;
        }
        break;
      case BR_PEM_END_OBJ:
        if (inobj) {
          *len_out = pd.len;
          fclose(f);
          return 0;
        }
        inobj = 0;
        break;
      case BR_PEM_ERROR:
        fclose(f);
        return -1;
      default:
        break;
      }
    }
  }
  fclose(f);
  return -1;
}

/* Bind a listener on 127.0.0.1 with an OS-assigned port. */
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
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 1) != 0 ||
      getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
    close(fd);
    return -1;
  }
  *out_port = ntohs(addr.sin_port);
  return fd;
}

/* Wait for pid with a timeout; kills the child on timeout (no hang). */
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

static int tls_send_all(int fd, const void *buf, size_t len) {
  const char *p = buf;
  while (len > 0) {
    ssize_t n = send(fd, p, len, 0);
    if (n <= 0)
      return -1;
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

/* Drive the server's engine (same state machine the client uses). */
static int server_pump(br_ssl_engine_context *eng, int fd, unsigned want) {
  for (;;) {
    unsigned st = br_ssl_engine_current_state(eng);
    if (st & BR_SSL_CLOSED)
      return -1;
    if (st & want)
      return 0;
    if (st & BR_SSL_SENDREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_sendrec_buf(eng, &len);
      if (tls_send_all(fd, buf, len) < 0)
        return -1;
      br_ssl_engine_sendrec_ack(eng, len);
    } else if (st & BR_SSL_RECVREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_recvrec_buf(eng, &len);
      ssize_t n = recv(fd, buf, len, 0);
      if (n <= 0)
        return -1;
      br_ssl_engine_recvrec_ack(eng, (size_t)n);
    } else {
      return -1;
    }
  }
}

/* Serve one TLS connection: handshake, read the request, reply 200. */
static void tls_child_serve(int listen_fd) {
  int conn = accept(listen_fd, NULL, NULL);
  br_ssl_server_context sc;
  br_x509_certificate chain[1];
  br_skey_decoder_context kd;
  const br_rsa_private_key *sk;
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
  unsigned char reqbuf[4096];
  size_t reqlen = 0;

  if (conn < 0)
    _exit(2);
  if (read_pem_obj(TLS_CERT, "CERTIFICATE", g_pem_dst, sizeof g_pem_dst, &g_pem_len) < 0)
    _exit(2);
  chain[0].data = g_pem_dst;
  chain[0].data_len = g_pem_len;
  /* key may be PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") */
  if (read_pem_obj(TLS_KEY, "RSA PRIVATE KEY", g_pem_key, sizeof g_pem_key, &g_pem_key_len) < 0 &&
      read_pem_obj(TLS_KEY, "PRIVATE KEY", g_pem_key, sizeof g_pem_key, &g_pem_key_len) < 0)
    _exit(2);
  br_skey_decoder_init(&kd);
  br_skey_decoder_push(&kd, g_pem_key, g_pem_key_len);
  sk = br_skey_decoder_get_rsa(&kd);
  if (sk == NULL)
    _exit(2);

  br_ssl_server_init_full_rsa(&sc, chain, 1, sk);
  br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1); /* bidi */
  br_ssl_server_reset(&sc);

  if (server_pump(&sc.eng, conn, BR_SSL_RECVAPP) < 0) {
    close(conn);
    _exit(3);
  }

  /* read the request until the header block is complete */
  for (;;) {
    size_t avail;
    unsigned char *p = br_ssl_engine_recvapp_buf(&sc.eng, &avail);
    size_t n = (sizeof reqbuf - reqlen < avail) ? (sizeof reqbuf - reqlen) : avail;
    memcpy(reqbuf + reqlen, p, n);
    br_ssl_engine_recvapp_ack(&sc.eng, n);
    reqlen += n;
    if (strstr((char *)reqbuf, "\r\n\r\n") != NULL)
      break;
    if (server_pump(&sc.eng, conn, BR_SSL_RECVAPP) < 0)
      break;
  }

  /* send the canned response */
  {
    const char *resp = TLS_RESP;
    size_t left = strlen(resp);
    while (left > 0) {
      size_t cap;
      unsigned char *p = br_ssl_engine_sendapp_buf(&sc.eng, &cap);
      size_t n;
      if (p == NULL)
        break;
      n = left < cap ? left : cap;
      memcpy(p, resp, n);
      br_ssl_engine_sendapp_ack(&sc.eng, n);
      br_ssl_engine_flush(&sc.eng, 0);
      resp += n;
      left -= n;
      if (left > 0 && server_pump(&sc.eng, conn, BR_SSL_SENDAPP) < 0)
        break;
    }
    (void)server_pump(&sc.eng, conn, BR_SSL_SENDAPP);
  }
  close(conn);
  _exit(0);
}

/* Serve two TLS connections with the SAME server context + session cache,
 * so the second handshake can resume the first session (session-ID based). */
static void tls_child_serve_two(int listen_fd) {
  br_ssl_server_context sc;
  br_ssl_session_cache_lru cache;
  unsigned char cache_store[100 * 8];
  br_x509_certificate chain[1];
  br_skey_decoder_context kd;
  const br_rsa_private_key *sk;
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
  int conn_no;

  if (read_pem_obj(TLS_CERT, "CERTIFICATE", g_pem_dst, sizeof g_pem_dst, &g_pem_len) < 0)
    _exit(2);
  chain[0].data = g_pem_dst;
  chain[0].data_len = g_pem_len;
  if (read_pem_obj(TLS_KEY, "RSA PRIVATE KEY", g_pem_key, sizeof g_pem_key, &g_pem_key_len) < 0 &&
      read_pem_obj(TLS_KEY, "PRIVATE KEY", g_pem_key, sizeof g_pem_key, &g_pem_key_len) < 0)
    _exit(2);
  br_skey_decoder_init(&kd);
  br_skey_decoder_push(&kd, g_pem_key, g_pem_key_len);
  sk = br_skey_decoder_get_rsa(&kd);
  if (sk == NULL)
    _exit(2);

  br_ssl_server_init_full_rsa(&sc, chain, 1, sk);
  br_ssl_session_cache_lru_init(&cache, cache_store, sizeof cache_store);
  br_ssl_server_set_cache(&sc, &cache.vtable);
  br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1); /* bidi */

  for (conn_no = 0; conn_no < 2; conn_no++) {
    int conn = accept(listen_fd, NULL, NULL);
    unsigned char reqbuf[4096];
    size_t reqlen = 0;
    const char *resp = TLS_RESP;
    size_t left;

    if (conn < 0)
      _exit(2);
    br_ssl_server_reset(&sc);
    if (server_pump(&sc.eng, conn, BR_SSL_RECVAPP) < 0) {
      close(conn);
      _exit(3);
    }
    for (;;) {
      size_t avail;
      unsigned char *p = br_ssl_engine_recvapp_buf(&sc.eng, &avail);
      size_t n = (sizeof reqbuf - reqlen < avail) ? (sizeof reqbuf - reqlen) : avail;
      memcpy(reqbuf + reqlen, p, n);
      br_ssl_engine_recvapp_ack(&sc.eng, n);
      reqlen += n;
      if (strstr((char *)reqbuf, "\r\n\r\n") != NULL)
        break;
      if (server_pump(&sc.eng, conn, BR_SSL_RECVAPP) < 0)
        break;
    }
    left = strlen(resp);
    while (left > 0) {
      size_t cap;
      unsigned char *p = br_ssl_engine_sendapp_buf(&sc.eng, &cap);
      size_t n = left < cap ? left : cap;
      if (p == NULL)
        break;
      memcpy(p, resp, n);
      br_ssl_engine_sendapp_ack(&sc.eng, n);
      br_ssl_engine_flush(&sc.eng, 0);
      resp += n;
      left -= n;
      if (left > 0 && server_pump(&sc.eng, conn, BR_SSL_SENDAPP) < 0)
        break;
    }
    (void)server_pump(&sc.eng, conn, BR_SSL_SENDAPP);
    close(conn);
  }
  _exit(0);
}

/* Connect the client to the loopback server over TLS and read the
 * response. Returns 0 on success, -1 on any failure. */
static int client_roundtrip(const char *host, const cu_tls_config_t *cfg, char *resp,
                            size_t resp_cap, size_t *resp_len) {
  int port, conn_fd = -1, rc = -1;
  int listen_fd = bind_loopback(&port);
  pid_t pid;
  int status;
  cu_tls_t *tls = NULL;
  cu_tls_result_t out;

  if (listen_fd < 0)
    return -1;
  pid = fork();
  if (pid < 0) {
    close(listen_fd);
    return -1;
  }
  if (pid == 0) {
    tls_child_serve(listen_fd); /* never returns */
  }

  /* client connects its own fd (caller-owned, per the dep contract) */
  {
    struct sockaddr_in addr;
    conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn_fd < 0)
      goto out;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (connect(conn_fd, (struct sockaddr *)&addr, sizeof addr) != 0)
      goto out;
  }

  tls = cu_tls_client_connect(conn_fd, host, cfg);
  if (tls == NULL)
    goto out;

  /* send a request, read the response */
  {
    const char *req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *p = req;
    size_t left = strlen(req);
    size_t total = 0;
    while (left > 0) {
      ssize_t n = cu_tls_write(tls, p, left, &out);
      if (n <= 0)
        goto out;
      p += n;
      left -= (size_t)n;
    }
    for (;;) {
      ssize_t n = cu_tls_read(tls, resp + total, resp_cap - total, &out);
      if (n == 0)
        break; /* clean close */
      if (n < 0)
        goto out;
      total += (size_t)n;
      if (strstr(resp, "\r\n\r\nhello world!") != NULL)
        break;
    }
    *resp_len = total;
  }
  rc = 0;

out:
  cu_tls_close(tls);
  if (conn_fd >= 0)
    close(conn_fd);
  if (wait_child(pid, &status, 5000) != 0)
    rc = -1;
  close(listen_fd);
  if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0))
    rc = -1;
  return rc;
}

TEST test_tls_session_resumption(void) {
  static uint8_t ws[CU_TLS_CONTEXT(1)];
  br_ssl_session_parameters sess;
  unsigned char sid1[32];
  int port, i;
  int listen_fd = bind_loopback(&port);
  pid_t pid;
  int status;

  memset(&sess, 0, sizeof sess);
  ASSERT(listen_fd >= 0);
  pid = fork();
  ASSERT(pid >= 0);
  if (pid == 0) {
    tls_child_serve_two(listen_fd);
  }

  for (i = 0; i < 2; i++) {
    struct sockaddr_in addr;
    int conn_fd;
    cu_tls_config_t cfg = {
        .ca_bundle = TLS_CERT,
        .tls_context = ws,
        .tls_context_cap = sizeof ws,
        .tls_session = &sess,
    };
    cu_tls_t *tls;
    const char *req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *p = req;
    size_t left = strlen(req);
    char resp[8192];
    size_t total = 0;
    cu_tls_result_t out;

    conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(conn_fd >= 0);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    ASSERT(connect(conn_fd, (struct sockaddr *)&addr, sizeof addr) == 0);

    tls = cu_tls_client_connect(conn_fd, "localhost", &cfg);
    ASSERT(tls != NULL);
    if (i == 0) {
      /* first handshake: the server issued a session */
      ASSERT(sess.session_id_len > 0);
      memcpy(sid1, sess.session_id, sizeof sid1);
    }
    while (left > 0) {
      ssize_t n = cu_tls_write(tls, p, left, &out);
      ASSERT(n > 0);
      p += n;
      left -= (size_t)n;
    }
    for (;;) {
      ssize_t n = cu_tls_read(tls, resp + total, sizeof resp - total, &out);
      if (n == 0)
        break;
      ASSERT(n > 0);
      total += (size_t)n;
      if (strstr(resp, "\r\n\r\nhello world!") != NULL)
        break;
    }
    cu_tls_close(tls);
    close(conn_fd);
  }

  ASSERT(wait_child(pid, &status, 5000) == 0);
  close(listen_fd);
  /* a resumed handshake echoes the same session ID; a full handshake
   * would mint a new one */
  ASSERT(memcmp(sess.session_id, sid1, 32) == 0);
  PASS();
}

TEST test_tls_close_notify(void) {
  static uint8_t ws[CU_TLS_CONTEXT(1)];
  char resp[8192];
  size_t resp_len = 0;
  cu_tls_config_t cfg = {
      .ca_bundle = TLS_CERT,
      .tls_context = ws,
      .tls_context_cap = sizeof ws,
  };
  int port;
  int listen_fd = bind_loopback(&port);
  pid_t pid;
  int status;
  struct sockaddr_in addr;
  int conn_fd;
  cu_tls_t *tls;
  cu_tls_result_t out;

  ASSERT(listen_fd >= 0);
  pid = fork();
  ASSERT(pid >= 0);
  if (pid == 0) {
    tls_child_serve(listen_fd);
  }
  conn_fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT(conn_fd >= 0);
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  ASSERT(connect(conn_fd, (struct sockaddr *)&addr, sizeof addr) == 0);

  tls = cu_tls_client_connect(conn_fd, "localhost", &cfg);
  ASSERT(tls != NULL);

  /* send a request, read the response */
  {
    const char *req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *p = req;
    size_t left = strlen(req);
    size_t total = 0;
    while (left > 0) {
      ssize_t n = cu_tls_write(tls, p, left, &out);
      ASSERT(n > 0);
      p += n;
      left -= (size_t)n;
    }
    for (;;) {
      ssize_t n = cu_tls_read(tls, resp + total, sizeof resp - total, &out);
      if (n == 0)
        break;
      ASSERT(n > 0);
      total += (size_t)n;
      if (strstr(resp, "\r\n\r\nhello world!") != NULL)
        break;
    }
    resp_len = total;
  }
  ASSERT(resp_len >= 12);
  ASSERT(memcmp(resp + resp_len - 12, "hello world!", 12) == 0);

  /* close-notify: sends close_notify, must not close the caller's fd */
  cu_tls_close(tls);
  { /* fd must still be open (borrowed, not closed by the dep) */
    int fl;
    errno = 0;
    fl = fcntl(conn_fd, F_GETFD);
    ASSERT(fl != -1 && errno != EBADF);
  }
  close(conn_fd);
  ASSERT(wait_child(pid, &status, 5000) == 0);
  close(listen_fd);
  PASS();
}

TEST test_tls_roundtrip(void) {
  static uint8_t ws[CU_TLS_CONTEXT(1)];
  char resp[8192];
  size_t resp_len = 0;
  cu_tls_config_t cfg = {
      .ca_bundle = TLS_CERT, /* loopback fixture: trust the test server */
      .tls_context = ws,
      .tls_context_cap = sizeof ws,
  };
  ASSERT(client_roundtrip("localhost", &cfg, resp, sizeof resp, &resp_len) == 0);
  ASSERT(resp_len >= 12);
  ASSERT(memcmp(resp + resp_len - 12, "hello world!", 12) == 0);
  PASS();
}

TEST test_tls_wrong_ca(void) {
  static uint8_t ws[CU_TLS_CONTEXT(1)];
  int port;
  int listen_fd = bind_loopback(&port);
  pid_t pid;
  int status;
  struct sockaddr_in addr;
  int conn_fd;
  cu_tls_config_t cfg = {
      .ca_bundle = TLS_OTHER_CA, /* not the server's CA */
      .tls_context = ws,
      .tls_context_cap = sizeof ws,
  };
  cu_tls_t *tls;

  ASSERT(listen_fd >= 0);
  pid = fork();
  ASSERT(pid >= 0);
  if (pid == 0) {
    tls_child_serve(listen_fd);
  }
  conn_fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT(conn_fd >= 0);
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  ASSERT(connect(conn_fd, (struct sockaddr *)&addr, sizeof addr) == 0);

  tls = cu_tls_client_connect(conn_fd, "localhost", &cfg);
  ASSERT(tls == NULL); /* handshake must fail verification */
  close(conn_fd);
  /* the server aborts (non-zero exit) when the client abandons the
   * handshake — no exit-status assertion here, just reap it */
  ASSERT(wait_child(pid, &status, 5000) == 0);
  close(listen_fd);
  PASS();
}

TEST test_tls_hostname_mismatch(void) {
  static uint8_t ws[CU_TLS_CONTEXT(1)];
  int port;
  int listen_fd = bind_loopback(&port);
  pid_t pid;
  int status;
  struct sockaddr_in addr;
  int conn_fd;
  cu_tls_config_t cfg = {
      .ca_bundle = TLS_CERT, /* trusted CA, but wrong name */
      .tls_context = ws,
      .tls_context_cap = sizeof ws,
  };
  cu_tls_t *tls;

  ASSERT(listen_fd >= 0);
  pid = fork();
  ASSERT(pid >= 0);
  if (pid == 0) {
    tls_child_serve(listen_fd);
  }
  conn_fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT(conn_fd >= 0);
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  ASSERT(connect(conn_fd, (struct sockaddr *)&addr, sizeof addr) == 0);

  /* cert is CN=localhost; connecting to the IP fails the name check */
  tls = cu_tls_client_connect(conn_fd, "127.0.0.1", &cfg);
  ASSERT(tls == NULL);
  close(conn_fd);
  ASSERT(wait_child(pid, &status, 5000) == 0);
  close(listen_fd);
  PASS();
}

TEST test_tls_insecure(void) {
  static uint8_t ws[CU_TLS_CONTEXT(1)];
  char resp[8192];
  size_t resp_len = 0;
  cu_tls_config_t cfg = {
      .insecure = true, /* accept-all: no anchors, no name check */
      .tls_context = ws,
      .tls_context_cap = sizeof ws,
  };
  ASSERT(client_roundtrip("127.0.0.1", &cfg, resp, sizeof resp, &resp_len) == 0);
  ASSERT(resp_len >= 12);
  ASSERT(memcmp(resp + resp_len - 12, "hello world!", 12) == 0);
  PASS();
}

TEST test_tls_small_workspace(void) {
  uint8_t ws[CU_TLS_CONTEXT_MIN - 1]; /* one byte short */
  cu_tls_config_t cfg = {
      .insecure = true,
      .tls_context = ws,
      .tls_context_cap = sizeof ws,
  };
  /* must refuse rather than overflow */
  ASSERT(cu_tls_client_connect(-1, "localhost", &cfg) == NULL);
  PASS();
}

TEST test_tls_bad_args(void) {
  static uint8_t ws[CU_TLS_CONTEXT(1)];
  ASSERT(cu_tls_client_connect(-1, NULL, NULL) == NULL);
  ASSERT(cu_tls_client_connect(-1, "localhost", NULL) == NULL);
  ASSERT(cu_tls_client_connect(-1, "",
                               &(cu_tls_config_t){
                                   .tls_context = ws,
                                   .tls_context_cap = sizeof ws,
                               }) == NULL);
  PASS();
}

SUITE(tls_suite) {
  RUN_TEST(test_tls_roundtrip);
  RUN_TEST(test_tls_wrong_ca);
  RUN_TEST(test_tls_hostname_mismatch);
  RUN_TEST(test_tls_insecure);
  RUN_TEST(test_tls_session_resumption);
  RUN_TEST(test_tls_close_notify);
  RUN_TEST(test_tls_small_workspace);
  RUN_TEST(test_tls_bad_args);
}
