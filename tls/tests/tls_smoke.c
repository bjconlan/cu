/*
 * TLS smoke test: real handshake against api.deepseek.com using the
 * SYSTEM trust store. Not part of `make test` (requires network) — run
 * manually:  make deps/cu/tls/tests/tls_smoke && ./deps/cu/tls/tests/tls_smoke
 *
 * Demonstrates the production trust-anchor path: no ca_bundle given, so
 * the dep resolves $SSL_CERT_FILE (or the caller passes the system bundle
 * path explicitly, e.g. /etc/ssl/certs/ca-certificates.crt).
 */
#define _POSIX_C_SOURCE 200809L
#include "cu/tls.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  static uint8_t ws[CU_TLS_CONTEXT(32)];
  const char *host = "api.deepseek.com";
  const char *ca_bundle = argc > 1 ? argv[1] : "/etc/ssl/certs/ca-certificates.crt";
  cu_tls_config_t cfg;
  cu_tls_t *tls;
  cu_tls_result_t out;
  char resp[8192];
  size_t total = 0;
  int fd;

  /* resolve + connect (getaddrinfo, cosmo/BSD style) */
  {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "443");
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
      fprintf(stderr, "dns: %s\n", host);
      return 1;
    }
    fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
      fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (fd < 0)
        continue;
      if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
        break;
      close(fd);
      fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
      fprintf(stderr, "connect failed\n");
      return 1;
    }
  }

  memset(&cfg, 0, sizeof cfg);
  cfg.ca_bundle = ca_bundle;
  cfg.tls_context = ws;
  cfg.tls_context_cap = sizeof ws;

  printf("handshake %s (ca=%s) ...\n", host, ca_bundle);
  tls = cu_tls_client_connect(fd, host, &cfg);
  if (!tls) {
    fprintf(stderr, "TLS handshake FAILED\n");
    close(fd);
    return 1;
  }
  printf("handshake OK\n");

  /* send GET /models */
  {
    const char *req = "GET /models HTTP/1.1\r\n"
                      "Host: api.deepseek.com\r\n"
                      "Accept: application/json\r\n"
                      "Connection: close\r\n\r\n";
    const char *p = req;
    size_t left = strlen(req);
    while (left > 0) {
      ssize_t n = cu_tls_write(tls, p, left, &out);
      if (n <= 0) {
        fprintf(stderr, "write failed (%d)\n", (int)out.error);
        return 1;
      }
      p += n;
      left -= (size_t)n;
    }
  }

  /* read the response */
  for (;;) {
    ssize_t n = cu_tls_read(tls, resp + total, sizeof resp - total, &out);
    if (n == 0)
      break; /* clean close */
    if (n < 0) {
      fprintf(stderr, "read failed (%d, tls=%d)\n", (int)out.error, out.tls_error);
      return 1;
    }
    total += (size_t)n;
  }
  resp[total < sizeof resp ? total : sizeof resp - 1] = 0;

  printf("--- response (%zu bytes) ---\n%.*s\n", total, (int)(total > 512 ? 512 : total), resp);

  /* check status line */
  if (strncmp(resp, "HTTP/1.1 200", 12) == 0 || strncmp(resp, "HTTP/1.1 401", 12) == 0) {
    printf("SMOKE PASS (server responded, TLS verified against system CA)\n");
    cu_tls_close(tls);
    close(fd);
    return 0;
  }
  fprintf(stderr, "SMOKE FAIL: unexpected status\n");
  cu_tls_close(tls);
  close(fd);
  return 1;
}
