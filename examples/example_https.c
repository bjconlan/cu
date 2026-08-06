/*
 * cu HTTP + TLS usage example: GET https://example.com/
 *
 * Shows the two-layer composition explicitly:
 *   1. cu_tls_connect  — owns the fd, TLS 1.2 handshake
 *   2. cu_http_fetch   — HTTP over the TLS transport (HTTPS)
 *
 * Build:
 *   cosmocc -Ideps/cu/tls/include -Ideps/cu/http_client/include \
 *           -Ideps/bearssl/inc -o example example.c \
 *           deps/cu/tls/src/tls.c deps/cu/http_client/src/http_client.c \
 *           build/bearssl-objects -static
 *   (build/bearssl-objects = all BearSSL .o files from build/bearssl)
 */
#define _POSIX_C_SOURCE 200809L
#include "cu/http_client.h"
#include "cu/tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t ws[CU_TLS_CONTEXT(128)];

/* TLS transport adapter: cu_tls_* as the transport read/write fns. */
static ssize_t tls_read(void *ctx, void *buf, size_t len) {
  cu_tls_result_t out;
  memset(&out, 0, sizeof out);
  return cu_tls_read((cu_tls_t *)ctx, buf, len, &out);
}
static ssize_t tls_write(void *ctx, const void *buf, size_t len) {
  cu_tls_result_t out;
  memset(&out, 0, sizeof out);
  return cu_tls_write((cu_tls_t *)ctx, buf, len, &out);
}

int main(void) {
  const char *host = "example.com";
  cu_tls_config_t tls_cfg;
  cu_tls_t *tls;
  cu_http_transport_t tr;
  cu_http_request_t req;
  cu_http_header_t rhdrs[16];
  cu_http_response_t *r;

  /* 1. TLS: connect + handshake (owns the fd; close via cu_tls_close) */
  memset(&tls_cfg, 0, sizeof tls_cfg);
  tls_cfg.ca_bundle = "/etc/ssl/certs/ca-certificates.crt"; /* or $SSL_CERT_FILE */
  tls_cfg.tls_context = ws;
  tls_cfg.tls_context_cap = sizeof ws;

  tls = cu_tls_connect(host, 443, &tls_cfg);
  if (!tls) {
    fprintf(stderr, "TLS connect/handshake failed\n");
    return 1;
  }

  /* 2. HTTP: transport = TLS handle */
  tr.read = tls_read;
  tr.write = tls_write;
  tr.ctx = tls;

  memset(&req, 0, sizeof req);
  req.method = "GET";
  req.path = "/";
  req.host = host;

  r = cu_http_fetch(&tr, &req, rhdrs, 16);
  if (!r) {
    fprintf(stderr, "fetch failed\n");
    cu_tls_close(tls);
    return 1;
  }

  printf("status: %d\n", r->status_code);
  printf("headers (%zu):\n", r->num_headers);
  for (size_t i = 0; i < r->num_headers; i++)
    printf("  %s: %s\n", r->headers[i].k, r->headers[i].v);
  printf("body (%zu bytes):\n%.*s\n", r->body_len, (int)(r->body_len > 300 ? 300 : r->body_len),
         r->body);

  cu_http_response_free(r);
  cu_tls_close(tls); /* closes the fd (fd-owning mode) */
  return 0;
}
