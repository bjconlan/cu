#ifndef CU_TLS_H
#define CU_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> /* ssize_t */

/* Workspace sizing macros reference BearSSL types. */
#include <bearssl.h>

/*===========================================================================
 * TLS handler — BearSSL over an already-connected socket fd.
 *
 * Cosmo-centric, s6-tlsc-inspired: takes a connected fd, wraps it in TLS
 * 1.2 (X25519-capable), exposes read/write/close. The fd is borrowed —
 * this library never closes it.
 *
 * Feature parity: u_http_client's verified set. TLS 1.2 only, ECDHE +
 * AES-GCM/ChaCha20 suites, br_ec_all_m31 (P-256/384/521 + X25519), trust
 * anchors (system CA bundle path or $SSL_CERT_FILE — no path probing),
 * hostname validation, insecure opt-out, session resumption, mono-mode
 * record buffer. No TLS 1.3, no ALPN, no server side.
 *
 * Trust anchors: pass a system CA bundle (e.g.
 * /etc/ssl/certs/ca-certificates.crt) as ca_bundle, or rely on
 * $SSL_CERT_FILE. Certs under deps/cu/tls/tests/certs/ are loopback test
 * fixtures, NOT canonical trust stores.
 *
 * WINDOWS: cosmocc exposes no Windows cert-store API (no CryptAPI in the
 * libc/nt headers). Windows has no predictable PEM bundle path, so on
 * Windows the caller MUST supply a bundle via ca_bundle or $SSL_CERT_FILE
 * (e.g. a PEM exported from the Windows cert store). Reading the store
 * directly is deferred; if self-contained cross-platform trust is ever
 * needed, redbean's embedded zipos roots are the cosmo-native pattern to
 * adopt instead.
 *===========================================================================*/

/*--- Error codes --------------------------------------------------------*/

typedef enum {
  CU_TLS_OK = 0,         /* success */
  CU_TLS_ERR_PARAM,      /* null/empty argument */
  CU_TLS_ERR_CONTEXT,    /* tls_context too small / bad config */
  CU_TLS_ERR_ANCHORS,    /* CA bundle missing/unreadable/no anchors */
  CU_TLS_ERR_HANDSHAKE,  /* TLS handshake failed */
  CU_TLS_ERR_VERIFY,     /* certificate/hostname verification failed */
  CU_TLS_ERR_IO,         /* socket read/write error (timeout included) */
  CU_TLS_ERR_CLOSED,     /* engine closed unexpectedly */
  CU_TLS_ERR_UNSUPPORTED /* requested feature not implemented */
} cu_tls_error_t;

/*--- Configuration -------------------------------------------------------*/

/* Caller-owned TLS context sizing. The context holds the BearSSL
 * contexts, the record buffer, and the parsed trust anchors.
 * CU_TLS_CONTEXT(n) sizes it for n root certificates; +64 covers
 * alignment padding when carving the internal layout. */
#define CU_TLS_DER_MAX 4096
#define CU_TLS_MAX_DN 256
#define CU_TLS_MAX_KEY 1024 /* RSA-4096 roots: n(512) + e; covers every mainstream bundle root */
#define CU_TLS_ANCHOR_STRIDE (sizeof(br_x509_trust_anchor) + CU_TLS_MAX_DN + CU_TLS_MAX_KEY)
#define CU_TLS_CONTEXT_MIN                                                                         \
  (sizeof(br_ssl_client_context) + sizeof(br_x509_minimal_context) + BR_SSL_BUFSIZE_MONO +         \
   CU_TLS_DER_MAX + CU_TLS_ANCHOR_STRIDE + 64)
#define CU_TLS_CONTEXT(n) (CU_TLS_CONTEXT_MIN + CU_TLS_ANCHOR_STRIDE * ((n) - 1))

typedef struct {
  const char *ca_bundle; /* path to PEM bundle; NULL → $SSL_CERT_FILE */
  bool insecure;         /* skip cert+hostname validation (never default) */
  /* Caller-owned TLS context memory — REQUIRED. Allocate
   * >= CU_TLS_CONTEXT(n) bytes (n = expected root certs; 128 covers a
   * full system bundle like Debian's 121-root store) and set tls_context
   * + tls_context_cap. One contiguous block, carved internally to hold:
   *   - br_ssl_client_context (engine state)
   *   - br_x509_minimal_context (chain validation)
   *   - record-layer I/O buffer
   *   - DER scratch + the parsed trust anchors (the variable part;
   *     n scales this). If the bundle has more roots than n, connect
   *     fails rather than silently truncating the trust store. */
  void *tls_context;
  size_t tls_context_cap;
  /* Session resumption: caller-owned, optional (NULL = never resume).
   * Set before connect, refreshed after a successful handshake. */
  br_ssl_session_parameters *tls_session;
} cu_tls_config_t;

/*--- Opaque handle -------------------------------------------------------*/

typedef struct cu_tls cu_tls_t;

/*--- Result --------------------------------------------------------------*/

typedef struct {
  cu_tls_error_t error;
  int tls_error; /* raw BearSSL engine code (BR_ERR_*) when error is TLS */
} cu_tls_result_t;

/*--- API ----------------------------------------------------------------*/

/*
 * Wrap an already-connected socket fd in TLS 1.2 and complete the
 * handshake. On success returns a handle (caller frees via cu_tls_close);
 * the fd remains owned by the caller.
 */
cu_tls_t *cu_tls_client_connect(int fd, const char *host, const cu_tls_config_t *config);

/*
 * Connect (getaddrinfo + socket + connect) and wrap in TLS 1.2. The
 * returned handle OWNS the fd — cu_tls_close closes it. This is the
 * convenience mode for callers that don't manage the socket themselves
 * (e.g. the HTTP dep's HTTPS wiring).
 */
cu_tls_t *cu_tls_connect(const char *host, int port, const cu_tls_config_t *config);

/* Read up to len decrypted bytes. Returns bytes read, 0 on clean close,
 * < 0 on error (result.out carries the code). */
ssize_t cu_tls_read(cu_tls_t *tls, void *buf, size_t len, cu_tls_result_t *out);

/* Write len plaintext bytes. Returns bytes written, < 0 on error. */
ssize_t cu_tls_write(cu_tls_t *tls, const void *buf, size_t len, cu_tls_result_t *out);

/* Send close-notify and free the handle. Closes the fd ONLY if the
 * handle was created by cu_tls_connect (fd-owning); for
 * cu_tls_client_connect (borrowed fd) the fd stays open. */
void cu_tls_close(cu_tls_t *tls);

#endif /* CU_TLS_H */
