#include "cu/tls.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*===========================================================================
 * TLS handler — BearSSL over an already-connected socket fd.
 *
 * Ported from u_http_client's verified TLS path (TLS 1.2 + X25519).
 * Caller-owned context: engine state, record buffer, trust anchors.
 * The fd is borrowed — this library never closes it.
 *===========================================================================*/

struct cu_tls {
  int fd;
  int owns_fd; /* cu_tls_close closes fd when set */
  const char *host;
  br_ssl_client_context *cc;
  uint8_t *ws;
  size_t wcap;
};

/* Trust-anchor storage: contiguous br_x509_trust_anchor array plus
 * per-anchor backing memory for the DER-encoded DN and public-key blob. */
typedef struct cu_tls_anchor_mem {
  uint8_t dn[CU_TLS_MAX_DN];
  uint8_t key[CU_TLS_MAX_KEY];
} cu_tls_anchor_mem;

static size_t cu_tls_align(size_t off, size_t align) {
  return (off + align - 1) & ~(align - 1);
}

/* PEM destination: collects decoded DER bytes into der[]. An overflow
 * marks len = cap + 1 so the decode is skipped. */
typedef struct cu_tls_der {
  uint8_t *buf;
  size_t cap;
  size_t len;
} cu_tls_der;

static void cu_tls_der_append(void *ctx, const void *data, size_t len) {
  cu_tls_der *d = (cu_tls_der *)ctx;
  if (d->len > d->cap)
    return; /* already marked overflow */
  if (d->len + len > d->cap) {
    d->len = d->cap + 1;
  } else {
    memcpy(d->buf + d->len, data, len);
    d->len += len;
  }
}

/* X.509 subject-DN appender. */
typedef struct cu_tls_dn {
  uint8_t *buf;
  size_t cap;
  size_t len;
} cu_tls_dn;

static void cu_tls_dn_append(void *ctx, const void *data, size_t len) {
  cu_tls_dn *d = (cu_tls_dn *)ctx;
  if (d->len + len <= d->cap) {
    memcpy(d->buf + d->len, data, len);
    d->len += len;
  }
}

/* Decode one DER certificate into a trust anchor. Returns 0 on success,
 * -1 when the certificate cannot be decoded or uses an unsupported key
 * (the caller skips it). */
static int cu_tls_decode_anchor(br_x509_trust_anchor *ta, cu_tls_anchor_mem *m, const uint8_t *der,
                                size_t derlen) {
  br_x509_decoder_context dc;
  const br_x509_pkey *pk;
  cu_tls_dn dn = {m->dn, CU_TLS_MAX_DN, 0};

  br_x509_decoder_init(&dc, cu_tls_dn_append, &dn);
  br_x509_decoder_push(&dc, der, derlen);
  pk = br_x509_decoder_get_pkey(&dc);
  if (pk == NULL || dn.len == 0)
    return -1;
  ta->dn.data = m->dn;
  ta->dn.len = dn.len;
  ta->flags = br_x509_decoder_isCA(&dc) ? BR_X509_TA_CA : 0;
  switch (pk->key_type) {
  case BR_KEYTYPE_RSA:
    if (pk->key.rsa.nlen + pk->key.rsa.elen > CU_TLS_MAX_KEY)
      return -1;
    memcpy(m->key, pk->key.rsa.n, pk->key.rsa.nlen);
    memcpy(m->key + pk->key.rsa.nlen, pk->key.rsa.e, pk->key.rsa.elen);
    ta->pkey.key_type = BR_KEYTYPE_RSA;
    ta->pkey.key.rsa.n = m->key;
    ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
    ta->pkey.key.rsa.e = m->key + pk->key.rsa.nlen;
    ta->pkey.key.rsa.elen = pk->key.rsa.elen;
    return 0;
  case BR_KEYTYPE_EC:
    if (pk->key.ec.qlen > CU_TLS_MAX_KEY)
      return -1;
    memcpy(m->key, pk->key.ec.q, pk->key.ec.qlen);
    ta->pkey.key_type = BR_KEYTYPE_EC;
    ta->pkey.key.ec.curve = pk->key.ec.curve;
    ta->pkey.key.ec.q = m->key;
    ta->pkey.key.ec.qlen = pk->key.ec.qlen;
    return 0;
  default:
    return -1;
  }
}

/* Stream a PEM bundle (one or more CERTIFICATE objects) into anchors[].
 * Returns the number of decoded anchors, -1 on file/PEM error, or -2 if
 * the bundle has more certificates than max_anchors can hold (the trust
 * store would be silently truncated — a config error). Undecodable
 * certificates are skipped. */
static int cu_tls_load_bundle(const char *path, br_x509_trust_anchor *anchors,
                              cu_tls_anchor_mem *amem, size_t max_anchors, uint8_t *der,
                              size_t der_cap) {
  FILE *f = fopen(path, "rb");
  br_pem_decoder_context pc;
  cu_tls_der dst = {der, der_cap, 0};
  uint8_t chunk[1024];
  size_t num = 0;
  int inobj = 0;
  int overflow = 0;

  if (f == NULL)
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
        if (strcmp(br_pem_decoder_name(&pc), "CERTIFICATE") == 0) {
          dst.len = 0;
          br_pem_decoder_setdest(&pc, cu_tls_der_append, &dst);
          inobj = 1;
        }
        break;
      case BR_PEM_END_OBJ:
        if (inobj && dst.len <= dst.cap) {
          if (num >= max_anchors) {
            overflow = 1;
          } else if (cu_tls_decode_anchor(&anchors[num], &amem[num], der, dst.len) == 0) {
            num++;
          }
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
  return overflow ? -2 : (int)num;
}

/* Accept-all X.509 class for the explicit insecure mode: validates nothing
 * but extracts the EE certificate's public key (the engine needs it for the
 * key exchange). Shares the context area with br_x509_minimal_context —
 * only one is used per request. */
typedef struct cu_tls_x509_accept {
  const br_x509_class *vtable;
  br_x509_decoder_context dc;
  br_x509_pkey pkey;
  uint8_t keyblob[CU_TLS_MAX_KEY];
  unsigned have_pkey;
} cu_tls_x509_accept;

_Static_assert(sizeof(cu_tls_x509_accept) <= sizeof(br_x509_minimal_context) &&
                   _Alignof(cu_tls_x509_accept) <= _Alignof(br_x509_minimal_context),
               "accept-all context must fit the x509 context area");

static void cu_tls_accept_dn(void *ctx, const void *data, size_t len) {
  (void)ctx;
  (void)data;
  (void)len;
}

static void cu_tls_accept_start_chain(const br_x509_class **ctx, const char *server_name) {
  cu_tls_x509_accept *a = (cu_tls_x509_accept *)(void *)ctx;
  (void)server_name;
  a->have_pkey = 0;
}

static void cu_tls_accept_start_cert(const br_x509_class **ctx, uint32_t length) {
  cu_tls_x509_accept *a = (cu_tls_x509_accept *)(void *)ctx;
  (void)length;
  br_x509_decoder_init(&a->dc, cu_tls_accept_dn, NULL);
}

static void cu_tls_accept_append(const br_x509_class **ctx, const unsigned char *data, size_t len) {
  cu_tls_x509_accept *a = (cu_tls_x509_accept *)(void *)ctx;
  br_x509_decoder_push(&a->dc, data, len);
}

static void cu_tls_accept_end_cert(const br_x509_class **ctx) {
  cu_tls_x509_accept *a = (cu_tls_x509_accept *)(void *)ctx;
  const br_x509_pkey *pk;

  /* TLS sends the chain leaf-first (RFC 5246 7.4.2); keep the FIRST
   * cert's key (the end-entity) and ignore the rest. */
  if (a->have_pkey)
    return;
  pk = br_x509_decoder_get_pkey(&a->dc);
  if (pk == NULL)
    return;
  switch (pk->key_type) {
  case BR_KEYTYPE_RSA:
    if (pk->key.rsa.nlen + pk->key.rsa.elen > CU_TLS_MAX_KEY)
      return;
    memcpy(a->keyblob, pk->key.rsa.n, pk->key.rsa.nlen);
    memcpy(a->keyblob + pk->key.rsa.nlen, pk->key.rsa.e, pk->key.rsa.elen);
    a->pkey.key_type = BR_KEYTYPE_RSA;
    a->pkey.key.rsa.n = a->keyblob;
    a->pkey.key.rsa.nlen = pk->key.rsa.nlen;
    a->pkey.key.rsa.e = a->keyblob + pk->key.rsa.nlen;
    a->pkey.key.rsa.elen = pk->key.rsa.elen;
    break;
  case BR_KEYTYPE_EC:
    if (pk->key.ec.qlen > CU_TLS_MAX_KEY)
      return;
    memcpy(a->keyblob, pk->key.ec.q, pk->key.ec.qlen);
    a->pkey.key_type = BR_KEYTYPE_EC;
    a->pkey.key.ec.curve = pk->key.ec.curve;
    a->pkey.key.ec.q = a->keyblob;
    a->pkey.key.ec.qlen = pk->key.ec.qlen;
    break;
  default:
    return;
  }
  a->have_pkey = 1;
}

static unsigned cu_tls_accept_end_chain(const br_x509_class **ctx) {
  (void)ctx;
  return 0;
}

static const br_x509_pkey *cu_tls_accept_get_pkey(const br_x509_class *const *ctx,
                                                  unsigned *usages) {
  cu_tls_x509_accept *a = (cu_tls_x509_accept *)(void *)ctx;
  if (usages != NULL)
    *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
  return a->have_pkey ? &a->pkey : NULL;
}

static const br_x509_class cu_tls_accept_vtable = {
    sizeof(cu_tls_x509_accept), cu_tls_accept_start_chain, cu_tls_accept_start_cert,
    cu_tls_accept_append,       cu_tls_accept_end_cert,    cu_tls_accept_end_chain,
    cu_tls_accept_get_pkey,
};

/* Client suites: ECDHE + AEAD only (AES-128-GCM, ChaCha20-Poly1305). No
 * RSA key exchange, no CBC/CCM/3DES — keeps the record layer to GCM +
 * ChaCha20 and avoids the RSA private-key path entirely. */
static const uint16_t cu_tls_suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

/* Engine record-layer pump: drives record I/O until the engine reaches
 * 'want' or closes. Isolated here so a poll-driven driver can replace it
 * later (br_ssl_engine_current_state maps SENDREC/RECVREC to
 * POLLOUT/POLLIN). */
typedef enum cu_tls_io {
  CU_TLS_IO_WANT = 0, /* 'want' state reached */
  CU_TLS_IO_CLOSED,   /* engine closed; check br_ssl_engine_last_error */
  CU_TLS_IO_EOF,      /* transport EOF; engine failed with BR_ERR_IO */
  CU_TLS_IO_SOCK      /* socket send/recv error (timeout included) */
} cu_tls_io;

static cu_tls_io cu_tls_pump(br_ssl_engine_context *eng, int fd, unsigned want) {
  for (;;) {
    unsigned st = br_ssl_engine_current_state(eng);
    if (st & BR_SSL_CLOSED)
      return CU_TLS_IO_CLOSED;
    if (st & want)
      return CU_TLS_IO_WANT;
    if (st & BR_SSL_SENDREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_sendrec_buf(eng, &len);
      ssize_t n = send(fd, buf, len, 0);
      if (n <= 0)
        return CU_TLS_IO_SOCK;
      br_ssl_engine_sendrec_ack(eng, (size_t)n);
    } else if (st & BR_SSL_RECVREC) {
      size_t len;
      unsigned char *buf = br_ssl_engine_recvrec_buf(eng, &len);
      ssize_t n = recv(fd, buf, len, 0);
      if (n == 0)
        return CU_TLS_IO_EOF;
      if (n < 0)
        return CU_TLS_IO_SOCK;
      br_ssl_engine_recvrec_ack(eng, (size_t)n);
    } else {
      return CU_TLS_IO_SOCK; /* no record progress possible */
    }
  }
}

/* Curated minimal client profile: TLS 1.2, ECDHE + AEAD only, one EC
 * implementation (all NIST curves + X25519 via m31), SHA-1/256/384,
 * portable constant-time record code. Avoids br_ssl_client_init_full,
 * which links multiple implementations of everything. */
static void cu_tls_client_setup(br_ssl_client_context *cc, br_x509_minimal_context *xc,
                                cu_tls_x509_accept *axc, const br_x509_trust_anchor *anchors,
                                size_t num_anchors, int insecure) {
  br_ssl_client_zero(cc);
  br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);
  br_ssl_engine_set_suites(&cc->eng, cu_tls_suites,
                           (sizeof cu_tls_suites) / (sizeof cu_tls_suites[0]));
  br_ssl_engine_set_ec(&cc->eng, &br_ec_all_m31);
  br_ssl_engine_set_rsavrfy(&cc->eng, &br_rsa_i31_pkcs1_vrfy);
  br_ssl_engine_set_ecdsa(&cc->eng, &br_ecdsa_i31_vrfy_asn1);
  /* record protection: AES-GCM (ct64) and ChaCha20-Poly1305 (ct) */
  br_ssl_engine_set_gcm(&cc->eng, &br_sslrec_in_gcm_vtable, &br_sslrec_out_gcm_vtable);
  br_ssl_engine_set_aes_ctr(&cc->eng, &br_aes_ct64_ctr_vtable);
  br_ssl_engine_set_ghash(&cc->eng, br_ghash_ctmul64);
  br_ssl_engine_set_chapol(&cc->eng, &br_sslrec_in_chapol_vtable, &br_sslrec_out_chapol_vtable);
  br_ssl_engine_set_chacha20(&cc->eng, br_chacha20_ct_run);
  br_ssl_engine_set_poly1305(&cc->eng, br_poly1305_ctmul_run);
  /* hashes: SHA-1 (legacy cert signatures), SHA-256/384 (TLS 1.2 PRF) */
  br_ssl_engine_set_hash(&cc->eng, br_sha1_ID, &br_sha1_vtable);
  br_ssl_engine_set_hash(&cc->eng, br_sha256_ID, &br_sha256_vtable);
  br_ssl_engine_set_hash(&cc->eng, br_sha384_ID, &br_sha384_vtable);
  br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
  br_ssl_engine_set_prf_sha384(&cc->eng, &br_tls12_sha384_prf);
  if (insecure) {
    axc->vtable = &cu_tls_accept_vtable;
    br_ssl_engine_set_x509(&cc->eng, &axc->vtable);
  } else {
    br_x509_minimal_init(xc, &br_sha256_vtable, anchors, num_anchors);
    br_x509_minimal_set_rsa(xc, &br_rsa_i31_pkcs1_vrfy);
    br_x509_minimal_set_ecdsa(xc, &br_ec_all_m31, &br_ecdsa_i31_vrfy_asn1);
    br_x509_minimal_set_hash(xc, br_sha1_ID, &br_sha1_vtable);
    br_x509_minimal_set_hash(xc, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(xc, br_sha384_ID, &br_sha384_vtable);
    br_ssl_engine_set_x509(&cc->eng, &xc->vtable);
  }
}

cu_tls_t *cu_tls_client_connect(int fd, const char *host, const cu_tls_config_t *config) {
  br_ssl_client_context *cc;
  br_x509_minimal_context *xc;
  cu_tls_x509_accept *axc;
  uint8_t *ws, *iobuf, *der;
  br_x509_trust_anchor *anchors;
  cu_tls_anchor_mem *amem;
  size_t wcap, max_anchors, num_anchors = 0, off;
  cu_tls_io io;
  cu_tls_t *tls;

  if (config == NULL || config->tls_context == NULL || host == NULL || !host[0])
    return NULL;

  ws = (uint8_t *)config->tls_context;
  wcap = config->tls_context_cap;

  /* Carve the caller's context: engine state, record buffer, one DER
   * buffer, then the anchor array + backing blobs fill the remainder. The
   * accept-all context aliases the x509-minimal area (only one is used). */
  if (wcap < CU_TLS_CONTEXT_MIN)
    return NULL;
  off = cu_tls_align(0, _Alignof(br_ssl_client_context));
  cc = (br_ssl_client_context *)(ws + off);
  off += sizeof(*cc);
  off = cu_tls_align(off, _Alignof(br_x509_minimal_context));
  xc = (br_x509_minimal_context *)(ws + off);
  axc = (cu_tls_x509_accept *)(void *)xc; /* shares the x509 area */
  off += sizeof(*xc);
  off = cu_tls_align(off, 8);
  iobuf = ws + off;
  off += BR_SSL_BUFSIZE_MONO;
  off = cu_tls_align(off, 8);
  der = ws + off;
  off += CU_TLS_DER_MAX;
  off = cu_tls_align(off, _Alignof(br_x509_trust_anchor));
  anchors = (br_x509_trust_anchor *)(ws + off);
  max_anchors = (wcap - off) / (sizeof(br_x509_trust_anchor) + sizeof(cu_tls_anchor_mem));
  if (max_anchors == 0)
    return NULL;
  off += max_anchors * sizeof(br_x509_trust_anchor);
  off = cu_tls_align(off, _Alignof(cu_tls_anchor_mem));
  amem = (cu_tls_anchor_mem *)(ws + off);

  if (!config->insecure) {
    const char *bundle = config->ca_bundle;
    int n;
    if (bundle == NULL)
      bundle = getenv("SSL_CERT_FILE");
    if (bundle == NULL)
      return NULL;
    n = cu_tls_load_bundle(bundle, anchors, amem, max_anchors, der, CU_TLS_DER_MAX);
    if (n <= 0)
      return NULL;
    num_anchors = (size_t)n;
  }

  cu_tls_client_setup(cc, xc, axc, anchors, num_anchors, config->insecure);
  br_ssl_engine_set_buffer(&cc->eng, iobuf, BR_SSL_BUFSIZE_MONO, 0);

  if (config->tls_session != NULL)
    br_ssl_engine_set_session_parameters(&cc->eng, config->tls_session);
  if (br_ssl_client_reset(cc, host, config->tls_session != NULL) == 0)
    return NULL;

  io = cu_tls_pump(&cc->eng, fd, BR_SSL_SENDAPP);
  if (io != CU_TLS_IO_WANT)
    return NULL;

  if (config->tls_session != NULL)
    br_ssl_engine_get_session_parameters(&cc->eng, config->tls_session);

  tls = (cu_tls_t *)calloc(1, sizeof *tls);
  if (tls == NULL)
    return NULL;
  tls->fd = fd;
  tls->host = host;
  tls->cc = cc;
  tls->ws = ws;
  tls->wcap = wcap;
  return tls;
}

cu_tls_t *cu_tls_connect(const char *host, int port, const cu_tls_config_t *config) {
  struct addrinfo hints, *res = NULL, *ai;
  char portstr[16];
  int fd = -1;
  cu_tls_t *tls;

  if (host == NULL || !host[0] || config == NULL)
    return NULL;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  snprintf(portstr, sizeof portstr, "%d", port);
  if (getaddrinfo(host, portstr, &hints, &res) != 0)
    return NULL;
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
  if (fd < 0)
    return NULL;

  tls = cu_tls_client_connect(fd, host, config);
  if (tls == NULL) {
    close(fd);
    return NULL;
  }
  tls->owns_fd = 1;
  return tls;
}

ssize_t cu_tls_read(cu_tls_t *tls, void *buf, size_t len, cu_tls_result_t *out) {
  cu_tls_io io;
  br_ssl_engine_context *eng;

  if (out)
    out->error = CU_TLS_OK;
  if (tls == NULL || buf == NULL || len == 0) {
    if (out)
      out->error = CU_TLS_ERR_PARAM;
    return -1;
  }
  eng = &tls->cc->eng;

  for (;;) {
    io = cu_tls_pump(eng, tls->fd, BR_SSL_RECVAPP);
    if (io == CU_TLS_IO_WANT) {
      size_t avail;
      unsigned char *rp = br_ssl_engine_recvapp_buf(eng, &avail);
      size_t n;
      if (rp == NULL || avail == 0) {
        if (out)
          out->error = CU_TLS_ERR_CLOSED;
        return -1;
      }
      n = len < avail ? len : avail;
      memcpy(buf, rp, n);
      br_ssl_engine_recvapp_ack(eng, n);
      return (ssize_t)n;
    }
    if (io == CU_TLS_IO_CLOSED || io == CU_TLS_IO_EOF) {
      int last = br_ssl_engine_last_error(eng);
      if (last == BR_ERR_OK || io == CU_TLS_IO_EOF) {
        return 0; /* clean close */
      }
      if (out) {
        out->error = CU_TLS_ERR_CLOSED;
        out->tls_error = last;
      }
      return -1;
    }
    if (out) {
      out->error = CU_TLS_ERR_IO;
      out->tls_error = br_ssl_engine_last_error(eng);
    }
    return -1;
  }
}

ssize_t cu_tls_write(cu_tls_t *tls, const void *buf, size_t len, cu_tls_result_t *out) {
  cu_tls_io io;
  br_ssl_engine_context *eng;

  if (out)
    out->error = CU_TLS_OK;
  if (tls == NULL || buf == NULL || len == 0) {
    if (out)
      out->error = CU_TLS_ERR_PARAM;
    return -1;
  }
  eng = &tls->cc->eng;

  /* write up to one sendapp chunk */
  {
    size_t cap;
    unsigned char *ap = br_ssl_engine_sendapp_buf(eng, &cap);
    size_t n;
    if (ap == NULL || cap == 0) {
      /* engine wants to flush first */
      io = cu_tls_pump(eng, tls->fd, BR_SSL_SENDAPP);
      if (io != CU_TLS_IO_WANT) {
        if (out) {
          out->error = CU_TLS_ERR_IO;
          out->tls_error = br_ssl_engine_last_error(eng);
        }
        return -1;
      }
      ap = br_ssl_engine_sendapp_buf(eng, &cap);
      if (ap == NULL || cap == 0) {
        if (out)
          out->error = CU_TLS_ERR_CLOSED;
        return -1;
      }
    }
    n = len < cap ? len : cap;
    memcpy(ap, buf, n);
    br_ssl_engine_sendapp_ack(eng, n);
    br_ssl_engine_flush(eng, 0);
    return (ssize_t)n;
  }
}

void cu_tls_close(cu_tls_t *tls) {
  if (tls == NULL)
    return;
  br_ssl_engine_close(&tls->cc->eng);
  /* best-effort close-notify flush; close the fd only if we own it */
  (void)cu_tls_pump(&tls->cc->eng, tls->fd, BR_SSL_CLOSED);
  if (tls->owns_fd)
    close(tls->fd);
  free(tls);
}
