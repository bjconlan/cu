# cu — Cosmo Utilities

Reusable cosmopolitan wire-layer components, built with cosmocc.

- **`tls/`** — `cu/tls.h`: BearSSL TLS 1.2 client (X25519-capable) over a
  connected fd. Two modes: `cu_tls_client_connect(fd, host, cfg)` (borrowed
  fd) and `cu_tls_connect(host, port, cfg)` (owns the fd). Caller-owned
  context (`CU_TLS_CONTEXT(n)`), system CA bundle trust anchors, session
  resumption, poll-composable engine.
- **`http_client/`** — `cu/http_client.h`: HTTP/1.1 codec over a generic
  read/write transport (zero TLS knowledge — HTTPS is HTTP through a TLS
  transport). Cosmo parsing (`ParseHttpMessage`/`Unchunk`/`GetHttpHeader`),
  exact framing (keep-alive), caller-owned k/v header arrays.

BearSSL is a pinned git submodule at `third_party/bearssl` (`7bea48e5`).

## Build

```sh
git submodule update --init   # fetch third_party/bearssl
make lib                      # build/libcu.a
make test                     # cu-test (tls + http_client suites)
```

## Example

`examples/example_https.c` — `GET https://example.com/` wired through both
layers explicitly:

```c
cu_tls_t *tls = cu_tls_connect("example.com", 443, &tls_cfg);
cu_http_transport_t tr = { tls_read, tls_write, tls };
cu_http_response_t *r = cu_http_fetch(&tr, &req, NULL, 0);
```

See the file header for the full build command.
