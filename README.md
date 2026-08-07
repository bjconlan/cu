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

## Sans-IO model

Both components follow the **engine + pump** design (the BearSSL model):
the protocol logic is a pure state machine with **zero I/O**, and a thin
*driver* bridges it to a transport.

- **TLS:** the BearSSL engine is the state machine; `cu_tls_read`/`write`
  (and `cu_tls_connect`'s handshake) are the pump.
- **HTTP:** `cu_http_parser_t` is the state machine; `cu_http_fetch` is a
  convenience driver over the internal `http_pump`.

The HTTP parser is fully sans-IO — you can feed it any byte sequence (a
socket, TLS, captured test bytes) and pull events:

```c
cu_http_parser_t p;
cu_http_parser_init(&p, CU_HTTP_RESPONSE);    /* or CU_HTTP_REQUEST */
cu_http_parser_feed(&p, bytes, n);             /* hand it bytes */
cu_http_event_t ev;
while ((ev = cu_http_parser_next(&p)) != CU_HTTP_EV_DONE) {
  switch (ev) {
  case CU_HTTP_EV_HEADERS:   /* status + headers available */
    cu_http_parser_status(&p);
    cu_http_parser_headers(&p, hdrs, cap);     /* k/v array */
    break;
  case CU_HTTP_EV_BODY:      /* one body chunk (slice) */
    cu_http_parser_body(&p, &len);
    break;
  case CU_HTTP_EV_NEED_MORE: /* feed more bytes, then retry */
    break;
  case CU_HTTP_EV_ERROR:     /* malformed input */
    break;
  }
}
cu_http_parser_destroy(&p);
```

Events: `HEADERS` (once), `BODY` (per decoded chunk — framing-aware:
content-length count-down, chunked via `Unchunk`, unframed pass-through),
`DONE` (response complete, connection reusable via `reset()`), `NEED_MORE`
(no progress without input), `ERROR`. Body slices point into parser
storage, valid until the next feed.

For the common buffer-the-body case, `cu_http_fetch` drives the parser to
`DONE` and returns the existing `cu_http_response_t`:

```c
cu_http_response_t *r = cu_http_fetch(&tr, &req, NULL, 0);
```

`cu_http_request_t.keep_alive` (default false) sends `Connection: close`;
set true to hold the connection open (streaming/SSE).

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

## License

MIT — see [LICENSE](LICENSE).
