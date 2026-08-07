/*
 * SSE streaming example: HTTP parser -> SSE parser pipeline.
 *
 * Shows how the two sans-IO parsers stack: feed the HTTP parser a
 * text/event-stream response, take its BODY events, feed those bytes to
 * the SSE parser, and pull complete events. The same wiring is what an
 * LLM client uses (SSE events -> model deltas), or any streamed
 * event-source consumer.
 *
 * Self-contained: no network — the response bytes are simulated so the
 * example runs anywhere. Swap the simulated bytes for real transport
 * reads (cu_http_fetch_stream / a TLS transport) in production.
 *
 * Build:
 *   cosmocc -Ihttp_client/include -o example_sse example_sse.c \
 *           http_client/src/http_client.c http_client/src/sse.c -static
 */
#define _POSIX_C_SOURCE 200809L
#include "cu/http_client.h"
#include "cu/sse.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  /* A simulated text/event-stream HTTP response: headers, then SSE
   * events. Content-Length frames the body so the parser reaches DONE
   * without needing EOF. In production these bytes come from a transport
   * read (chunked/unframed bodies work the same — the parser handles the
   * framing). */
  static const char body[] =
      "data: {\"role\":\"assistant\",\"content\":\"Hel\"}\n"
      "\n"
      "data: {\"content\":\"lo!\"}\n"
      "event: done\n"
      "data: [DONE]\n"
      "\n";
  char response[512];
  int hlen = snprintf(response, sizeof response,
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/event-stream\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n",
                      sizeof body - 1);
  memcpy(response + hlen, body, sizeof body - 1);
  response[hlen + sizeof body - 1] = 0;

  cu_http_parser_t hp;
  cu_sse_parser_t sp;
  int done = 0;
  int guard = 0;

  cu_http_parser_init(&hp, CU_HTTP_RESPONSE);
  cu_sse_parser_init(&sp);

  /* Feed the whole response to the HTTP parser, then drain events. In a
   * real consumer this loop interleaves transport reads (NEED_MORE). */
  cu_http_parser_feed(&hp, response, strlen(response));

  while (!done && guard++ < 32) {
    cu_http_event_t ev = cu_http_parser_next(&hp);
    switch (ev) {
    case CU_HTTP_EV_HEADERS:
      printf("HTTP status: %d\n", cu_http_parser_status(&hp));
      break;
    case CU_HTTP_EV_BODY: {
      size_t blen;
      const char *chunk = cu_http_parser_body(&hp, &blen);
      /* feed the body bytes to the SSE parser */
      cu_sse_parser_feed(&sp, chunk, blen);
      while (cu_sse_parser_next(&sp)) {
        cu_sse_event_t e;
        cu_sse_parser_event(&sp, &e);
        printf("SSE event: data=[%.*s] name=[%s]\n", (int)e.data_len, e.data,
               e.event[0] ? e.event : "(message)");
      }
      break;
    }
    case CU_HTTP_EV_DONE:
      done = 1;
      break;
    case CU_HTTP_EV_NEED_MORE:
      /* a real consumer reads from the transport here and feeds again */
      done = 1; /* simulated: no more bytes */
      break;
    case CU_HTTP_EV_ERROR:
      fprintf(stderr, "HTTP parse error\n");
      done = 1;
      break;
    }
  }

  /* drain any SSE events that arrived with the final BODY */
  while (cu_sse_parser_next(&sp)) {
    cu_sse_event_t e;
    cu_sse_parser_event(&sp, &e);
    printf("SSE event (final): data=[%.*s] name=[%s]\n", (int)e.data_len, e.data,
           e.event[0] ? e.event : "(message)");
  }

  cu_http_parser_destroy(&hp);
  cu_sse_parser_destroy(&sp);
  return 0;
}
