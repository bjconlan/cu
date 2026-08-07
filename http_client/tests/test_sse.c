/*
 * SSE parser unit tests — sans-IO, byte-at-a-time and whole-buffer.
 */
#define _POSIX_C_SOURCE 200809L
#include "cu/sse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tests/greatest.h"

/* Collect events from a stream fed whole-buffer. Returns count. The
 * event strings are copied (strdup) so they survive parser destroy. */
static size_t collect(const char *stream, size_t n, cu_sse_event_t *evs, size_t cap) {
  cu_sse_parser_t sp;
  cu_sse_parser_init(&sp);
  cu_sse_parser_feed(&sp, stream, n);
  size_t got = 0;
  while (cu_sse_parser_next(&sp) && got < cap) {
    cu_sse_event_t e;
    cu_sse_parser_event(&sp, &e);
    evs[got] = e;
    evs[got].data = strdup(e.data);
    evs[got].event = strdup(e.event);
    evs[got].id = strdup(e.id);
    got++;
  }
  cu_sse_parser_destroy(&sp);
  return got;
}

/* Feed byte-at-a-time; returns event count (same events expected). */
static size_t collect_bytewise(const char *stream, size_t n, cu_sse_event_t *evs, size_t cap) {
  cu_sse_parser_t sp;
  cu_sse_parser_init(&sp);
  size_t got = 0;
  for (size_t i = 0; i < n; i++) {
    cu_sse_parser_feed(&sp, stream + i, 1);
    while (cu_sse_parser_next(&sp) && got < cap) {
      cu_sse_event_t e;
      cu_sse_parser_event(&sp, &e);
      evs[got] = e;
      evs[got].data = strdup(e.data);
      evs[got].event = strdup(e.event);
      evs[got].id = strdup(e.id);
      got++;
    }
  }
  cu_sse_parser_destroy(&sp);
  return got;
}

TEST test_sse_basic(void) {
  const char *stream =
      "data: hello\n"
      "\n";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(1, (int)n);
  ASSERT_STR_EQ("hello", evs[0].data);
  ASSERT_EQ(5, (int)evs[0].data_len);
  PASS();
}

TEST test_sse_multi_field(void) {
  const char *stream =
      "event: delta\n"
      "data: {\"a\":1}\n"
      "\n";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(1, (int)n);
  ASSERT_STR_EQ("delta", evs[0].event);
  ASSERT_STR_EQ("{\"a\":1}", evs[0].data);
  PASS();
}

TEST test_sse_multiline_data(void) {
  const char *stream =
      "data: line1\n"
      "data: line2\n"
      "\n";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(1, (int)n);
  ASSERT_STR_EQ("line1\nline2", evs[0].data);
  ASSERT_EQ(11, (int)evs[0].data_len);
  PASS();
}

TEST test_sse_id_retry(void) {
  const char *stream =
      "id: 42\n"
      "retry: 3000\n"
      "data: x\n"
      "\n";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(1, (int)n);
  ASSERT(evs[0].has_id);
  ASSERT_STR_EQ("42", evs[0].id);
  ASSERT_EQ(3000, (int)evs[0].retry_ms);
  PASS();
}

TEST test_sse_comment_ignored(void) {
  const char *stream =
      ": this is a comment\n"
      "data: real\n"
      "\n";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(1, (int)n);
  ASSERT_STR_EQ("real", evs[0].data);
  PASS();
}

TEST test_sse_multiple_events(void) {
  const char *stream =
      "data: one\n"
      "\n"
      "data: two\n"
      "\n"
      "data: three\n"
      "\n";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(3, (int)n);
  ASSERT_STR_EQ("one", evs[0].data);
  ASSERT_STR_EQ("two", evs[1].data);
  ASSERT_STR_EQ("three", evs[2].data);
  PASS();
}

TEST test_sse_crlf_endings(void) {
  const char *stream =
      "data: crlf\r\n"
      "\r\n"
      "data: lf\n"
      "\n"
      "data: cr\r"
      "\r";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(3, (int)n);
  ASSERT_STR_EQ("crlf", evs[0].data);
  ASSERT_STR_EQ("lf", evs[1].data);
  ASSERT_STR_EQ("cr", evs[2].data);
  PASS();
}

TEST test_sse_split_feeds(void) {
  /* byte-at-a-time must yield identical events */
  const char *stream =
      "event: a\n"
      "data: 1\n"
      "\n"
      "data: 2\n"
      "\n";
  cu_sse_event_t whole[4], bw[4];
  size_t nw = collect(stream, strlen(stream), whole, 4);
  size_t nb = collect_bytewise(stream, strlen(stream), bw, 4);
  ASSERT_EQ((int)nw, (int)nb);
  ASSERT_EQ(2, (int)nw);
  ASSERT(memcmp(whole[0].data, bw[0].data, whole[0].data_len + 1) == 0);
  ASSERT(memcmp(whole[1].data, bw[1].data, whole[1].data_len + 1) == 0);
  PASS();
}

TEST test_sse_no_data_field(void) {
  /* an event with only event:/id: still dispatches on the blank line */
  const char *stream =
      "event: ping\n"
      "\n";
  cu_sse_event_t evs[4];
  size_t n = collect(stream, strlen(stream), evs, 4);
  ASSERT_EQ(1, (int)n);
  ASSERT_STR_EQ("ping", evs[0].event);
  ASSERT_EQ(0, (int)evs[0].data_len);
  PASS();
}

SUITE(sse_suite) {
  RUN_TEST(test_sse_basic);
  RUN_TEST(test_sse_multi_field);
  RUN_TEST(test_sse_multiline_data);
  RUN_TEST(test_sse_id_retry);
  RUN_TEST(test_sse_comment_ignored);
  RUN_TEST(test_sse_multiple_events);
  RUN_TEST(test_sse_crlf_endings);
  RUN_TEST(test_sse_split_feeds);
  RUN_TEST(test_sse_no_data_field);
}
