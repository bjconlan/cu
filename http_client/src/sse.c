#define _POSIX_C_SOURCE 200809L
#include "cu/sse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*===========================================================================
 * SSE parser — sans-IO state machine.
 *
 * Feeds event-stream bytes; emits complete events. One event slot: the
 * consumer must call cu_sse_parser_next() + cu_sse_parser_event() before
 * feeding more data (the event pointers are valid until the next feed).
 * This matches streaming consumption: feed a chunk, drain ready events,
 * feed more.
 *===========================================================================*/

typedef struct cu_sse_state {
  /* line buffer (grows) */
  char *buf;
  size_t len;
  size_t cap;
  /* working accumulators for the in-progress event */
  char *data;
  size_t data_len, data_cap;
  char *event;
  size_t event_len, event_cap;
  char *id;
  size_t id_len, id_cap;
  long retry_ms;
  bool have_retry;
  /* event queue */
  struct cu_sse_qev {
    char *data;
    size_t data_len;
    char *event;
    char *id;
    bool has_id;
    long retry_ms;
    bool have_retry;
    struct cu_sse_qev *next;
  } *qhead, *qtail, *qfree;
} cu_sse_state_t;

void cu_sse_parser_init(cu_sse_parser_t *p) {
  p->_p = calloc(1, sizeof(cu_sse_state_t));
}

void cu_sse_parser_destroy(cu_sse_parser_t *p) {
  cu_sse_state_t *s = (cu_sse_state_t *)p->_p;
  if (s) {
    free(s->buf);
    free(s->data);
    free(s->event);
    free(s->id);
    struct cu_sse_qev *q;
    for (q = s->qhead; q;) { struct cu_sse_qev *n = q->next; free(q->data); free(q->event); free(q->id); free(q); q = n; }
    for (q = s->qfree; q;) { struct cu_sse_qev *n = q->next; free(q->data); free(q->event); free(q->id); free(q); q = n; }
    free(s);
  }
  p->_p = NULL;
}

void cu_sse_parser_reset(cu_sse_parser_t *p) {
  cu_sse_state_t *s = (cu_sse_state_t *)p->_p;
  if (s) {
    s->len = 0;
    s->data_len = 0;
    s->event_len = 0;
    s->id_len = 0;
    s->have_retry = false;
    s->retry_ms = -1;
  }
}

/* append to a growable string */
static int grow(char **pp, size_t *len, size_t *cap, const char *bytes, size_t n) {
  if (*len + n + 1 > *cap) {
    size_t nc = *cap ? *cap : 64;
    while (nc < *len + n + 1)
      nc *= 2;
    char *q = realloc(*pp, nc);
    if (!q)
      return -1;
    *pp = q;
    *cap = nc;
  }
  memcpy(*pp + *len, bytes, n);
  *len += n;
  (*pp)[*len] = '\0';
  return 0;
}

/* dispatch: copy the working accumulators into a queue node */
static void dispatch(cu_sse_state_t *s) {
  struct cu_sse_qev *q = calloc(1, sizeof *q);
  if (!q)
    return;
  {
    size_t dc = 0;
    grow(&q->data, &q->data_len, &dc, s->data ? s->data : "", s->data_len);
  }
  {
    size_t el = 0, ec = 0;
    grow(&q->event, &el, &ec, s->event ? s->event : "", s->event_len);
  }
  {
    size_t il = 0, ic = 0;
    grow(&q->id, &il, &ic, s->id ? s->id : "", s->id_len);
  }
  q->has_id = s->id_len > 0;
  q->retry_ms = s->retry_ms;
  q->have_retry = s->have_retry;
  if (s->qtail)
    s->qtail->next = q;
  else
    s->qhead = q;
  s->qtail = q;
  s->data_len = 0;
  s->event_len = 0;
  s->id_len = 0;
  s->have_retry = false;
  s->retry_ms = -1;
}

void cu_sse_parser_feed(cu_sse_parser_t *p, const char *bytes, size_t len) {
  cu_sse_state_t *s = (cu_sse_state_t *)p->_p;
  if (!s)
    return;
  if (grow(&s->buf, &s->len, &s->cap, bytes, len) != 0)
    return;
  size_t i = 0;
  while (i < s->len) {
    size_t j = i;
    while (j < s->len && s->buf[j] != '\n' && s->buf[j] != '\r')
      j++;
    if (j == s->len)
      break; /* incomplete line */
    /* compute the terminator width */
    size_t next;
    if (s->buf[j] == '\r') {
      next = (j + 1 < s->len && s->buf[j + 1] == '\n') ? j + 2 : j + 1;
    } else {
      next = j + 1;
    }
    /* process the line [i, j) */
    if (j == i) {
      dispatch(s);
    } else {
      const char *line = s->buf + i;
      size_t linelen = j - i;
      if (line[0] == ':') {
        /* comment — ignore */
      } else {
        size_t colon = 0;
        while (colon < linelen && line[colon] != ':')
          colon++;
        const char *name = line;
        size_t namelen = colon;
        const char *value = line + colon + (colon < linelen ? 1 : 0);
        size_t valuelen = colon < linelen ? linelen - colon - 1 : 0;
        if (valuelen > 0 && value[0] == ' ')
          value++, valuelen--;
        if (namelen == 4 && memcmp(name, "data", 4) == 0) {
          if (s->data_len > 0)
            grow(&s->data, &s->data_len, &s->data_cap, "\n", 1);
          grow(&s->data, &s->data_len, &s->data_cap, value, valuelen);
        } else if (namelen == 5 && memcmp(name, "event", 5) == 0) {
          s->event_len = 0;
          grow(&s->event, &s->event_len, &s->event_cap, value, valuelen);
        } else if (namelen == 2 && memcmp(name, "id", 2) == 0) {
          s->id_len = 0;
          grow(&s->id, &s->id_len, &s->id_cap, value, valuelen);
        } else if (namelen == 5 && memcmp(name, "retry", 5) == 0) {
          char *end;
          long v = strtol(value, &end, 10);
          if (end != value) {
            s->retry_ms = v;
            s->have_retry = true;
          }
        }
      }
    }
    /* remove the consumed line */
    memmove(s->buf, s->buf + next, s->len - next);
    s->len -= next;
    i = 0;
  }
}

int cu_sse_parser_next(cu_sse_parser_t *p) {
  cu_sse_state_t *s = (cu_sse_state_t *)p->_p;
  if (!s || !s->qhead)
    return 0;
  return 1;
}

void cu_sse_parser_event(const cu_sse_parser_t *p, cu_sse_event_t *out) {
  cu_sse_state_t *s = (cu_sse_state_t *)p->_p;
  struct cu_sse_qev *q = s->qhead;
  if (!q) {
    memset(out, 0, sizeof *out);
    return;
  }
  /* free the previously-popped node (strings were consumed) */
  if (s->qfree) {
    struct cu_sse_qev *f = s->qfree;
    free(f->data);
    free(f->event);
    free(f->id);
    free(f);
    s->qfree = NULL;
  }
  /* hand the caller pointers into this node; park it as qfree */
  out->data = q->data ? q->data : "";
  out->data_len = q->data_len;
  out->event = q->event ? q->event : "";
  out->id = q->id ? q->id : "";
  out->has_id = q->has_id;
  out->retry_ms = q->have_retry ? q->retry_ms : -1;
  s->qhead = q->next;
  if (!s->qhead)
    s->qtail = NULL;
  q->next = NULL;
  s->qfree = q;
}
