#============================================================================
# cu — Cosmo Utilities
#
# Reusable cosmopolitan wire deps: TLS (BearSSL) + HTTP/1.1 client.
# Uses cosmocc for portable APE binaries. Targets C23.
#============================================================================

COSMOCC   ?= /home/bjc/.local/opt/cosmocc/bin/cosmocc
COSMOAR   ?= /home/bjc/.local/opt/cosmocc/bin/cosmoar
CSTANDARD := -std=c2x
BASE_CFLAGS := -g -O2 -Wall -Wextra -Werror -Wpedantic $(CSTANDARD)

CC := $(COSMOCC)
AR := $(COSMOAR)
CFLAGS := $(BASE_CFLAGS) -I. -Iinclude -Ithird_party/bearssl/inc
LDFLAGS := -static

# BearSSL (git submodule, pinned). Relaxed flags — C99, never -Werror.
BEARSSL_DIR := third_party/bearssl
BEARSSL_SRCS := $(wildcard $(BEARSSL_DIR)/src/*.c $(BEARSSL_DIR)/src/*/*.c)
ifeq ($(BEARSSL_SRCS),)
$(error third_party/bearssl submodule not checked out: git submodule update --init)
endif
BEARSSL_CFLAGS := -std=c99 -Os -w -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
                  -I$(BEARSSL_DIR)/src -I$(BEARSSL_DIR)/inc
BEARSSL_OBJS := $(patsubst $(BEARSSL_DIR)/%.c,build/bearssl/%.o,$(BEARSSL_SRCS))

# cu components
TLS_SRCS := tls/src/tls.c
TLS_OBJS := $(TLS_SRCS:.c=.o)
HTTP_SRCS := http_client/src/http_client.c
HTTP_OBJS := $(HTTP_SRCS:.c=.o)
CU_OBJS := $(TLS_OBJS) $(HTTP_OBJS)

TEST_SRCS := test_main.c tls/tests/test_tls.c http_client/tests/test_http.c
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST := cu-test

#--------------------------------------------------------------------------
# Targets
#--------------------------------------------------------------------------

.PHONY: all lib test clean format

all: lib

lib: build/libcu.a

build/libcu.a: $(CU_OBJS) $(BEARSSL_OBJS)
	mkdir -p build
	$(AR) rcs $@ $(CU_OBJS) $(BEARSSL_OBJS)

test: $(TEST)

$(TEST): $(TEST_OBJS) $(CU_OBJS) $(BEARSSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(CU_OBJS) $(BEARSSL_OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

tls/tests/%.o: CFLAGS += -Itls/include -I.
http_client/tests/%.o: CFLAGS += -Ihttp_client/include -I.
tls/src/%.o: CFLAGS += -Itls/include -Ihttp_client/include
http_client/src/%.o: CFLAGS += -Ihttp_client/include

build/bearssl/%.o: $(BEARSSL_DIR)/%.c | build
	$(CC) $(BEARSSL_CFLAGS) -c -o $@ $<

build:
	mkdir -p build

clean:
	rm -f $(CU_OBJS) $(TEST_OBJS) $(BEARSSL_OBJS) build/libcu.a $(TEST)
	rm -rf build

format:
	$(CLANGFORMAT) -i tls/include/*.h tls/src/*.c http_client/include/*.h http_client/src/*.c
