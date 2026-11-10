# LPM - LFS Package Manager
#
#   make            release build (-O2)
#   make debug      -O0 -g with AddressSanitizer + UBSan (sticky until
#                   `make clean`, so a following `make test` uses it too)
#   make test       build, then run the CLI tests and the unit tests
#   make unit-test  build and run only the unit tests
#   make clean      remove build artefacts
#   make install    install binary to $(DESTDIR)$(PREFIX)/bin

CC       = gcc
PREFIX   = /usr/local

# Flags the project always needs live in their own variables, so that
# overriding CFLAGS on the command line (e.g. `make CFLAGS=-g`) cannot
# silently drop the language standard or the warnings.
LPM_CPPFLAGS = -Iinclude -D_POSIX_C_SOURCE=200809L
LPM_CFLAGS   = -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
               -Wstrict-prototypes -Wmissing-prototypes
CFLAGS       = -O2
LDFLAGS      =
LDLIBS       =

# `make debug` writes its CFLAGS/LDFLAGS here; every later make
# invocation picks them up until `make clean` deletes the build dir.
-include build/config.mk

SANITIZE = -fsanitize=address,undefined -fno-omit-frame-pointer

BIN  = lpm
SRC  = $(wildcard src/*.c)
OBJ  = $(SRC:src/%.c=build/%.o)

# Unit tests live in tests/ (never matched by the src/*.c wildcard, so
# they cannot end up in the lpm binary). The metadata test links only
# the modules it exercises: the parser has no database/CLI dependency.
TEST_BIN  = build/test_metadata
TEST_OBJ  = build/test_metadata.o build/metadata.o build/util.o
# GNU ld --wrap lets the test inject malloc/calloc/realloc failures.
TEST_WRAP = -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc

DEP  = $(OBJ:.o=.d) build/test_metadata.d

.PHONY: all debug test unit-test clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(LPM_CPPFLAGS) $(CPPFLAGS) $(LPM_CFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

build/test_%.o: tests/test_%.c | build
	$(CC) $(LPM_CPPFLAGS) $(CPPFLAGS) $(LPM_CFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(TEST_BIN): $(TEST_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(TEST_WRAP) -o $@ $(TEST_OBJ) $(LDLIBS)

build:
	mkdir -p build

debug:
	$(MAKE) clean
	mkdir -p build
	printf 'CFLAGS = -O0 -g %s\nLDFLAGS = %s\n' '$(SANITIZE)' '$(SANITIZE)' > build/config.mk
	$(MAKE) all $(TEST_BIN)

test: $(BIN) $(TEST_BIN)
	bash tests/run_tests.sh ./$(BIN)
	./$(TEST_BIN) tests/fixtures

unit-test: $(TEST_BIN)
	./$(TEST_BIN) tests/fixtures

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)
	rm -rf build

-include $(DEP)
