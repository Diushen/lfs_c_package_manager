# LPM - LFS Package Manager
#
#   make            release build (-O2)
#   make debug      -O0 -g with AddressSanitizer + UBSan
#   make test       build, then run tests/run_tests.sh
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
LDLIBS       =

SANITIZE = -fsanitize=address,undefined -fno-omit-frame-pointer

BIN  = lpm
SRC  = $(wildcard src/*.c)
OBJ  = $(SRC:src/%.c=build/%.o)
DEP  = $(OBJ:.o=.d)

.PHONY: all debug test clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(LPM_CPPFLAGS) $(CPPFLAGS) $(LPM_CFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

build:
	mkdir -p build

debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O0 -g $(SANITIZE)" LDFLAGS="$(SANITIZE)"

test: $(BIN)
	bash tests/run_tests.sh ./$(BIN)

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)
	rm -rf build

-include $(DEP)
