# LPM - LFS Package Manager
#
#   make            release build (-O2) of lpm
#   make debug      -O0 -g with AddressSanitizer + UBSan (sticky until
#                   `make clean`, so a following `make test` uses it too)
#   make test       build, then run the CLI tests and all unit tests
#   make unit-test  build and run only the unit tests
#   make demo       build only build/lpm-db-demo (Milestone 3 demonstration)
#   make clean      remove build artefacts
#   make install    install the lpm binary to $(DESTDIR)$(PREFIX)/bin
#                   (the demo and test programs are never installed)

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

# Library objects = everything except the CLI front end. Test and demo
# programs link only what they exercise.
CORE_OBJ = build/util.o build/metadata.o build/version.o build/filelist.o
DB_OBJ   = $(CORE_OBJ) build/database.o

# Unit tests live in tests/ (never matched by the src/*.c wildcard, so
# they cannot end up in the lpm binary).
TEST_BIN      = build/test_metadata build/test_version build/test_filelist \
                build/test_database
DEMO_BIN      = build/lpm-db-demo
# GNU ld --wrap lets a test intercept a function to inject failures:
# allocation failures everywhere, and system-call failures (short
# writes, EINTR, ENOSPC, EIO, ...) for the database test.
ALLOC_WRAP    = -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc
SYSCALL_WRAP  = -Wl,--wrap=write -Wl,--wrap=fsync -Wl,--wrap=renameat \
                -Wl,--wrap=openat -Wl,--wrap=unlinkat -Wl,--wrap=mkdirat \
                -Wl,--wrap=fchmod -Wl,--wrap=close -Wl,--wrap=flock

DEP  = $(OBJ:.o=.d) $(TEST_BIN:=.d) build/lpm-db-demo.d

.PHONY: all debug test unit-test demo clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(LPM_CPPFLAGS) $(CPPFLAGS) $(LPM_CFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

build/test_%.o: tests/test_%.c | build
	$(CC) $(LPM_CPPFLAGS) $(CPPFLAGS) $(LPM_CFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

build/lpm-db-demo.o: tools/lpm-db-demo.c | build
	$(CC) $(LPM_CPPFLAGS) $(CPPFLAGS) $(LPM_CFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

build/test_metadata: build/test_metadata.o build/metadata.o build/util.o
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) -o $@ $^ $(LDLIBS)

build/test_version: build/test_version.o build/version.o build/metadata.o build/util.o
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/test_filelist: build/test_filelist.o build/filelist.o build/metadata.o build/util.o
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) -o $@ $^ $(LDLIBS)

build/test_database: build/test_database.o $(DB_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) $(SYSCALL_WRAP) -o $@ $^ $(LDLIBS)

$(DEMO_BIN): build/lpm-db-demo.o $(DB_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

demo: $(DEMO_BIN)

build:
	mkdir -p build

debug:
	$(MAKE) clean
	mkdir -p build
	printf 'CFLAGS = -O0 -g %s\nLDFLAGS = %s\n' '$(SANITIZE)' '$(SANITIZE)' > build/config.mk
	$(MAKE) all $(TEST_BIN) $(DEMO_BIN)

test: $(BIN) $(TEST_BIN) $(DEMO_BIN)
	bash tests/run_tests.sh ./$(BIN) ./$(DEMO_BIN)
	./build/test_metadata tests/fixtures
	./build/test_version
	./build/test_filelist
	./build/test_database

unit-test: $(TEST_BIN)
	./build/test_metadata tests/fixtures
	./build/test_version
	./build/test_filelist
	./build/test_database

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)
	rm -rf build

-include $(DEP)
