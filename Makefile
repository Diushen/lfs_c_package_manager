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
# External libraries (Milestone 4): libarchive reads packages, libcrypto
# (OpenSSL) computes SHA-256. pkg-config / pkgconf is used when present;
# otherwise the plain library names are used.
PKG_CONFIG    ?= pkg-config
ARCHIVE_CFLAGS := $(shell $(PKG_CONFIG) --cflags libarchive 2>/dev/null)
ARCHIVE_LIBS   := $(shell $(PKG_CONFIG) --libs libarchive 2>/dev/null || echo -larchive)
CRYPTO_CFLAGS  := $(shell $(PKG_CONFIG) --cflags libcrypto 2>/dev/null)
CRYPTO_LIBS    := $(shell $(PKG_CONFIG) --libs libcrypto 2>/dev/null || echo -lcrypto)

LPM_CPPFLAGS = -Iinclude -D_POSIX_C_SOURCE=200809L $(ARCHIVE_CFLAGS) $(CRYPTO_CFLAGS)
LPM_CFLAGS   = -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
               -Wstrict-prototypes -Wmissing-prototypes
CFLAGS       = -O2
LDFLAGS      =
LDLIBS       =
LPM_LIBS     = $(ARCHIVE_LIBS) $(CRYPTO_LIBS)

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
PKG_OBJ  = $(DB_OBJ) build/integrity.o build/safefs.o build/archive.o \
           build/manifest.o build/pkg.o build/install.o build/solver.o \
           build/plan.o build/signature.o build/trust.o
SIGN_OBJ = build/signature.o build/integrity.o build/metadata.o build/util.o

# Unit tests live in tests/ (never matched by the src/*.c wildcard, so
# they cannot end up in the lpm binary).
TEST_BIN      = build/test_metadata build/test_version build/test_filelist \
                build/test_database build/test_integrity build/test_archive \
                build/test_install build/test_solver build/test_deps \
                build/test_signature build/test_auth
DEMO_BIN      = build/lpm-db-demo
# Package signing tool (Milestone 6); like the demo, never installed.
SIGN_BIN      = build/lpm-sign
# GNU ld --wrap lets a test intercept a function to inject failures:
# allocation failures everywhere, and system-call failures (short
# writes, EINTR, ENOSPC, EIO, ...) for the database test.
ALLOC_WRAP    = -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc
SYSCALL_WRAP  = -Wl,--wrap=write -Wl,--wrap=fsync -Wl,--wrap=renameat \
                -Wl,--wrap=openat -Wl,--wrap=unlinkat -Wl,--wrap=mkdirat \
                -Wl,--wrap=fchmod -Wl,--wrap=close -Wl,--wrap=flock
INSTALL_WRAP  = $(SYSCALL_WRAP) -Wl,--wrap=linkat -Wl,--wrap=symlinkat

DEP  = $(OBJ:.o=.d) $(TEST_BIN:=.d) build/lpm-db-demo.d build/lpm-sign.d

.PHONY: all debug test unit-test demo clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LPM_LIBS) $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(LPM_CPPFLAGS) $(CPPFLAGS) $(LPM_CFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

build/lpm-sign.o: tools/lpm-sign.c | build
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

build/test_integrity: build/test_integrity.o build/integrity.o build/metadata.o build/util.o
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(CRYPTO_LIBS) $(LDLIBS)

build/test_archive: build/test_archive.o build/archive.o build/safefs.o build/filelist.o \
                    build/metadata.o build/util.o
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(ARCHIVE_LIBS) $(LDLIBS)

build/test_install: build/test_install.o $(PKG_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) $(INSTALL_WRAP) -o $@ $^ $(LPM_LIBS) $(LDLIBS)

build/test_solver: build/test_solver.o build/solver.o build/version.o build/metadata.o \
                   build/util.o
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) -o $@ $^ $(LDLIBS)

build/test_deps: build/test_deps.o $(PKG_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) $(INSTALL_WRAP) -Wl,--wrap=lpm_pkg_read -o $@ $^ $(LPM_LIBS) $(LDLIBS)

build/test_signature: build/test_signature.o $(SIGN_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) -o $@ $^ $(CRYPTO_LIBS) $(LDLIBS)

build/test_auth: build/test_auth.o $(PKG_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) $(ALLOC_WRAP) $(INSTALL_WRAP) -Wl,--wrap=lpm_pkg_read -o $@ $^ $(LPM_LIBS) $(LDLIBS)

$(SIGN_BIN): build/lpm-sign.o $(SIGN_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LPM_LIBS) $(LDLIBS)

$(DEMO_BIN): build/lpm-db-demo.o $(DB_OBJ)
	$(CC) $(LPM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

demo: $(DEMO_BIN) $(SIGN_BIN)

build:
	mkdir -p build

debug:
	$(MAKE) clean
	mkdir -p build
	printf 'CFLAGS = -O0 -g %s\nLDFLAGS = %s\n' '$(SANITIZE)' '$(SANITIZE)' > build/config.mk
	$(MAKE) all $(TEST_BIN) $(DEMO_BIN) $(SIGN_BIN)

test: $(BIN) $(TEST_BIN) $(DEMO_BIN) $(SIGN_BIN)
	bash tests/run_tests.sh ./$(BIN) ./$(DEMO_BIN) ./$(SIGN_BIN)
	./build/test_metadata tests/fixtures
	./build/test_version
	./build/test_filelist
	./build/test_database
	./build/test_integrity
	./build/test_archive
	./build/test_install
	./build/test_solver
	./build/test_deps
	./build/test_signature
	./build/test_auth

unit-test: $(TEST_BIN)
	./build/test_metadata tests/fixtures
	./build/test_version
	./build/test_filelist
	./build/test_database
	./build/test_integrity
	./build/test_archive
	./build/test_install
	./build/test_solver
	./build/test_deps
	./build/test_signature
	./build/test_auth

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)
	rm -rf build

-include $(DEP)
