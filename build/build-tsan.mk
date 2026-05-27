# Thread Sanitizer build flavor.  Mirrors build-sanitize.mk (ASAN) with the
# following flag deltas:
#   C side:   -fsanitize=thread (not address); keep -O1 and -fno-omit-frame-pointer;
#             drop -DNGX_DEBUG_PALLOC and -DNGX_SUPPRESS_WARN (ASAN-specific).
#   Rust side: -Zsanitizer=thread (not address); keep -Zexternal-clangrt and
#              RUSTC_BOOTSTRAP=1 -Zbuild-std so the unstable flag works on stable.
#   TEST_ENV:  TSAN_OPTIONS (not ASAN_OPTIONS); no LSAN suppressions file.
#
# TSAN on macOS arm64 is FORBIDDEN (historically produces spurious noise on
# aarch64-apple-darwin).  This file is used only inside build/Dockerfile.tsan
# via the tsan-test Makefile target.  `make build BUILD=tsan` compiles on
# macOS as a flag-validity sanity check; never RUN the result on macOS.

CFLAGS_TSAN	+= -O1 -fsanitize=thread -fno-omit-frame-pointer
LDFLAGS_TSAN	+= -fsanitize=thread

RUSTFLAGS 	+= -Cforce-frame-pointers=yes
RUSTFLAGS 	+= -Zsanitizer=thread -Zexternal-clangrt

BUILD_ENV	+= RUSTFLAGS="$(RUSTFLAGS)"
BUILD_ENV	+= RUSTC_BOOTSTRAP=1
BUILD_ENV	+= NGX_RUSTC_OPT="-Zbuild-std"
BUILD_ENV	+= NGX_RUST_TARGET="$(HOST_TUPLE)"

TEST_ENV	+= TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1:detect_deadlocks=1
TEST_ENV	+= TEST_NGINX_CATLOG=1

NGINX_CONFIGURE	= \
	$(NGINX_CONFIGURE_BASE) \
		--with-cc=clang \
		--with-cc-opt="$(CFLAGS_TSAN)" \
		--with-ld-opt="$(LDFLAGS_TSAN)" \
		--with-debug \
		--add-module="$(CURDIR)"
