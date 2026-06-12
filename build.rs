// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use std::env;
use std::path::PathBuf;

fn main() {
    detect_nginx_features();
    check_build_flavor();

    // Generate required compiler flags
    if cfg!(target_os = "macos") {
        println!("cargo::rustc-link-arg=-undefined");
        println!("cargo::rustc-link-arg=dynamic_lookup");
    }

    // Compile the module-side C shims (H3F1 bitfield accessors + C2 ssl/cert
    // accessors) against the real nginx headers.
    compile_c_shims();

    // Compile proto files for OTLP encoding (used in Step 7)
    compile_protos();
}

/// Compile the module-side C shims against the real nginx headers:
///
/// - `src/shim/ngx_otel_bitfield_shim.c` — accessors for `ngx_http_request_t`
///   bitfields that rust-bindgen reads at the wrong bit offset
///   (allocation-unit-sharing bug; see the file header and
///   `BINDGEN_BITFIELD_ISSUE_DRAFT.md`).
/// - `src/shim/ngx_otel_ssl_shim.c` — `ngx_http_ssl_srv_conf_t` accessors and
///   the OpenSSL `SSL_CTX_set_current_cert` cert-enumeration wrapper for the
///   config-time cert table (TLS cert-metrics item C2; see its file header).
///
/// The shims are compiled by *our* build against the *same* nginx headers and
/// `-D` defines nginx-sys used to build nginx, so the layout they see is
/// byte-identical to nginx's own — correct by construction.  The nginx include
/// list (`DEP_NGINX_INCLUDE`, parsed from the generated objs/Makefile's
/// `ALL_INCS`) also carries the OpenSSL include directory nginx itself was
/// configured with, so `<openssl/ssl.h>` resolves to the same headers.
///
/// Include paths and defines are taken from the `DEP_NGINX_INCLUDE` /
/// `DEP_NGINX_BUILD_DIR` / `DEP_NGINX_CFLAGS` environment variables that
/// nginx-sys exports to its dependents (via `links = "nginx"` +
/// `cargo::metadata=include=…` / `=build_dir=…` / `=cflags=…`), so we do not
/// re-derive them.  `DEP_NGINX_INCLUDE` is an `env::join_paths` list (OS path
/// separator); `DEP_NGINX_CFLAGS` is a space-separated `-Dname[=value]` list.
fn compile_c_shims() {
    println!("cargo::rerun-if-changed=src/shim/ngx_otel_bitfield_shim.c");
    println!("cargo::rerun-if-changed=src/shim/ngx_otel_ssl_shim.c");
    println!("cargo::rerun-if-env-changed=DEP_NGINX_INCLUDE");
    println!("cargo::rerun-if-env-changed=DEP_NGINX_BUILD_DIR");
    println!("cargo::rerun-if-env-changed=DEP_NGINX_CFLAGS");

    let mut build = cc::Build::new();
    build.file("src/shim/ngx_otel_bitfield_shim.c");
    build.file("src/shim/ngx_otel_ssl_shim.c");

    // Include dirs from nginx-sys (src/core, src/event, src/os/unix, src/http,
    // src/http/modules, …) plus the build/objs dir (ngx_auto_config.h /
    // ngx_auto_headers.h).
    if let Some(include) = env::var_os("DEP_NGINX_INCLUDE") {
        for path in env::split_paths(&include) {
            build.include(path);
        }
    }
    // The objs build dir holds ngx_auto_config.h / ngx_auto_headers.h, which
    // ngx_config.h includes.  It is normally already in DEP_NGINX_INCLUDE, but
    // add it explicitly so the shim compiles even if it is not.
    if let Some(build_dir) = env::var_os("DEP_NGINX_BUILD_DIR") {
        build.include(build_dir);
    }

    // The same `-D` defines nginx-sys used (feature gates that affect the
    // ngx_http_request_t layout, e.g. NGX_HTTP_V2/V3, SSL).
    if let Ok(cflags) = env::var("DEP_NGINX_CFLAGS") {
        for def in cflags.split_whitespace() {
            if let Some(d) = def.strip_prefix("-D") {
                match d.split_once('=') {
                    Some((name, value)) => {
                        build.define(name, Some(value));
                    }
                    None => {
                        build.define(d, None);
                    }
                }
            }
        }
    }

    build.compile("ngx_otel_shims");
}

/// Guard against building a release-profile crate against a debug-flavored
/// nginx tree (or vice versa).
///
/// The hazard: `.cargo/config.toml` defaults `NGINX_BUILD_DIR=objs-debug` so
/// that `cargo check` / rust-analyzer work without going through `make`.  If a
/// developer then runs `cargo test --release` bare, cargo passes `objs-debug`
/// to the build — release-profile nginx-sys bindings built against the
/// `--with-debug` nginx tree.  Those bindings land in `target/release`, where
/// `make build-release` also writes its artefacts.  bindgen caches are keyed
/// on the input headers; a stale cache from the wrong flavor silently produces
/// incorrect bindings (the "bindgen cache lies" gotcha).
///
/// Detection: `ngx_auto_config.h` in the nginx build dir contains
///   `#define NGX_DEBUG  1`
/// when nginx was configured `--with-debug` (the debug flavor); the release
/// flavor has no such line.
///
/// Escape hatch: set `NGX_OTEL_ALLOW_FLAVOR_MISMATCH=1` if you genuinely need
/// to cross-link (unusual; prefer `make build-release` / `make unittest-release`
/// instead).  After any intentional mismatch, run `cargo clean` to purge the
/// release cache before further release builds.
fn check_build_flavor() {
    // Rebuild whenever the escape-hatch or the build dir changes.
    println!("cargo::rerun-if-env-changed=NGX_OTEL_ALLOW_FLAVOR_MISMATCH");
    println!("cargo::rerun-if-env-changed=NGINX_BUILD_DIR");

    // Escape hatch: intentional cross-link (unusual).
    if env::var("NGX_OTEL_ALLOW_FLAVOR_MISMATCH").as_deref() == Ok("1") {
        return;
    }

    // cargo sets PROFILE to "debug" or "release" in build scripts.
    let profile = env::var("PROFILE").unwrap_or_default();
    let is_release = profile == "release";

    // Read the build dir from nginx-sys's metadata export (DEP_NGINX_BUILD_DIR),
    // falling back to the raw env var the user (or .cargo/config.toml) set.
    // DEP_NGINX_BUILD_DIR is set by nginx-sys build script; NGINX_BUILD_DIR is
    // the raw env var the user (or .cargo/config.toml) provides.
    let build_dir = env::var_os("DEP_NGINX_BUILD_DIR")
        .or_else(|| env::var_os("NGINX_BUILD_DIR"))
        .map(PathBuf::from);

    let auto_config_path = match &build_dir {
        Some(dir) => dir.join("ngx_auto_config.h"),
        None => return, // no build dir known; the existing bindgen error will fire
    };

    // Rerun when the auto-config changes (file may not exist yet if configure
    // hasn't run; that's fine — the existing bindgen path handles that).
    println!("cargo::rerun-if-changed={}", auto_config_path.display());

    // Only guard on a POSITIVE NGX_DEBUG detection; missing / unreadable file
    // → skip (the existing bindgen error already catches a broken NGINX_BUILD_DIR).
    let contents = match std::fs::read_to_string(&auto_config_path) {
        Ok(s) => s,
        Err(_) => return,
    };
    // Match a genuine `#define NGX_DEBUG 1` (whitespace-tolerant), NOT a bare
    // substring: a non-debug tree's `ngx_auto_config.h` can still mention
    // `NGX_DEBUG` in an `#ifndef NGX_DEBUG` guard, which `contains("NGX_DEBUG")`
    // would wrongly flag as a debug tree (the A0.5 false-positive that aborted
    // `make test` on debian-vm). Only the actual define indicates `--with-debug`.
    let nginx_tree_is_debug = contents.lines().any(|line| {
        let mut toks = line.split_whitespace();
        toks.next() == Some("#define")
            && toks.next() == Some("NGX_DEBUG")
            && toks.next() == Some("1")
    });

    if is_release && nginx_tree_is_debug {
        // Hard error: release cargo profile + debug nginx tree = bad cache.
        panic!(
            "\n\
             ┌────────────────────────────────────────────────────────────────┐\n\
             │  BUILD FLAVOR MISMATCH — release profile + debug nginx tree    │\n\
             ├────────────────────────────────────────────────────────────────┤\n\
             │  NGINX_BUILD_DIR={dir} was configured with            │\n\
             │  --with-debug (NGX_DEBUG=1), but cargo is building in RELEASE  │\n\
             │  profile.  The bindgen cache in target/release would contain   │\n\
             │  bindings generated from the wrong (debug-flavored) headers.   │\n\
             │                                                                │\n\
             │  Remedy:                                                       │\n\
             │    make build-release        (recommended — sets objs-release) │\n\
             │    make unittest-release     (release-profile unit tests)      │\n\
             │  or, if you truly mean to cross-link:                         │\n\
             │    NGX_OTEL_ALLOW_FLAVOR_MISMATCH=1 cargo test --release --lib │\n\
             │  Then run `cargo clean` before the next release build to purge │\n\
             │  the stale release cache.                                      │\n\
             └────────────────────────────────────────────────────────────────┘\n",
            dir = auto_config_path.parent().map(|p| p.display().to_string()).unwrap_or_default(),
        );
    }

    // Reverse case: debug profile + non-debug tree.  This is less hazardous
    // (the debug cache won't collide with a release build; debug bindings
    // compiled against a non-debug nginx tree are valid for running debug
    // tests, just without extra nginx assertions).  Warn rather than hard-error
    // so that developers who have only a release-configured nginx available are
    // not completely blocked from running debug tests.
    if !is_release && !nginx_tree_is_debug {
        println!(
            "cargo::warning=Build flavor note: debug cargo profile with a non-debug nginx tree \
             ({dir}). Tests will work but without nginx --with-debug assertions. \
             Use `make build` (which configures --with-debug) for full debug coverage.",
            dir = auto_config_path.parent().map(|p| p.display().to_string()).unwrap_or_default(),
        );
    }
}

/// Generates `ngx_os`, `ngx_feature` and nginx version cfg values.
fn detect_nginx_features() {
    // Detect NGX_STAT_STUB from ngx_auto_config.h, which nginx-sys does not
    // surface as a feature but we gate code on.
    let stat_stub = detect_stat_stub();

    // Specify acceptable values for `ngx_feature`.
    // Append "stat_stub" to the list nginx-sys gives us so our #[cfg] guards
    // don't trigger "unexpected cfg condition value" warnings.
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES_CHECK");
    let features_check = env::var("DEP_NGINX_FEATURES_CHECK").unwrap_or("any()".to_string());
    if features_check == "any()" {
        println!("cargo::rustc-check-cfg=cfg(ngx_feature, values(any()))");
    } else {
        println!(
            r#"cargo::rustc-check-cfg=cfg(ngx_feature, values({features_check},"stat_stub"))"#,
        );
    }

    // Read feature flags detected by nginx-sys and pass to the compiler.
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES");
    if let Ok(features) = env::var("DEP_NGINX_FEATURES") {
        for feature in features.split(',').map(str::trim) {
            println!("cargo::rustc-cfg=ngx_feature=\"{feature}\"");
        }
    }
    if stat_stub {
        println!("cargo::rustc-cfg=ngx_feature=\"stat_stub\"");
    }

    // Specify acceptable values for `ngx_os`
    println!("cargo::rerun-if-env-changed=DEP_NGINX_OS_CHECK");
    println!(
        "cargo::rustc-check-cfg=cfg(ngx_os, values({}))",
        env::var("DEP_NGINX_OS_CHECK").unwrap_or("any()".to_string())
    );
    // Read operating system detected by nginx-sys and pass to the compiler.
    println!("cargo::rerun-if-env-changed=DEP_NGINX_OS");
    if let Ok(os) = env::var("DEP_NGINX_OS") {
        println!("cargo::rustc-cfg=ngx_os=\"{os}\"");
    }
}

/// Returns `true` when the nginx build we're linking against was configured
/// with `--with-http_stub_status_module` (i.e. `NGX_STAT_STUB` is defined).
///
/// nginx-sys does not surface this as a feature, so we check directly.
/// The `DEP_NGINX_BUILD_DIR` env var is set by nginx-sys (via `links = "nginx"`
/// and `cargo::metadata=build_dir=...`).
fn detect_stat_stub() -> bool {
    println!("cargo::rerun-if-env-changed=DEP_NGINX_BUILD_DIR");
    let build_dir = match env::var("DEP_NGINX_BUILD_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => return false,
    };
    let auto_config = build_dir.join("ngx_auto_config.h");
    println!("cargo::rerun-if-changed={}", auto_config.display());
    std::fs::read_to_string(&auto_config).map(|s| s.contains("NGX_STAT_STUB")).unwrap_or(false)
}

/// Compile OpenTelemetry proto files with tonic-prost-build.
fn compile_protos() {
    let proto_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("proto");

    let otel_protos = [
        proto_root.join("opentelemetry/proto/common/v1/common.proto"),
        proto_root.join("opentelemetry/proto/resource/v1/resource.proto"),
        proto_root.join("opentelemetry/proto/metrics/v1/metrics.proto"),
        proto_root.join("opentelemetry/proto/collector/metrics/v1/metrics_service.proto"),
        proto_root.join("opentelemetry/proto/logs/v1/logs.proto"),
        proto_root.join("opentelemetry/proto/collector/logs/v1/logs_service.proto"),
        proto_root.join("opentelemetry/proto/trace/v1/trace.proto"),
        proto_root.join("opentelemetry/proto/collector/trace/v1/trace_service.proto"),
    ];

    if otel_protos.iter().all(|p| p.exists()) {
        tonic_prost_build::configure()
            .build_client(true)
            .build_server(false)
            .compile_protos(&otel_protos, std::slice::from_ref(&proto_root))
            .expect("tonic-prost-build failed for OTel protos");

        for proto in &otel_protos {
            println!("cargo::rerun-if-changed={}", proto.display());
        }
    }

    // Phase 1.2 Item 2: compile the local echo proto used for bidi smoke
    // testing.  This proto is a throwaway local definition; Phase 5 will
    // replace it with OTAP's arrow_service.proto.
    //
    // Two separate compilations are required because the main library is
    // no_std, and the tonic-generated server stub uses bare `Box::pin` which
    // is not in scope in a no_std context (tonic::codegen::* doesn't re-export
    // Box).  The example binary (bidi_echo_server.rs) is a full-std Rust
    // binary, so it can safely include the server+client version.
    //
    // - Client-only version → OUT_DIR/ngx.otel.echo.v1.rs
    //   Used from src/transport/grpc/echo_proto.rs (no_std-safe).
    //
    // - Server+client version → OUT_DIR/echo_server_gen/ngx.otel.echo.v1.rs
    //   Used from examples/bidi_echo_server.rs (full-std, dev-only binary).
    let echo_proto = proto_root.join("echo/v1/echo.proto");
    if echo_proto.exists() {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

        // Client-only: no_std-safe, used by the library.
        tonic_prost_build::configure()
            .build_client(true)
            .build_server(false)
            .compile_protos(std::slice::from_ref(&echo_proto), std::slice::from_ref(&proto_root))
            .expect("tonic-prost-build failed for echo client");

        // Server+client: used by examples/bidi_echo_server.rs only.
        let echo_server_out = out_dir.join("echo_server_gen");
        std::fs::create_dir_all(&echo_server_out).expect("create echo_server_gen dir");
        tonic_prost_build::configure()
            .build_client(true)
            .build_server(true)
            .out_dir(&echo_server_out)
            .compile_protos(std::slice::from_ref(&echo_proto), &[proto_root])
            .expect("tonic-prost-build failed for echo server");

        println!("cargo::rerun-if-changed={}", echo_proto.display());
    }
}
