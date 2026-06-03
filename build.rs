// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use std::env;
use std::path::PathBuf;

fn main() {
    detect_nginx_features();

    // Generate required compiler flags
    if cfg!(target_os = "macos") {
        println!("cargo::rustc-link-arg=-undefined");
        println!("cargo::rustc-link-arg=dynamic_lookup");
    }

    // Compile proto files for OTLP encoding (used in Step 7)
    compile_protos();
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
