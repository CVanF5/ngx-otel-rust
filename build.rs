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
    // Specify acceptable values for `ngx_feature`
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES_CHECK");
    println!(
        "cargo::rustc-check-cfg=cfg(ngx_feature, values({}))",
        env::var("DEP_NGINX_FEATURES_CHECK").unwrap_or("any()".to_string())
    );
    // Read feature flags detected by nginx-sys and pass to the compiler.
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES");
    if let Ok(features) = env::var("DEP_NGINX_FEATURES") {
        for feature in features.split(',').map(str::trim) {
            println!("cargo::rustc-cfg=ngx_feature=\"{feature}\"");
        }
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

/// Compile OpenTelemetry proto files with prost-build.
fn compile_protos() {
    let proto_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("proto");

    let protos = [
        proto_root.join("opentelemetry/proto/common/v1/common.proto"),
        proto_root.join("opentelemetry/proto/resource/v1/resource.proto"),
        proto_root.join("opentelemetry/proto/metrics/v1/metrics.proto"),
        proto_root.join("opentelemetry/proto/collector/metrics/v1/metrics_service.proto"),
    ];

    // Only compile if all proto files exist
    let all_exist = protos.iter().all(|p| p.exists());

    if all_exist {
        prost_build::Config::new()
            .compile_protos(&protos, &[&proto_root])
            .expect("prost-build failed");

        // Mark proto files for recompilation
        for proto in &protos {
            println!("cargo::rerun-if-changed={}", proto.display());
        }
    }
}
