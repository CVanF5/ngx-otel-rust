// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Nginx directive handler functions for the OTel module.
//!
//! Each `cmd_*` function here is registered in the command tables defined in
//! `config/mod.rs`.  They are `extern "C"` callbacks invoked by nginx during
//! configuration parsing.

use core::ffi::{c_char, c_void};
use core::{mem, ptr};

use hyper::header::{HeaderName, HeaderValue};

use nginx_sys::{
    ngx_command_t, ngx_conf_parse, ngx_conf_t, ngx_http_compile_complex_value_t,
    ngx_http_complex_value_t, ngx_str_t, ngx_uint_t, NGX_LOG_EMERG, NGX_LOG_WARN,
};
use ngx::core::{NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::http::HttpModuleMainConf;
use ngx::ngx_conf_log_error;

use crate::logs::error_writer::{
    ngx_otel_error_writer, otel_log_insert, parse_error_log_level, OtelErrorWriterState,
};
use crate::HttpOtelModule;

#[cfg(any(test, feature = "test-support"))]
use super::align_ring_size;
use super::{
    cf_args, parse_duration_ms, parse_size_bytes, ExporterConfig, KvPair, MainConfig, UNSET_FLAG,
    UNSET_U64,
};

// ── Inner exporter block ───────────────────────────────────────────────────────

pub(super) extern "C" fn cmd_exporter_set_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the directive's conf pointer, which for the
    // `otel_exporter` block was set to `&amcf.exporter` (an `ExporterConfig` in
    // the conf pool); casting and `as_mut` yield a valid exclusive reference.
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.endpoint.is_empty() {
        return already_set_error();
    }

    // SAFETY: `cf` is the valid non-null parse context nginx passes to a directive
    // handler, and its `args` array holds the parsed directive tokens.
    let args = unsafe { cf_args(cf) };
    ecf.endpoint = args[1];
    NGX_CONF_OK
}

pub(super) extern "C" fn cmd_exporter_set_trusted_cert(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block's conf pointer, set to
    // `&amcf.exporter` (an `ExporterConfig` in the conf pool); the cast + `as_mut`
    // yield a valid exclusive reference.
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.trusted_cert.is_empty() {
        return already_set_error();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; its `args` array
    // holds the parsed tokens.
    let args = unsafe { cf_args(cf) };
    ecf.trusted_cert = args[1];
    NGX_CONF_OK
}

/// `ssl_certificate <path>` inside `otel_exporter {}` — mTLS client cert path.
/// Cert+key pairing validated in `MainConfig::post_config`.
pub(super) extern "C" fn cmd_exporter_set_ssl_cert(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (`ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.ssl_cert.is_empty() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    ecf.ssl_cert = args[1];
    NGX_CONF_OK
}

/// `ssl_certificate_key <path>` inside `otel_exporter {}` — mTLS client key
/// path; see `cmd_exporter_set_ssl_cert`.
pub(super) extern "C" fn cmd_exporter_set_ssl_cert_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (`ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.ssl_cert_key.is_empty() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    ecf.ssl_cert_key = args[1];
    NGX_CONF_OK
}

/// `ssl_verify on|off` inside `otel_exporter {}`. Default (unset) = on.
/// `off` is INSECURE; a WARN is emitted at `post_config` time.
pub(super) extern "C" fn cmd_exporter_set_ssl_verify(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (`ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if ecf.ssl_verify != UNSET_FLAG {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let val = args[1];
    if val.as_bytes() == b"on" {
        ecf.ssl_verify = 1;
    } else if val.as_bytes() == b"off" {
        ecf.ssl_verify = 0;
    } else {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            cf,
            "otel_exporter: ssl_verify: invalid value \"{}\"; expected on or off",
            val
        );
        return c"invalid ssl_verify value".as_ptr().cast_mut();
    }
    NGX_CONF_OK
}

pub(super) extern "C" fn cmd_exporter_set_metrics_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (an `ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.metrics_endpoint.is_empty() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    warn_if_has_authority(cf, "metrics", args[1].as_bytes());
    ecf.metrics_endpoint = args[1];
    NGX_CONF_OK
}

pub(super) extern "C" fn cmd_exporter_set_logs_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (an `ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.logs_endpoint.is_empty() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    warn_if_has_authority(cf, "logs", args[1].as_bytes());
    ecf.logs_endpoint = args[1];
    NGX_CONF_OK
}

pub(super) extern "C" fn cmd_exporter_set_traces_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (an `ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.traces_endpoint.is_empty() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    warn_if_has_authority(cf, "traces", args[1].as_bytes());
    ecf.traces_endpoint = args[1];
    NGX_CONF_OK
}

/// Validates a header name/value byte pair using the same `hyper` parser as
/// the transport layer, so "accepted at config time" == "accepted at
/// runtime". `Err(true)` = bad name, `Err(false)` = bad value. Pure function,
/// unit-testable without nginx FFI.
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub(super) fn check_header_kv(name: &[u8], value: &[u8]) -> Result<(), bool> {
    if HeaderName::from_bytes(name).is_err() {
        return Err(true); // bad name
    }
    if HeaderValue::from_bytes(value).is_err() {
        return Err(false); // bad value
    }
    Ok(())
}

/// Validates a header name/value pair, logging `NGX_LOG_EMERG` and returning
/// `false` on failure so the caller can return `NGX_CONF_ERROR`.
///
/// # Safety
/// `cf` must be the valid non-null directive parse context.
unsafe fn validate_header_kv(cf: *mut ngx_conf_t, name: &[u8], value: &[u8]) -> bool {
    match check_header_kv(name, value) {
        Ok(()) => true,
        Err(bad_name) => {
            if bad_name {
                // SAFETY: `cf` is a valid non-null parse context for `ngx_conf_log_error!`;
                // the enclosing fn is already `unsafe`.
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "invalid header name: \"{}\"",
                    std::str::from_utf8(name).unwrap_or("<invalid UTF-8>")
                );
            } else {
                // SAFETY: same as above.
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "invalid value for header \"{}\": contains illegal bytes",
                    std::str::from_utf8(name).unwrap_or("<invalid UTF-8>")
                );
            }
            false
        }
    }
}

/// `header <name> <value>` inside `otel_exporter { ... }` — appends to the
/// same `exporter_headers` Vec as the top-level `otel_exporter_header`
/// directive. `conf` is `&amcf.exporter`; the containing `MainConfig` is
/// recovered via its known field offset.
pub(super) extern "C" fn cmd_exporter_block_add_header(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is `ptr::addr_of_mut!(amcf.exporter)` cast to `*mut c_void`
    // (see `cmd_set_exporter_block`). Subtracting `offset_of!(MainConfig, exporter)`
    // yields the start of the enclosing `MainConfig`, which nginx allocated in its
    // conf pool and keeps live for the whole config cycle.
    let amcf = unsafe {
        let ecf_offset = mem::offset_of!(MainConfig, exporter);
        let base = (conf as *mut u8).sub(ecf_offset);
        base.cast::<MainConfig>().as_mut().expect("main config")
    };
    // SAFETY: `cf` is the valid non-null directive parse context (TAKE2 args).
    let args = unsafe { cf_args(cf) };
    // SAFETY: `cf` is the valid non-null parse context; args[1/2] are nginx pool
    // strings whose lifetime covers the whole config cycle.
    if !unsafe { validate_header_kv(cf, args[1].as_bytes(), args[2].as_bytes()) } {
        return NGX_CONF_ERROR;
    }
    amcf.exporter_headers.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

/// `interval <msec>` inside `otel_exporter { ... }` — writes
/// `MainConfig.metric_interval_ms` (same field as `otel_metric_interval`).
/// Accepts the nginx msec grammar (`500ms`, `5s`, `5m`, `2h`, `1d`, bare
/// integer = seconds), matching the C++ `interval` directive
/// (`ngx_conf_set_msec_slot`, cpp:131). `conf` recovered via the same
/// container-of pattern as [`cmd_exporter_block_add_header`].
pub(super) extern "C" fn cmd_exporter_block_set_interval(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: same container-of recovery as `cmd_exporter_block_add_header`.
    let amcf = unsafe {
        let ecf_offset = mem::offset_of!(MainConfig, exporter);
        let base = (conf as *mut u8).sub(ecf_offset);
        base.cast::<MainConfig>().as_mut().expect("main config")
    };

    if amcf.metric_interval_ms != UNSET_U64 {
        return already_set_error();
    }

    // SAFETY: `cf` is the valid non-null directive parse context (TAKE1 arg).
    let args = unsafe { cf_args(cf) };
    match parse_duration_ms(args[1].as_bytes()) {
        Some(ms) if ms > 0 => {
            amcf.metric_interval_ms = ms;
            NGX_CONF_OK
        }
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "invalid time value in \"interval\": \"{}\"",
                args[1]
            );
            NGX_CONF_ERROR
        }
    }
}

/// `batch_size <n>` inside `otel_exporter { ... }` — accepted for C++ config
/// compatibility (nginx size grammar, matches `ngx_conf_set_size_slot`,
/// cpp:137) but ignored: this module uses a fixed-size span ring.
pub(super) extern "C" fn cmd_exporter_block_ignore_batch_size(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf` is the valid non-null directive parse context (TAKE1 arg).
    let args = unsafe { cf_args(cf) };
    if parse_size_bytes(args[1].as_bytes()).is_none() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "invalid size value in \"batch_size\": \"{}\"",
            args[1]
        );
        return NGX_CONF_ERROR;
    }
    ngx_conf_log_error!(
        NGX_LOG_WARN,
        &raw mut *cf,
        "\"batch_size\" is accepted but ignored \
         (this module uses a fixed-size span ring)"
    );
    NGX_CONF_OK
}

/// `batch_count <n>` inside `otel_exporter { ... }` — accepted for C++ config
/// compatibility (nginx size grammar, matches `ngx_conf_set_size_slot`,
/// cpp:143) but ignored: this module uses a fixed retry-buffer depth.
pub(super) extern "C" fn cmd_exporter_block_ignore_batch_count(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf` is the valid non-null directive parse context (TAKE1 arg).
    let args = unsafe { cf_args(cf) };
    if parse_size_bytes(args[1].as_bytes()).is_none() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "invalid size value in \"batch_count\": \"{}\"",
            args[1]
        );
        return NGX_CONF_ERROR;
    }
    ngx_conf_log_error!(
        NGX_LOG_WARN,
        &raw mut *cf,
        "\"batch_count\" is accepted but ignored \
         (this module uses a fixed retry-buffer depth)"
    );
    NGX_CONF_OK
}

/// Dispatcher invoked by `ngx_conf_parse` for each directive inside
/// `otel_exporter { ... }`.
pub(super) extern "C" fn cmd_exporter_block_handler(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _dummy: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf` is the valid non-null block-parse context; its `args` array
    // holds the inner directive's tokens.
    let args = unsafe { cf_args(cf) };

    // SAFETY: `NGX_HTTP_OTEL_EXPORTER_COMMANDS` is a module-private `static mut`
    // touched only during single-threaded config parsing (no concurrent access),
    // so taking a `&mut` slice of it here is sound.
    let commands = unsafe { &mut super::NGX_HTTP_OTEL_EXPORTER_COMMANDS[..] };
    for cmd in commands {
        if cmd.name.is_empty() {
            break;
        }
        if args[0] != cmd.name {
            continue;
        }
        let expected = cmd_nargs(cmd);
        if args.len() < expected.0 || args.len() > expected.1 {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "invalid number of arguments in \"{}\" directive",
                args[0]
            );
            return NGX_CONF_ERROR;
        }
        let handler = cmd.set.expect("command handler");
        // SAFETY: `handler` is a valid directive callback fn pointer; `cf` is the
        // valid parse context, and `(*cf).handler_conf` is the block's conf pointer
        // (set by `cmd_set_exporter_block` to `&amcf.exporter`) that the inner
        // handlers expect.
        return unsafe { handler(cf, cmd, (*cf).handler_conf) };
    }

    ngx_conf_log_error!(
        NGX_LOG_EMERG,
        &raw mut *cf,
        "unknown directive \"{}\" in otel_exporter block",
        args[0]
    );
    NGX_CONF_ERROR
}

// ── Top-level command handlers ─────────────────────────────────────────────────

pub(super) extern "C" fn cmd_set_exporter_block(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: for a MAIN_CONF directive nginx passes the module's `MainConfig`
    // pointer as `conf`; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.exporter.is_set() {
        ngx_conf_log_error!(NGX_LOG_EMERG, &raw mut *cf, "\"otel_exporter\" is duplicate");
        return NGX_CONF_ERROR;
    }

    // SAFETY: `cf` is a valid non-null parse context; `*cf` copies the current
    // `ngx_conf_t` by value to derive a block-scoped parse context.
    let mut block_cf: ngx_conf_t = unsafe { *cf };
    block_cf.handler = Some(cmd_exporter_block_handler);
    block_cf.handler_conf = ptr::addr_of_mut!(amcf.exporter).cast();

    // SAFETY: `block_cf` is a valid in-scope parse context with our block handler
    // installed; `ngx_conf_parse` recurses into the `otel_exporter { ... }` body.
    let rc = unsafe { ngx_conf_parse(&raw mut block_cf, ptr::null_mut()) };
    if !rc.is_null() {
        return rc; // a sub-directive already reported its own error
    }
    // A present block without `endpoint` is a config error, not a silent
    // fallback to disabled mode (nginx idiom: mandatory sub-directive).
    if amcf.exporter.endpoint.as_bytes().is_empty() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "\"endpoint\" is mandatory in the \"otel_exporter\" block"
        );
        return NGX_CONF_ERROR;
    }
    NGX_CONF_OK
}

pub(super) extern "C" fn cmd_add_resource_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE2: name + value).
    let args = unsafe { cf_args(cf) };
    amcf.resource_attrs.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

pub(super) extern "C" fn cmd_add_exporter_header(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE2: name + value).
    let args = unsafe { cf_args(cf) };
    // Validate name and value with the same hyper parser the runtime uses so that
    // "accepted at config time" == "accepted at runtime" (no silent drops).
    // SAFETY: `cf` is the valid non-null parse context; args[1/2] are nginx pool
    // strings whose lifetime covers the whole config cycle.
    if !unsafe { validate_header_kv(cf, args[1].as_bytes(), args[2].as_bytes()) } {
        return NGX_CONF_ERROR;
    }
    amcf.exporter_headers.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

pub(super) extern "C" fn cmd_set_metric_interval(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.metric_interval_ms != UNSET_U64 {
        return already_set_error();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE1: the duration).
    let args = unsafe { cf_args(cf) };
    match parse_duration_ms(args[1].as_bytes()) {
        Some(ms) if ms > 0 => {
            amcf.metric_interval_ms = ms;
            NGX_CONF_OK
        }
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "invalid duration in \"otel_metric_interval\": \"{}\"",
                args[1]
            );
            NGX_CONF_ERROR
        }
    }
}

/// `otel_export_protocol otlp_http | otlp_grpc;`. Rejects `arrow` as "not yet implemented".
pub(super) extern "C" fn cmd_set_export_protocol(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use super::ExportProtocol;
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.export_protocol.is_some() {
        return already_set_error();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE1: the protocol name).
    let args = unsafe { cf_args(cf) };
    let value = args[1].as_bytes();

    if value == b"otlp_http" {
        amcf.export_protocol = Some(ExportProtocol::OtlpHttp);
        NGX_CONF_OK
    } else if value == b"otlp_grpc" {
        amcf.export_protocol = Some(ExportProtocol::OtlpGrpc);
        NGX_CONF_OK
    } else if value == b"arrow" {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_export_protocol: \"arrow\" is not yet implemented"
        );
        NGX_CONF_ERROR
    } else {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_export_protocol: unknown value \"{}\"; valid values: otlp_http, otlp_grpc",
            args[1]
        );
        NGX_CONF_ERROR
    }
}

/// `otel_log_ring_size <size>;` — stores into `MainConfig::log_ring_size`.
/// Test-support only; production always uses the auto-default
/// ([`crate::logs::ring::DEFAULT_LOG_RING_CAP`]) — this override lets
/// integration tests shrink the ring to provoke overflow.
#[cfg(any(test, feature = "test-support"))]
pub(super) extern "C" fn cmd_set_log_ring_size(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.log_ring_size > 0 {
        return already_set_error();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE1: the size).
    let args = unsafe { cf_args(cf) };
    let raw = args[1].as_bytes();

    match parse_size_bytes(raw) {
        Some(n) if n > 0 => {
            // The error-ring header and coalescer table start at multiples of
            // ring_size_bytes(cap); both hold AtomicU64 fields (align 8), so
            // cap must be a multiple of 8. Round up with checked arithmetic
            // (avoids overflow panic near usize::MAX).
            let Some(aligned) = align_ring_size(n) else {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_log_ring_size: invalid size (use e.g. \"512k\" or \"1m\")"
                );
                return NGX_CONF_ERROR;
            };
            if aligned != n {
                ngx_conf_log_error!(
                    NGX_LOG_WARN,
                    &raw mut *cf,
                    "otel_log_ring_size: {} rounded up to {} (must be a multiple of 8 for AtomicU64 alignment in shm)",
                    n,
                    aligned
                );
            }
            amcf.log_ring_size = aligned;
            NGX_CONF_OK
        }
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_log_ring_size: invalid size (use e.g. \"512k\" or \"1m\")"
            );
            NGX_CONF_ERROR
        }
    }
}

/// `otel_error_log [<level>];` — inserts a writer-only `ngx_log_t` node into
/// `cycle->new_log` calling `ngx_otel_error_writer` for errors past the
/// severity floor. NOARGS = fixed `NGX_LOG_ERR` (intentionally decoupled from
/// core `error_log`, whose level is directive-order dependent at parse time);
/// TAKE1 = explicit level override. Errors on duplicate directive.
pub(super) extern "C" fn cmd_set_error_log(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.error_log_enabled {
        ngx_conf_log_error!(NGX_LOG_EMERG, &raw mut *cf, "\"otel_error_log\" is duplicate");
        return NGX_CONF_ERROR;
    }

    // SAFETY: `cf` is the valid non-null parse context nginx passes to the handler.
    let level_floor: ngx_uint_t = match unsafe { parse_error_log_level_floor(cf) } {
        Some(l) => l,
        None => return NGX_CONF_ERROR,
    };

    // ngx_pcalloc zero-initialises both nodes — the correct "unset" defaults.
    // SAFETY: `cf` is the valid non-null parse context; `cf.pool` is nginx's conf
    // pool (null-checked below). `ngx_pcalloc` returns zeroed, suitably-aligned
    // memory of the requested size for `ngx_log_t` / `OtelErrorWriterState`, and
    // the `ngx_conf_log_error!` calls use the same valid `cf`.
    let (new_log, state) = unsafe {
        let pool = (*cf).pool;
        if pool.is_null() {
            ngx_conf_log_error!(NGX_LOG_EMERG, &raw mut *cf, "otel_error_log: null pool");
            return NGX_CONF_ERROR;
        }
        let log_ptr = nginx_sys::ngx_pcalloc(pool, mem::size_of::<nginx_sys::ngx_log_t>())
            as *mut nginx_sys::ngx_log_t;
        if log_ptr.is_null() {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_error_log: ngx_pcalloc failed for log node"
            );
            return NGX_CONF_ERROR;
        }
        let state_ptr = nginx_sys::ngx_pcalloc(pool, mem::size_of::<OtelErrorWriterState>())
            as *mut OtelErrorWriterState;
        if state_ptr.is_null() {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_error_log: ngx_pcalloc failed for writer state"
            );
            return NGX_CONF_ERROR;
        }
        (log_ptr, state_ptr)
    };

    // Writer-only node: no `file` set, so it never writes to a file itself;
    // the core file node still writes via chain continuation.
    // SAFETY: `new_log` and `state` are the non-null, zeroed pool allocations from
    // the block above; writing their fields is sound and they outlive the cycle
    // (conf-pool lifetime).
    unsafe {
        (*new_log).log_level = level_floor;
        (*new_log).writer = Some(ngx_otel_error_writer);
        (*new_log).wdata = state as *mut core::ffi::c_void;
        (*state).level_floor = level_floor;
        // Remaining state fields stay zero/null (correct defaults);
        // coalesce_enabled is set later by init_process, gated on coalesce_table.
    }

    // Insert into cycle->new_log chain (sorted descending by log_level).
    // cycle->new_log is an embedded ngx_log_t value (never null); confirmed:
    // ngx_cycle.h:43-44: `ngx_log_t *log; ngx_log_t new_log;` — `new_log` is a value.
    // SAFETY: `cf` is valid; `cf.cycle` is the live cycle and `new_log` (per
    // ngx_cycle.h) is an embedded `ngx_log_t` value, so `&mut (*cycle).new_log` is
    // a valid chain head for `otel_log_insert`; `new_log` is our valid pool node.
    unsafe {
        let cycle = (*cf).cycle;
        otel_log_insert(ptr::addr_of_mut!((*cycle).new_log), new_log);
    }

    amcf.error_log_enabled = true;
    amcf.error_log_level = level_floor;

    NGX_CONF_OK
}

/// `otel_error_log_coalesce on|off;` — sets `amcf.error_log_coalesce`. Not
/// `ngx_conf_set_flag_slot` because the field is a plain `bool`, not `ngx_flag_t`.
pub(super) extern "C" fn cmd_set_error_log_coalesce(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (FLAG: on|off).
    let args = unsafe { cf_args(cf) };
    let val = args[1].as_bytes();
    match val {
        b"on" => amcf.error_log_coalesce = true,
        b"off" => amcf.error_log_coalesce = false,
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_error_log_coalesce: invalid value; use on or off"
            );
            return NGX_CONF_ERROR;
        }
    }
    NGX_CONF_OK
}

/// `otel_status_endpoint;` (location-level, no args, test-support only) —
/// installs [`crate::otel_status_content_handler`], which returns
/// `control_shm.version` as plain text for the heartbeat integration test.
/// Absent from production `.so` files.
#[cfg(any(test, feature = "test-support"))]
pub(super) extern "C" fn cmd_set_otel_status_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    use ngx::http::{HttpModuleLocationConf, NgxHttpCoreModule};

    // SAFETY: `cf` is the valid non-null directive parse context nginx passes to
    // a LOC_CONF handler; `&*cf` is a sound shared borrow.
    let cf_ref = unsafe { &*cf };
    let clcf = match NgxHttpCoreModule::location_conf_mut(cf_ref) {
        Some(c) => c,
        None => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_status_endpoint: failed to get core location conf"
            );
            return NGX_CONF_ERROR;
        }
    };
    clcf.handler = Some(crate::otel_status_content_handler);
    NGX_CONF_OK
}

// ── Trace directive handlers ──────────────────────────────────────────────────

/// `otel_trace <complex-value>;` — evaluated at request time: truthy
/// (non-empty, not `"0"`/`"off"`) enables tracing. Absent leaves `otel_trace`
/// null — zero cost, no REWRITE handler work.
pub(super) extern "C" fn cmd_set_otel_trace(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::LocationConf;

    // SAFETY: nginx passes our module's `LocationConf*` as `conf` for a
    // `NGX_HTTP_LOC_CONF_OFFSET` directive; the cast + `as_mut` yield a valid
    // exclusive reference.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if !lcf.otel_trace.is_null() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let mut value = args[1]; // ngx_str_t is Copy — we need a mutable local for ccv.value
                             // SAFETY: `cf` is valid; `value` is a local ngx_str_t holding the directive arg.
    let cv = unsafe { compile_complex_value(cf, &raw mut value) };
    if cv.is_null() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_trace: failed to compile complex value expression"
        );
        return NGX_CONF_ERROR;
    }
    lcf.otel_trace = cv;
    NGX_CONF_OK
}

/// `otel_log_export on | off | if=<cond>;` — mirrors core `access_log ... if=`.
/// Bare/`on` = export all; `off` = disabled; `if=<cond>` compiles the
/// remainder as a complex value. Setting any selecting form (`on`/bare/`if=`)
/// flips the main-conf `any_log_export` flag so the logs shm zone is allocated.
pub(super) extern "C" fn cmd_set_otel_log_export(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::{LocationConf, LogExportMode};

    // SAFETY: nginx passes our module's `LocationConf*` as `conf` for a
    // `NGX_HTTP_LOC_CONF_OFFSET` directive; the cast + `as_mut` yield a valid
    // exclusive reference.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if lcf.log_export_is_set() {
        return already_set_error();
    }

    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };

    let mode = if args.len() < 2 {
        LogExportMode::All // bare `otel_log_export;`
    } else {
        let param = args[1].as_bytes();
        if param == b"on" {
            LogExportMode::All
        } else if param == b"off" {
            LogExportMode::Off
        } else if param.len() >= 3 && &param[..3] == b"if=" {
            let cond = &param[3..];
            let mut cond_str = ngx_str_t { len: cond.len(), data: cond.as_ptr().cast_mut() };
            // SAFETY: `cf` is valid; `cond_str` borrows the directive arg bytes,
            // which nginx keeps valid for the duration of the parse (and the
            // compiled complex value copies the script into pool memory).
            let cv = unsafe { compile_complex_value(cf, &raw mut cond_str) };
            if cv.is_null() {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_log_export: failed to compile \"if=\" condition"
                );
                return NGX_CONF_ERROR;
            }
            lcf.log_export_cv = cv;
            LogExportMode::If
        } else {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_log_export: invalid parameter; expected on | off | if=<cond>"
            );
            return NGX_CONF_ERROR;
        }
    };

    lcf.set_log_export_mode(mode);

    // Flip the main-conf flag at parse time: directive callbacks run before
    // postconfiguration, which reads the flag for the zone-allocation decision.
    if matches!(mode, LogExportMode::All | LogExportMode::If) {
        // SAFETY: `cf` is a valid non-null parse context; the shared borrow is
        // sound for reading the module main conf.
        let cf_ref = unsafe { &*cf };
        if let Some(amcf) = HttpOtelModule::main_conf_mut(cf_ref) {
            amcf.any_log_export = true;
        }
    }

    NGX_CONF_OK
}

/// Directive callback for `otel_trace_context ignore|extract|inject|propagate;`.
pub(super) extern "C" fn cmd_set_otel_trace_context(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::{LocationConf, TraceContextMode};

    // SAFETY: nginx passes our `LocationConf*` as `conf`; the cast is valid.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if lcf.trace_context_is_set() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let mode = match args[1].as_bytes() {
        b"ignore" => TraceContextMode::Ignore,
        b"extract" => TraceContextMode::Extract,
        b"inject" => TraceContextMode::Inject,
        b"propagate" => TraceContextMode::Propagate,
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_trace_context: unknown value \"{}\"; valid: ignore, extract, inject, propagate",
                args[1]
            );
            return NGX_CONF_ERROR;
        }
    };
    lcf.set_trace_context(mode);
    NGX_CONF_OK
}

/// `otel_span_name <complex-value>;` — per-location override, evaluated at
/// request time. Absent = built-in `"METHOD route_name"` format.
pub(super) extern "C" fn cmd_set_otel_span_name(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::LocationConf;

    // SAFETY: nginx passes our `LocationConf*` as `conf`; the cast is valid.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if !lcf.span_name_cv.is_null() {
        return already_set_error();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let mut value = args[1]; // ngx_str_t is Copy
                             // SAFETY: `cf` is valid; `value` is a local ngx_str_t copy of the directive arg.
    let cv = unsafe { compile_complex_value(cf, &raw mut value) };
    if cv.is_null() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_span_name: failed to compile complex value expression"
        );
        return NGX_CONF_ERROR;
    }
    lcf.span_name_cv = cv;
    NGX_CONF_OK
}

/// `otel_span_attr <key> <value>;` — appends to this location's span
/// attribute list; no inheritance from parent (mirrors C++ `addSpanAttr`).
pub(super) extern "C" fn cmd_add_otel_span_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::LocationConf;

    // SAFETY: nginx passes our `LocationConf*` as `conf`; the cast is valid.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // TAKE2 tokens: name=args[1], value=args[2].
    let args = unsafe { cf_args(cf) };
    lcf.span_attrs.push((args[1], args[2]));
    NGX_CONF_OK
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns `(min_args, max_args)` expected (including the directive name itself).
pub(super) fn cmd_nargs(cmd: &ngx_command_t) -> (usize, usize) {
    use nginx_sys::{NGX_CONF_FLAG, NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_CONF_TAKE2};
    let t = cmd.type_ as u64;
    if t & (NGX_CONF_NOARGS as u64) != 0 {
        return (1, 1);
    }
    if t & (NGX_CONF_TAKE1 as u64) != 0 {
        return (2, 2);
    }
    if t & (NGX_CONF_TAKE2 as u64) != 0 {
        return (3, 3);
    }
    if t & (NGX_CONF_FLAG as u64) != 0 {
        return (2, 2);
    }
    (1, usize::MAX)
}

/// Directive-handler error string for a directive that appears more than once.
///
/// nginx renders the returned pointer as `"<directive>" is duplicate`.  Centralises
/// the `c"is duplicate"` cast repeated across the duplicate-guard arms of the
/// directive handlers.
#[inline]
pub(super) fn already_set_error() -> *mut c_char {
    c"is duplicate".as_ptr().cast_mut()
}

/// Parses the `otel_error_log` severity floor: TAKE1 = explicit level,
/// NOARGS = `NGX_LOG_ERR` default. `None` (after an `NGX_LOG_EMERG` log) on
/// an unknown level.
///
/// # Safety
/// `cf` must be the valid, non-null parse context nginx passes to the handler.
pub(super) unsafe fn parse_error_log_level_floor(cf: *mut ngx_conf_t) -> Option<ngx_uint_t> {
    // SAFETY: `cf` is the valid non-null parse context. `cf_args(cf)` reads the
    // parsed tokens, and the inner `ngx_conf_log_error!` uses the same valid `cf`.
    unsafe {
        let args = cf_args(cf);
        if args.len() > 1 {
            let level_str = args[1].as_bytes();
            match parse_error_log_level(level_str) {
                Some(l) => Some(l),
                None => {
                    ngx_conf_log_error!(
                        NGX_LOG_EMERG,
                        &raw mut *cf,
                        "otel_error_log: unknown level; use emerg|alert|crit|error|warn|notice|info|debug"
                    );
                    None
                }
            }
        } else {
            // Fixed default, intentionally decoupled from core error_log: mirroring
            // couples the OTel floor to on-box debug verbosity, and a parse-time
            // read of cycle->new_log is directive-order dependent.
            Some(nginx_sys::NGX_LOG_ERR as ngx_uint_t)
        }
    }
}

/// `true` when `value` contains a scheme+authority marker (`://`) that would
/// be silently stripped at export time. Pure predicate, unit-tested by
/// `h2f5_per_signal_endpoint_host_detection`.
pub(crate) fn has_authority(value: &[u8]) -> bool {
    value.windows(3).any(|w| w == b"://")
}

/// Emits a WARN when a per-signal endpoint value includes a scheme/authority:
/// only the path component is used at export time.
fn warn_if_has_authority(cf: *mut ngx_conf_t, signal: &str, value: &[u8]) {
    if has_authority(value) {
        ngx_conf_log_error!(
            NGX_LOG_WARN,
            cf,
            "otel export: {}_endpoint contains a host/scheme — only the path \
             component will be used; host/port from the base endpoint directive \
             is preserved (full multi-endpoint support is not yet implemented)",
            signal
        );
    }
}

/// Compiles a directive argument into a `ngx_http_complex_value_t` on the
/// conf pool. Returns the allocated pointer, or `null_mut()` on allocation or
/// compilation failure (caller must log and return `NGX_CONF_ERROR`).
///
/// # Safety
/// `cf` must be a valid non-null `ngx_conf_t` parse context.
/// `value` must point to the directive's `ngx_str_t` argument for the duration
/// of the call; `ngx_http_compile_complex_value` may modify it temporarily.
pub(super) unsafe fn compile_complex_value(
    cf: *mut ngx_conf_t,
    value: *mut ngx_str_t,
) -> *mut ngx_http_complex_value_t {
    // SAFETY: `cf` is a valid non-null parse context; `(*cf).pool` is the live
    // conf pool nginx manages for config-parse time allocations.
    let cv_ptr =
        unsafe { nginx_sys::ngx_pcalloc((*cf).pool, mem::size_of::<ngx_http_complex_value_t>()) }
            as *mut ngx_http_complex_value_t;
    if cv_ptr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `mem::zeroed()` is valid for `ngx_http_compile_complex_value_t`
    // because it is a `#[repr(C)]` POD struct (all-zero is a valid starting state
    // before filling the mandatory fields below).
    let mut ccv: ngx_http_compile_complex_value_t = unsafe { mem::zeroed() };
    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = cv_ptr;
    // zero/conf_prefix/root_prefix bitfields stay 0 — no special prefix handling.
    // SAFETY: `ccv` is fully initialised; `ngx_http_compile_complex_value` reads
    // the `value` ngx_str_t (possibly modifying it temporarily) and writes into
    // `complex_value` (our pool allocation, valid for the conf lifetime).
    let rc = unsafe { nginx_sys::ngx_http_compile_complex_value(&raw mut ccv) };
    if rc != nginx_sys::NGX_OK as nginx_sys::ngx_int_t {
        return ptr::null_mut();
    }
    cv_ptr
}

#[cfg(test)]
mod tests {
    use super::check_header_kv;

    /// N2: header name/value pair validation uses the same hyper parser as the
    /// runtime, so config-accepted == runtime-accepted (no silent drops).
    ///
    /// Mutation evidence (executed, both halves recorded in commit):
    /// remove the `check_header_kv` call from `cmd_exporter_block_add_header`
    /// (but not `cmd_add_exporter_header`) and call the check directly → the
    /// invalid-name test against `check_header_kv` still PASSES because the pure
    /// function is intact; the directive-level protection would be missing but is
    /// covered by the FFI-level integration test below.  The mutation that matters:
    /// flip `HeaderName::from_bytes(name).is_err()` to `.is_ok()` → the
    /// bad-name cases return `Ok(())` → FAILS.
    #[test]
    fn n2_header_kv_valid_accepted() {
        assert_eq!(check_header_kv(b"x-trace-id", b"abc123"), Ok(()));
        assert_eq!(check_header_kv(b"Authorization", b"Bearer tok"), Ok(()));
        assert_eq!(check_header_kv(b"content-type", b"application/json"), Ok(()));
    }

    #[test]
    fn n2_header_name_with_space_rejected() {
        // A space in the header name is not a valid token character.
        assert!(check_header_kv(b"bad name", b"value").is_err());
        let result = check_header_kv(b"bad name", b"value");
        assert_eq!(result, Err(true), "bad name should produce Err(true)");
    }

    #[test]
    fn n2_header_name_with_colon_rejected() {
        // A colon in the field-name is invalid per RFC 7230.
        let result = check_header_kv(b"a:b", b"value");
        assert_eq!(result, Err(true), "name with colon should produce Err(true)");
    }

    #[test]
    fn n2_header_value_with_control_char_rejected() {
        // An embedded newline in the value is a header-injection vector.
        let result = check_header_kv(b"x-id", b"val\nue");
        assert_eq!(result, Err(false), "value with newline should produce Err(false)");
    }
}
