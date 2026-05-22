// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_char, c_void};
use core::{mem, ptr};

use nginx_sys::{
    ngx_array_t, ngx_command_t, ngx_conf_parse, ngx_conf_t, ngx_flag_t, ngx_module_t, ngx_str_t,
    ngx_uint_t, NGX_CONF_BLOCK, NGX_CONF_FLAG, NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_CONF_TAKE2,
    NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET, NGX_LOG_EMERG,
};
use ngx::core::{Status, NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::http::HttpModuleMainConf;
use ngx::{ngx_conf_log_error, ngx_string};

use crate::shm;
use crate::HttpOtelModule;

/* ─────────────────────────── extension helpers ─────────────────────────────── */

/// Returns the directive arguments from a `ngx_conf_t`.
///
/// # Safety
/// Caller must ensure `cf` is a valid, non-null pointer and that `cf.args`
/// points to an initialized `ngx_array_t` of `ngx_str_t` elements.
unsafe fn cf_args(cf: *const ngx_conf_t) -> &'static [ngx_str_t] {
    let arr: *const ngx_array_t = unsafe { (*cf).args };
    if arr.is_null() {
        return &[];
    }
    unsafe { (*arr).as_slice::<ngx_str_t>() }
}

// Sentinel: ngx_flag_t not yet set by config
const UNSET_FLAG: ngx_flag_t = -1;
// Sentinel: u64 not yet set
const UNSET_U64: u64 = u64::MAX;
// Default export interval: 10 s in milliseconds
const DEFAULT_INTERVAL_MS: u64 = 10_000;
// Default batch size
const DEFAULT_BATCH_SIZE: u64 = 100;
/// Default retry-buffer depth used by [`MainConfig::retry_buffer_depth`].
/// See the spec-inconsistency note on that method.
const DEFAULT_RETRY_BUFFER_DEPTH: usize = 4;

/// Per-worker key-value pair stored in NGINX pool memory.
/// Both key and value are ngx_str_t slices into the configuration file buffer.
#[derive(Clone, Copy, Debug)]
pub struct KvPair {
    pub key: ngx_str_t,
    pub value: ngx_str_t,
}

/// Exporter sub-block configuration.
#[derive(Debug, Default)]
pub struct ExporterConfig {
    /// The OTLP/HTTP endpoint URL.
    /// Accepted schemes: `unix:`, `http://`, `https://`
    pub endpoint: ngx_str_t,
    /// Path to a trusted CA certificate for HTTPS (optional).
    pub trusted_cert: ngx_str_t,
}

impl ExporterConfig {
    pub fn is_set(&self) -> bool {
        !self.endpoint.is_empty()
    }
}

/// Main (http-block) configuration for ngx-otel-rust.
pub struct MainConfig {
    /// Whether `otel_exporter { ... }` was configured.
    pub exporter: ExporterConfig,
    /// `otel_service_name`
    pub service_name: ngx_str_t,
    /// `otel_resource_attr <k> <v>` — accumulated list.
    pub resource_attrs: std::vec::Vec<KvPair>,
    /// `otel_exporter_header <k> <v>` — accumulated list.
    pub exporter_headers: std::vec::Vec<KvPair>,
    /// `otel_metric_interval` — stored in milliseconds; UNSET_U64 until configured.
    pub metric_interval_ms: u64,
    /// `otel_metric_batch_size` — UNSET_U64 until configured.
    pub metric_batch_size: u64,
    /// `otel_metric_zone <name> <size>` — name part.
    pub zone_name: ngx_str_t,
    /// `otel_metric_zone <name> <size>` — size in bytes; 0 = not configured.
    pub zone_size: usize,
    /// `otel_metric_status_code_class on | off`
    /// UNSET_FLAG (-1) = not set (treated as on/default).
    pub status_code_class: ngx_flag_t,
    /// `otel_metric_high_cardinality_attr <attr>` — accumulated list.
    pub high_cardinality_attrs: std::vec::Vec<ngx_str_t>,
    /// The registered shared memory zone (set during postconfiguration).
    pub shm_zone: *mut nginx_sys::ngx_shm_zone_t,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            exporter: ExporterConfig::default(),
            service_name: ngx_str_t::default(),
            resource_attrs: std::vec::Vec::new(),
            exporter_headers: std::vec::Vec::new(),
            metric_interval_ms: UNSET_U64,
            metric_batch_size: UNSET_U64,
            zone_name: ngx_str_t::default(),
            zone_size: 0,
            status_code_class: UNSET_FLAG,
            high_cardinality_attrs: std::vec::Vec::new(),
            shm_zone: ptr::null_mut(),
        }
    }
}

impl MainConfig {
    /// Returns `true` when `otel_exporter { endpoint ... }` was configured.
    pub fn is_configured(&self) -> bool {
        self.exporter.is_set()
    }

    /// Effective export interval.
    pub fn interval_ms(&self) -> u64 {
        if self.metric_interval_ms == UNSET_U64 {
            DEFAULT_INTERVAL_MS
        } else {
            self.metric_interval_ms
        }
    }

    /// Effective batch size (max data points per encoded batch).
    ///
    /// **NOTE — currently unused.** The export loop emits one batch per
    /// interval regardless of size; the directive is reserved for a future
    /// iteration that chunks large collections. Do not remove without
    /// updating the directive table.
    #[allow(dead_code)]
    pub fn batch_size(&self) -> u64 {
        if self.metric_batch_size == UNSET_U64 {
            DEFAULT_BATCH_SIZE
        } else {
            self.metric_batch_size
        }
    }

    /// Maximum number of *unsent* batches the export loop holds in its retry
    /// buffer on send failure. Older entries are evicted oldest-first.
    ///
    /// Distinct from [`batch_size`](Self::batch_size), which is points-per-batch.
    /// The Step 9 spec's claim that "depth from otel_metric_batch_size, default
    /// reasonable 4-8 batches" is internally inconsistent (batch_size defaults
    /// to 100, which would buffer 10k+ points). The "reasonable default" reading
    /// wins here. Currently a constant; promotable to a directive if operators
    /// need to tune it.
    pub fn retry_buffer_depth(&self) -> usize {
        DEFAULT_RETRY_BUFFER_DEPTH
    }

    /// Whether HTTP status code class bucketing is enabled (default: true).
    pub fn status_code_class_enabled(&self) -> bool {
        self.status_code_class != 0 // UNSET_FLAG or 1 → true; explicit 0 → false
    }

    /// Obtain the main config from the previous NGINX cycle (used for SIGHUP reload).
    pub fn old_config<'a>(cf: &mut ngx_conf_t) -> Option<&'a MainConfig> {
        let old_cycle = unsafe { cf.cycle.as_ref()?.old_cycle.as_ref()? };
        if old_cycle.conf_ctx.is_null() {
            return None;
        }
        HttpOtelModule::main_conf(old_cycle)
    }

    /// Validate and finalise the configuration after all directives have been parsed.
    ///
    /// Takes `&mut self` to store the shm zone pointer.
    pub fn postconfiguration(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        if !self.is_configured() {
            // Module loaded but not configured: zero-cost mode.
            return Ok(());
        }

        // Validate endpoint scheme.
        let ep = self.exporter.endpoint.as_bytes();
        let valid_scheme = ep.starts_with(b"unix:")
            || ep.starts_with(b"http://")
            || ep.starts_with(b"https://");

        if !valid_scheme {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel_exporter: \"endpoint\" must start with unix:, http://, or https://"
                );
            }
            return Err(Status::NGX_ERROR);
        }

        // Register the shared memory zone.
        self.register_shm_zone(cf, module)?;

        Ok(())
    }

    /// Register the per-worker shared memory zone with nginx.
    fn register_shm_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        // Determine the number of worker processes from ngx_core_conf_t.
        // ngx_get_conf(cycle->conf_ctx, ngx_core_module) = conf_ctx[ngx_core_module.index]
        // is a void* pointing to ngx_core_conf_t (typed as void*** in the binding).
        let n_workers: usize = unsafe {
            let cycle = (*cf).cycle.as_ref().ok_or(Status::NGX_ERROR)?;
            let core_idx = nginx_sys::ngx_core_module.index as usize;
            // conf_ctx is *mut *mut *mut *mut c_void; indexing gives *mut *mut *mut c_void.
            // The BIT value of that pointer IS the ngx_core_conf_t*.
            let raw_conf: *mut *mut *mut core::ffi::c_void =
                *cycle.conf_ctx.add(core_idx);
            let core_conf: *const nginx_sys::ngx_core_conf_t = raw_conf.cast();
            if core_conf.is_null() {
                1 // fallback
            } else {
                (*core_conf).worker_processes.max(1) as usize
            }
        };

        // Compute required zone size.
        let required_size = shm::zone_size_for(n_workers);

        // Choose a zone name: use the configured name or default.
        let default_name = ngx::ngx_string!("ngx_http_otel_zone");
        let mut zone_name: ngx_str_t = if self.zone_name.is_empty() {
            default_name
        } else {
            self.zone_name
        };

        // Apply the larger of required size and explicitly configured size.
        let zone_size = if self.zone_size > 0 {
            self.zone_size.max(required_size)
        } else {
            required_size
        };

        // Register the zone.
        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel: failed to register shared memory zone"
                );
            }
            return Err(Status::NGX_ERROR);
        };

        // Configure the zone init callback.
        unsafe {
            (*zone).init = Some(shm::otel_shm_zone_init);
            (*zone).data = ptr::from_mut(self).cast();
        }

        self.shm_zone = zone;
        Ok(())
    }

    /// Returns the base address of our WorkerSlots data within the shared memory zone.
    ///
    /// This is `shm.addr + data_offset()` — past the nginx slab-pool header that
    /// `ngx_init_zone_pool` writes at the very start of every shm zone.
    ///
    /// Returns `None` if either:
    /// - `shm_zone` is null (no zone registered — module not configured yet), OR
    /// - `shm_zone.shm.addr` is null (zone declared but not yet mapped — the
    ///   window between `ngx_shared_memory_add` and `ngx_init_zone`).
    pub fn shm_base(&self) -> Option<*mut u8> {
        let zone = unsafe { self.shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        Some(unsafe { addr.cast::<u8>().add(crate::shm::data_offset()) })
    }
}

/* ─────────────────────────── inner exporter block ─────────────────────────── */

/// Commands valid inside `otel_exporter { ... }`.
static mut NGX_HTTP_OTEL_EXPORTER_COMMANDS: [ngx_command_t; 3] = [
    ngx_command_t {
        name: ngx_string!("endpoint"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("trusted_certificate"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_trusted_cert),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

extern "C" fn cmd_exporter_set_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.endpoint.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    ecf.endpoint = args[1];
    NGX_CONF_OK
}

extern "C" fn cmd_exporter_set_trusted_cert(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.trusted_cert.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    ecf.trusted_cert = args[1];
    NGX_CONF_OK
}

/// Dispatcher invoked by ngx_conf_parse for each directive inside the
/// `otel_exporter { ... }` block.
extern "C" fn cmd_exporter_block_handler(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _dummy: *mut c_void,
) -> *mut c_char {
    let args = unsafe { cf_args(cf) };

    let commands = unsafe { &mut NGX_HTTP_OTEL_EXPORTER_COMMANDS[..] };
    for cmd in commands {
        if cmd.name.is_empty() {
            break;
        }
        if args[0] != cmd.name {
            continue;
        }
        let expected = cmd_nargs(cmd);
        if args.len() < expected.0 || args.len() > expected.1 {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid number of arguments in \"{}\" directive",
                    args[0]
                );
            }
            return NGX_CONF_ERROR;
        }
        let handler = cmd.set.expect("command handler");
        return unsafe { handler(cf, cmd, (*cf).handler_conf) };
    }

    unsafe {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &mut *cf,
            "unknown directive \"{}\" in otel_exporter block",
            args[0]
        );
    }
    NGX_CONF_ERROR
}

/* ─────────────────────────── top-level commands ────────────────────────────── */

/// Number of top-level commands + 1 (terminator).
const NCMDS: usize = 10;

pub static mut NGX_HTTP_OTEL_COMMANDS: [ngx_command_t; NCMDS] = [
    // otel_exporter { endpoint ...; trusted_certificate ...; }
    ngx_command_t {
        name: ngx_string!("otel_exporter"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_NOARGS | NGX_CONF_BLOCK) as ngx_uint_t,
        set: Some(cmd_set_exporter_block),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // otel_service_name <name>;
    ngx_command_t {
        name: ngx_string!("otel_service_name"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_str_slot),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: mem::offset_of!(MainConfig, service_name),
        post: ptr::null_mut(),
    },
    // otel_resource_attr <key> <value>;
    ngx_command_t {
        name: ngx_string!("otel_resource_attr"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
        set: Some(cmd_add_resource_attr),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // otel_exporter_header <name> <value>;
    ngx_command_t {
        name: ngx_string!("otel_exporter_header"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
        set: Some(cmd_add_exporter_header),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // otel_metric_interval <duration>;
    ngx_command_t {
        name: ngx_string!("otel_metric_interval"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(cmd_set_metric_interval),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // otel_metric_batch_size <count>;
    ngx_command_t {
        name: ngx_string!("otel_metric_batch_size"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(cmd_set_metric_batch_size),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // otel_metric_zone <name> <size>;
    ngx_command_t {
        name: ngx_string!("otel_metric_zone"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
        set: Some(cmd_set_metric_zone),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // otel_metric_status_code_class on | off;
    ngx_command_t {
        name: ngx_string!("otel_metric_status_code_class"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG) as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_flag_slot),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: mem::offset_of!(MainConfig, status_code_class),
        post: ptr::null_mut(),
    },
    // otel_metric_high_cardinality_attr <attr>;
    ngx_command_t {
        name: ngx_string!("otel_metric_high_cardinality_attr"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(cmd_add_high_cardinality_attr),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    // terminator
    ngx_command_t::empty(),
];

/* ─────────────────────────── command handlers ──────────────────────────────── */

extern "C" fn cmd_set_exporter_block(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.exporter.is_set() {
        unsafe {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &mut *cf,
                "\"otel_exporter\" is duplicate"
            );
        }
        return NGX_CONF_ERROR;
    }

    let mut block_cf: ngx_conf_t = unsafe { *cf };
    block_cf.handler = Some(cmd_exporter_block_handler);
    block_cf.handler_conf = ptr::addr_of_mut!(amcf.exporter).cast();

    unsafe { ngx_conf_parse(&mut block_cf, ptr::null_mut()) }
}

extern "C" fn cmd_add_resource_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    let args = unsafe { cf_args(cf) };
    amcf.resource_attrs.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

extern "C" fn cmd_add_exporter_header(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    let args = unsafe { cf_args(cf) };
    amcf.exporter_headers.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

extern "C" fn cmd_set_metric_interval(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.metric_interval_ms != UNSET_U64 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    match parse_duration_ms(args[1].as_bytes()) {
        Some(ms) if ms > 0 => {
            amcf.metric_interval_ms = ms;
            NGX_CONF_OK
        }
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid duration in \"otel_metric_interval\": \"{}\"",
                    args[1]
                );
            }
            NGX_CONF_ERROR
        }
    }
}

extern "C" fn cmd_set_metric_batch_size(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.metric_batch_size != UNSET_U64 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    match parse_u64_ascii(args[1].as_bytes()) {
        Some(n) if n > 0 => {
            amcf.metric_batch_size = n;
            NGX_CONF_OK
        }
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid value in \"otel_metric_batch_size\": \"{}\"",
                    args[1]
                );
            }
            NGX_CONF_ERROR
        }
    }
}

extern "C" fn cmd_set_metric_zone(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.zone_size > 0 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    // args[1] = name, args[2] = size (e.g. "10m", "1g")
    let size = match parse_size_bytes(args[2].as_bytes()) {
        Some(s) if s > 0 => s,
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid size in \"otel_metric_zone\": \"{}\"",
                    args[2]
                );
            }
            return NGX_CONF_ERROR;
        }
    };

    amcf.zone_name = args[1];
    amcf.zone_size = size;
    NGX_CONF_OK
}

extern "C" fn cmd_add_high_cardinality_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    let args = unsafe { cf_args(cf) };

    let attr = args[1];
    let valid = attr.as_bytes() == b"url.path"
        || attr.as_bytes() == b"client.address"
        || attr.as_bytes() == b"user_agent.original";

    if !valid {
        unsafe {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &mut *cf,
                "unknown high-cardinality attr \"{}\"; valid values: url.path, client.address, user_agent.original",
                attr
            );
        }
        return NGX_CONF_ERROR;
    }

    amcf.high_cardinality_attrs.push(attr);
    NGX_CONF_OK
}

/* ─────────────────────────── helpers ───────────────────────────────────────── */

/// Returns `(min_args, max_args)` expected (including the directive name itself).
fn cmd_nargs(cmd: &ngx_command_t) -> (usize, usize) {
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

/// Parse duration strings like `10s`, `5m`, `2h`, `1d` → milliseconds.
fn parse_duration_ms(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (num_bytes, suffix) = match s.last() {
        Some(b's') => (&s[..s.len() - 1], 1_000u64),
        Some(b'm') => (&s[..s.len() - 1], 60_000u64),
        Some(b'h') => (&s[..s.len() - 1], 3_600_000u64),
        Some(b'd') => (&s[..s.len() - 1], 86_400_000u64),
        _ => (s, 1_000u64), // bare number treated as seconds
    };
    let n = parse_u64_ascii(num_bytes)?;
    n.checked_mul(suffix)
}

/// Parse a size string like `1024`, `10k`, `5m`, `2g` → bytes.
fn parse_size_bytes(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let (num_bytes, mult) = match s.last() {
        Some(&c) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_lowercase() {
                b'k' => 1024usize,
                b'm' => 1024 * 1024,
                b'g' => 1024 * 1024 * 1024,
                _ => return None,
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1usize),
    };
    let n = parse_u64_ascii(num_bytes)?;
    (n as usize).checked_mul(mult)
}

/// Parse a decimal ASCII string → u64.
fn parse_u64_ascii(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_ms() {
        assert_eq!(parse_duration_ms(b"10s"), Some(10_000));
        assert_eq!(parse_duration_ms(b"5m"), Some(300_000));
        assert_eq!(parse_duration_ms(b"2h"), Some(7_200_000));
        assert_eq!(parse_duration_ms(b"1d"), Some(86_400_000));
        assert_eq!(parse_duration_ms(b"0s"), Some(0));
        assert_eq!(parse_duration_ms(b""), None);
        assert_eq!(parse_duration_ms(b"abc"), None);
    }

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size_bytes(b"1024"), Some(1024));
        assert_eq!(parse_size_bytes(b"10k"), Some(10 * 1024));
        assert_eq!(parse_size_bytes(b"5m"), Some(5 * 1024 * 1024));
        assert_eq!(parse_size_bytes(b"2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_bytes(b""), None);
    }

    #[test]
    fn test_default_config() {
        let cfg = MainConfig::default();
        assert!(!cfg.is_configured());
        assert_eq!(cfg.interval_ms(), DEFAULT_INTERVAL_MS);
        assert_eq!(cfg.batch_size(), DEFAULT_BATCH_SIZE);
        assert!(cfg.status_code_class_enabled()); // UNSET treated as on
    }
}
