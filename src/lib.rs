// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

#![no_std]
extern crate std;

use core::ptr;

use nginx_sys::{ngx_conf_t, ngx_http_module_t, ngx_module_t, ngx_uint_t, NGX_HTTP_MODULE};
use ngx::core::Status;
use ngx::http::{HttpModule, HttpModuleMainConf};

mod config;
mod data_model;
mod encoder;
mod export;
mod metric_source;
mod shm;
mod transport;

#[derive(Debug)]
struct HttpOtelModule;

static NGX_HTTP_OTEL_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(HttpOtelModule::postconfiguration),
    create_main_conf: Some(HttpOtelModule::create_main_conf),
    init_main_conf: Some(HttpOtelModule::init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: None,
    merge_loc_conf: None,
};

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_otel_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_otel_module: ngx_module_t = ngx_module_t {
    ctx: ptr::addr_of!(NGX_HTTP_OTEL_MODULE_CTX).cast_mut().cast(),
    commands: ptr::null_mut(),
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    ..ngx_module_t::default()
};

unsafe impl HttpModuleMainConf for HttpOtelModule {
    type MainConf = config::MainConfig;
}

impl HttpModule for HttpOtelModule {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_otel_module) }
    }

    unsafe extern "C" fn postconfiguration(_cf: *mut ngx_conf_t) -> nginx_sys::ngx_int_t {
        // Stub: just return OK for now.
        // Step 2+ will populate this.
        Status::NGX_OK.into()
    }
}
