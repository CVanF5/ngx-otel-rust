// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Generated code for the local Echo bidi-streaming proto.
//!
//! Phase 1.2 Item 2 mechanical exercise of the gRPC bridge.  The proto
//! is a throwaway local definition; Phase 5 will replace it with OTAP's
//! `arrow_service.proto` when that protocol firms up.

pub mod ngx_otel_echo_v1 {
    // This file includes the CLIENT-ONLY generated code for the echo proto.
    // The server stub is generated separately (to OUT_DIR/echo_server_gen/)
    // and used only from examples/bidi_echo_server.rs, which is a full-std
    // binary.  See build.rs for the rationale (the server stub uses bare
    // Box::pin which isn't in scope in a no_std crate).
    include!(concat!(env!("OUT_DIR"), "/ngx.otel.echo.v1.rs"));
}
