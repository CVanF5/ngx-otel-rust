/*
 * Copyright (c) F5, Inc.
 *
 * This source code is licensed under the Apache License, Version 2.0 license
 * found in the LICENSE file in the root directory of this source tree.
 *
 * ngx_otel_ssl_shim.c — module-side C accessors for the http_ssl module's
 * per-server configuration and for full leaf-certificate enumeration on an
 * `SSL_CTX` (TLS cert-metrics Phase C, item C2).
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * 1. `ngx_http_ssl_srv_conf_t` dereferencing stays on the C side BY DECISION
 *    OF RECORD (C1 review advisory, adopted 2026-06-12).  The C1 premise
 *    correction found the struct IS emitted in the regenerated bindings (it
 *    carries zero bitfields), but after the `ngx_http_request_t` bindgen
 *    bitfield mis-layout episode (see `ngx_otel_bitfield_shim.c` in this
 *    directory) the policy is: dereference nginx structs of this class in C
 *    compiled against the REAL nginx headers — immune to bindgen layout-class
 *    bugs by construction — and use the bindings presence only to type-check
 *    the shim signatures from the Rust side.
 *
 * 2. Full certificate enumeration requires the REAL OpenSSL macros
 *    `SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST / SSL_CERT_SET_NEXT)`
 *    (decision Q5).  These are `SSL_CTX_ctrl` macro wrappers that exist only
 *    in the C headers; hand-copying their ctrl codes into Rust would silently
 *    rot if OpenSSL ever renumbered them.  The macro use lives here, where the
 *    system <openssl/ssl.h> owns the definitions.
 *
 * CONCURRENCY / LIFECYCLE NOTE
 * ----------------------------
 * `ngx_otel_foreach_ctx_cert` MUTATES the SSL_CTX's current-certificate
 * cursor while iterating (that is how the OpenSSL API works).  It restores
 * the cursor to FIRST before returning.  This is safe ONLY because it runs at
 * configuration time, in the single-threaded master process, BEFORE workers
 * fork and before any TLS handshake can touch the context.  It must NEVER be
 * called on a live serving context under traffic.
 *
 * This is a module-side .c (compiled by build.rs via the `cc` crate against
 * the same nginx headers and -D defines nginx-sys used), NOT a change to the
 * frozen ngx-rust fork.
 *
 * RULE FOR FUTURE MAINTAINERS
 * ---------------------------
 * Any NEW field read of `ngx_http_ssl_srv_conf_t` (or another ssl-module
 * struct) MUST be added as an accessor here, not as a Rust-side bindings
 * dereference.  Exception, also of record: `ngx_ssl_t` itself (`ssl->ctx`,
 * `ssl->certs`) is a core-event struct with no bitfields whose bindgen layout
 * was explicitly verified in C1 (`tests/RESULTS-c1-bindings-2026-06-12.txt`);
 * the Rust side reads those two fields through the bindings.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HTTP_SSL)

#include <ngx_http_ssl_module.h>

/*
 * Return &conf->ssl for the server's `ngx_http_ssl_srv_conf_t`.
 *
 * `ssl_srv_conf` is the pointer found in the server's
 * `ctx->srv_conf[ngx_http_ssl_module.ctx_index]` slot, passed as void* so the
 * Rust caller never dereferences the srv-conf struct itself.  Returns NULL
 * for a NULL input.  The returned `ngx_ssl_t` is embedded in the srv conf
 * (conf-pool memory, valid for the cycle lifetime).
 */
ngx_ssl_t *
ngx_otel_srv_ssl(void *ssl_srv_conf)
{
    if (ssl_srv_conf == NULL) {
        return NULL;
    }

    return &((ngx_http_ssl_srv_conf_t *) ssl_srv_conf)->ssl;
}

/*
 * Return conf->certificates — the `ngx_array_t` of `ngx_str_t` cert file
 * paths exactly as configured by the `ssl_certificate` directive(s).
 * May be NULL (no `ssl_certificate` in this server block).
 */
ngx_array_t *
ngx_otel_srv_ssl_certificates(void *ssl_srv_conf)
{
    if (ssl_srv_conf == NULL) {
        return NULL;
    }

    return ((ngx_http_ssl_srv_conf_t *) ssl_srv_conf)->certificates;
}

/*
 * Resolve a config-order index for `cert` within `ssl->certs`.
 *
 * `ssl->certs` is the `ngx_array_t` of `X509 *` that nginx populates in
 * `ssl_certificate` directive order (ngx_event_openssl.c, ngx_ssl_certificate)
 * — 1:1 with the path list returned by ngx_otel_srv_ssl_certificates().  We
 * cannot match by pointer identity: SSL_CTX_get0_certificate() (used by the
 * enumeration below) returns OpenSSL's internal X509 object, a DIFFERENT
 * pointer than the one nginx cached in ssl->certs.  Instead we match by cert
 * IDENTITY using X509_cmp(3), which compares the certificates' canonical DER
 * encodings and therefore matches the same logical cert across the two
 * distinct X509 objects.
 *
 * This is required because the enumeration cursor is NOT in config order: the
 * SSL_CTX current-cert cursor walks certs by key-type slot (ssl/ssl_cert.c
 * ssl_cert_set_current() iterates c->pkeys[i] by SSL_PKEY_RSA, RSA_PSS, DSA,
 * SSL_PKEY_ECC, ... slot index), so for a dual-cert block listed
 * ECDSA-before-RSA the cursor still yields RSA first.  Mapping the enumeration
 * position directly onto the config-order path list would mislabel the paths.
 *
 * Returns the 0-based config index of the matching cert, or -1 if `ssl`/`cert`
 * is NULL, ssl->certs is empty, or no loaded cert matches.
 */
int
ngx_otel_cert_config_index(ngx_ssl_t *ssl, X509 *cert)
{
    ngx_uint_t   j;
    X509       **loaded;

    if (ssl == NULL || cert == NULL || ssl->certs.nelts == 0
        || ssl->certs.elts == NULL)
    {
        return -1;
    }

    loaded = ssl->certs.elts;

    for (j = 0; j < ssl->certs.nelts; j++) {
        if (loaded[j] != NULL && X509_cmp(cert, loaded[j]) == 0) {
            return (int) j;
        }
    }

    return -1;
}

/*
 * Enumerate EVERY leaf certificate installed in `ctx` (one per key-exchange
 * slot: RSA, ECDSA, Ed25519, ... — decision Q5: dual-cert blocks must yield
 * BOTH certs), invoking `cb(cert, data)` for each.
 *
 * Iteration protocol is OpenSSL's own cursor API:
 *   SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST), then
 *   SSL_CTX_get0_certificate + SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT)
 * until SET_NEXT reports no further certificate.
 *
 * The certificates are borrowed (get0): the callback must NOT free them and
 * must not stash the pointer beyond config time.
 *
 * `cb` returns 0 to continue, non-zero to stop early.
 *
 * Returns the number of certificates visited (0 for a NULL or cert-less ctx).
 * The current-cert cursor is restored to FIRST before returning — but see the
 * header comment: config-time, single-threaded master use ONLY.
 */
int
ngx_otel_foreach_ctx_cert(SSL_CTX *ctx, int (*cb)(X509 *cert, void *data),
    void *data)
{
    int    visited;
    X509  *cert;

    if (ctx == NULL || cb == NULL) {
        return 0;
    }

    visited = 0;

    if (SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST) == 0) {
        return 0;
    }

    for ( ;; ) {
        cert = SSL_CTX_get0_certificate(ctx);

        if (cert == NULL) {
            break;
        }

        visited++;

        if (cb(cert, data) != 0) {
            break;
        }

        if (SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT) == 0) {
            break;
        }
    }

    /* restore the cursor so the ctx is left in its initial state */
    (void) SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);

    return visited;
}

#else  /* !NGX_HTTP_SSL */

/*
 * Stub variants so the module links against an nginx source tree configured
 * WITHOUT --with-http_ssl_module.  (Our reference build enables the flag —
 * C1 — but the shim must not be the thing that breaks a no-ssl build.)
 * The Rust caller additionally gates on the ssl module's presence in
 * cycle->modules at runtime, so these stubs are belt-and-braces.
 */

void *
ngx_otel_srv_ssl(void *ssl_srv_conf)
{
    (void) ssl_srv_conf;
    return NULL;
}

ngx_array_t *
ngx_otel_srv_ssl_certificates(void *ssl_srv_conf)
{
    (void) ssl_srv_conf;
    return NULL;
}

int
ngx_otel_cert_config_index(void *ssl, void *cert)
{
    (void) ssl;
    (void) cert;
    return -1;
}

int
ngx_otel_foreach_ctx_cert(void *ctx, int (*cb)(void *cert, void *data),
    void *data)
{
    (void) ctx;
    (void) cb;
    (void) data;
    return 0;
}

#endif  /* NGX_HTTP_SSL */
