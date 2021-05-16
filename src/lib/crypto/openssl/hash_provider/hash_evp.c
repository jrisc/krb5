/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/hash_provider/hash_evp.c - OpenSSL hash providers */
/*
 * Copyright (C) 2015 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "crypto_int.h"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <threads.h>

typedef struct ossl_lib_md_context {
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *legacy_provider;
    EVP_MD *md;
} ossl_md_context_t;

static thread_local ossl_md_context_t *ossl_md_ctx = NULL;

static krb5_error_code
init_ossl_md_ctx(ossl_md_context_t *ctx, const char *algo)
{
    ctx->libctx = OSSL_LIB_CTX_new();
    if (!ctx->libctx)
        return KRB5_CRYPTO_INTERNAL;

    /*
     * Load both legacy and default provider as both may be needed.
     * If they fail keep going and an error will be raised when we try to
     * fetch the cipher later.
     */
    ctx->legacy_provider = OSSL_PROVIDER_load(ctx->libctx, "legacy");

    ctx->md = EVP_MD_fetch(ctx->libctx, algo, NULL);
    if (!ctx->md)
        return KRB5_CRYPTO_INTERNAL;

    return 0;
}

static void
deinit_ossl_ctx(ossl_md_context_t *ctx)
{
    if (ctx->md)
        EVP_MD_free(ctx->md);

    if (ctx->legacy_provider)
        OSSL_PROVIDER_unload(ctx->legacy_provider);

    if (ctx->libctx)
        OSSL_LIB_CTX_free(ctx->libctx);
}

static krb5_error_code
hash_evp(const EVP_MD *type, const krb5_crypto_iov *data, size_t num_data,
         krb5_data *output)
{
    EVP_MD_CTX *ctx;
    const krb5_data *d;
    size_t i;
    int ok;
    krb5_error_code ret;

    ret = krb5int_crypto_init();
    if (ret)
        return ret;

    if (output->length != (unsigned int)EVP_MD_size(type))
        return KRB5_CRYPTO_INTERNAL;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return ENOMEM;

    ok = EVP_DigestInit_ex(ctx, type, NULL);
    for (i = 0; i < num_data; i++) {
        if (!SIGN_IOV(&data[i]))
            continue;
        d = &data[i].data;
        ok = ok && EVP_DigestUpdate(ctx, d->data, d->length);
    }
    ok = ok && EVP_DigestFinal_ex(ctx, (uint8_t *)output->data, NULL);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : KRB5_CRYPTO_INTERNAL;
}

static krb5_error_code
hash_legacy_evp(const char *algo, const krb5_crypto_iov *data, size_t num_data,
                krb5_data *output)
{
    krb5_error_code err;

    if (!ossl_md_ctx) {
        ossl_md_ctx = malloc(sizeof(ossl_md_context_t));
        if (!ossl_md_ctx)
            return ENOMEM;

        err = init_ossl_md_ctx(ossl_md_ctx, algo);
        if (err) {
            deinit_ossl_ctx(ossl_md_ctx);
            free(ossl_md_ctx);
            ossl_md_ctx = NULL;
            goto end;
        }
    }

    err = hash_evp(ossl_md_ctx->md, data, num_data, output);

end:
    return err;
}

static krb5_error_code
hash_md4(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    /*
     * MD4 is needed in FIPS mode to perform key generation for RC4 keys used
     * by IPA.  These keys are only used along a (separately) secured channel
     * for legacy reasons when performing trusts to Active Directory.
     */
    return FIPS_mode() ? hash_legacy_evp("MD4", data, num_data, output)
                       : hash_evp(EVP_md4(), data, num_data, output);
}

static krb5_error_code
hash_md5(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    /*
     * MD5 is needed in FIPS mode for communication with RADIUS servers.  This
     * is gated in libkrad by libdefaults->radius_md5_fips_override.
     */
    return FIPS_mode() ? hash_legacy_evp("MD5", data, num_data, output)
                       : hash_evp(EVP_md5(), data, num_data, output);
}

static krb5_error_code
hash_sha1(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    return hash_evp(EVP_sha1(), data, num_data, output);
}

static krb5_error_code
hash_sha256(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    return hash_evp(EVP_sha256(), data, num_data, output);
}

static krb5_error_code
hash_sha384(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    return hash_evp(EVP_sha384(), data, num_data, output);
}

const struct krb5_hash_provider krb5int_hash_md4 = {
    "MD4", 16, 64, hash_md4
};

const struct krb5_hash_provider krb5int_hash_md5 = {
    "MD5", 16, 64, hash_md5
};

const struct krb5_hash_provider krb5int_hash_sha1 = {
    "SHA1", 20, 64, hash_sha1
};

const struct krb5_hash_provider krb5int_hash_sha256 = {
    "SHA-256", 32, 64, hash_sha256
};

const struct krb5_hash_provider krb5int_hash_sha384 = {
    "SHA-384", 48, 128, hash_sha384
};
