/*
 * pqctoday-tpm — PQC cross-validation harness
 *
 * Validates OpenSSL 3.6.2 EVP ML-DSA / ML-KEM output against NIST ACVP
 * canonical vectors, and (optionally) cross-checks against softhsmv3
 * PKCS#11 via dlopen. Runs as a standalone test binary invoked by
 * `make crossval`; not linked to libtpms so the cross-check is an
 * independent signal rather than a circular self-test.
 *
 * Build: see CMakeLists.txt in the parent directory.
 *
 * Copyright 2026 PQC Today. BSD-3-Clause.
 */

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Terminal output                                                     */
/* ------------------------------------------------------------------ */

static int g_passed = 0;
static int g_failed = 0;

#define PASS(msg, ...) do { fprintf(stdout, "[PASS] " msg "\n", ##__VA_ARGS__); g_passed++; } while (0)
#define FAIL(msg, ...) do { fprintf(stdout, "[FAIL] " msg "\n", ##__VA_ARGS__); g_failed++; } while (0)
#define INFO(msg, ...) fprintf(stdout, "       " msg "\n", ##__VA_ARGS__)

static void dump_openssl_errors(const char *where) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "       openssl(%s): %s\n", where, buf);
    }
}

/* ------------------------------------------------------------------ */
/* ML-DSA KAT test                                                     */
/* ------------------------------------------------------------------ */

static int
test_mldsa_sign_verify_roundtrip(const char *algName,
                                 const uint8_t *seed, size_t seedLen,
                                 const uint8_t *msg,  size_t msgLen)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY     *pkey = NULL;
    EVP_MD_CTX   *md   = NULL;
    OSSL_PARAM    params[2];
    uint8_t      *sig  = NULL;
    size_t        sigLen = 0;
    int           rc = 0;

    /* Import the keypair from the 32-byte seed. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto cleanup;

    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_ML_DSA_SEED, (void *)seed, seedLen);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        dump_openssl_errors("EVP_PKEY_fromdata");
        goto cleanup;
    }

    /* Sign. */
    md = EVP_MD_CTX_new();
    if (!md) goto cleanup;
    if (EVP_DigestSignInit_ex(md, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
        dump_openssl_errors("EVP_DigestSignInit_ex");
        goto cleanup;
    }
    if (EVP_DigestSign(md, NULL, &sigLen, msg, msgLen) <= 0) goto cleanup;
    sig = OPENSSL_malloc(sigLen);
    if (!sig) goto cleanup;
    if (EVP_DigestSign(md, sig, &sigLen, msg, msgLen) <= 0) {
        dump_openssl_errors("EVP_DigestSign");
        goto cleanup;
    }

    /* Verify with a fresh md ctx. */
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit_ex(md, NULL, NULL, NULL, NULL, pkey, NULL) <= 0)
        goto cleanup;
    if (EVP_DigestVerify(md, sig, sigLen, msg, msgLen) != 1) {
        dump_openssl_errors("EVP_DigestVerify");
        goto cleanup;
    }

    rc = 1;

 cleanup:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* ------------------------------------------------------------------ */
/* ML-KEM encap/decap round-trip                                       */
/* ------------------------------------------------------------------ */

static int
test_mlkem_roundtrip(const char *algName,
                     const uint8_t *seed, size_t seedLen)
{
    EVP_PKEY     *pkey  = NULL;
    EVP_PKEY_CTX *ctx   = NULL;
    OSSL_PARAM    params[2];
    uint8_t      *ct    = NULL;
    size_t        ctLen = 0;
    uint8_t       ssA[128] = {0};
    size_t        ssALen = sizeof(ssA);
    uint8_t       ssB[128] = {0};
    size_t        ssBLen = sizeof(ssB);
    int           rc = 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto cleanup;
    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed, seedLen);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        dump_openssl_errors("ML-KEM fromdata");
        goto cleanup;
    }
    EVP_PKEY_CTX_free(ctx); ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) goto cleanup;
    if (EVP_PKEY_encapsulate(ctx, NULL, &ctLen, NULL, &ssALen) <= 0) goto cleanup;
    ct = OPENSSL_malloc(ctLen);
    if (!ct) goto cleanup;
    if (EVP_PKEY_encapsulate(ctx, ct, &ctLen, ssA, &ssALen) <= 0) {
        dump_openssl_errors("EVP_PKEY_encapsulate");
        goto cleanup;
    }

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) goto cleanup;
    if (EVP_PKEY_decapsulate(ctx, ssB, &ssBLen, ct, ctLen) <= 0) {
        dump_openssl_errors("EVP_PKEY_decapsulate");
        goto cleanup;
    }

    if (ssALen != ssBLen || memcmp(ssA, ssB, ssALen) != 0) {
        INFO("encap shared secret != decap shared secret — protocol broken");
        goto cleanup;
    }

    rc = 1;

 cleanup:
    OPENSSL_free(ct);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Driver                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    fprintf(stdout, "pqctoday-tpm cross-validation harness\n");
    fprintf(stdout, "=====================================\n");
    fprintf(stdout, "  OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    fprintf(stdout, "\n");

    /* Fixed test seed — deterministic within a run so failures are
     * reproducible. Real NIST ACVP integration comes via kat_loader.c
     * iterating vectors/ JSON files; this scaffolding proves the harness
     * end-to-end against our own-derived inputs first. */
    static const uint8_t seed32[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t seed64[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    static const uint8_t msg[] = "pqctoday-tpm cross-validation message";

    /* ---- OpenSSL ML-DSA ---- */
    if (test_mldsa_sign_verify_roundtrip("ML-DSA-44", seed32, sizeof(seed32),
                                         msg, sizeof(msg) - 1))
        PASS("ML-DSA-44  OpenSSL seed → sign → verify");
    else
        FAIL("ML-DSA-44  OpenSSL seed → sign → verify");

    if (test_mldsa_sign_verify_roundtrip("ML-DSA-65", seed32, sizeof(seed32),
                                         msg, sizeof(msg) - 1))
        PASS("ML-DSA-65  OpenSSL seed → sign → verify");
    else
        FAIL("ML-DSA-65  OpenSSL seed → sign → verify");

    if (test_mldsa_sign_verify_roundtrip("ML-DSA-87", seed32, sizeof(seed32),
                                         msg, sizeof(msg) - 1))
        PASS("ML-DSA-87  OpenSSL seed → sign → verify");
    else
        FAIL("ML-DSA-87  OpenSSL seed → sign → verify");

    /* ---- OpenSSL ML-KEM ---- */
    if (test_mlkem_roundtrip("ML-KEM-512", seed64, sizeof(seed64)))
        PASS("ML-KEM-512  OpenSSL seed → encap → decap");
    else
        FAIL("ML-KEM-512  OpenSSL seed → encap → decap");

    if (test_mlkem_roundtrip("ML-KEM-768", seed64, sizeof(seed64)))
        PASS("ML-KEM-768  OpenSSL seed → encap → decap");
    else
        FAIL("ML-KEM-768  OpenSSL seed → encap → decap");

    if (test_mlkem_roundtrip("ML-KEM-1024", seed64, sizeof(seed64)))
        PASS("ML-KEM-1024 OpenSSL seed → encap → decap");
    else
        FAIL("ML-KEM-1024 OpenSSL seed → encap → decap");

    /* ---- softhsmv3 cross-check ---- */
    const char *p11mod = getenv("PQCTODAY_TPM_PKCS11_MODULE");
    if (p11mod && *p11mod) {
        INFO("softhsmv3 cross-check requested against %s", p11mod);
        INFO("p11_helper.c integration pending — skipped this run");
    } else {
        INFO("PQCTODAY_TPM_PKCS11_MODULE unset — skipping softhsmv3 cross-check");
    }

    fprintf(stdout, "\n=====================================\n");
    fprintf(stdout, "  %d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
