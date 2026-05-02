/********************************************************************************/
/*										*/
/*		   ML-DSA (FIPS 204) implementation for libtpms			*/
/*		Written for pqctoday-tpm (Copyright 2026 PQC Today)		*/
/*										*/
/*  BSD-3-Clause clean-room implementation against OpenSSL 3.6+ EVP.		*/
/*  The ML-DSA algorithm is covered by NIST FIPS 204 (August 2024).		*/
/*  The TPM 2.0 surface is defined by TCG Library Specification V1.85 RC4	*/
/*  (December 2025), Part 2 §15 (ML-DSA) and the TPM_ALG_MLDSA /		*/
/*  TPM_ALG_HASH_MLDSA algorithm IDs added to the registry.			*/
/*										*/
/*  Private key storage: per V1.85 Part 2 TPM2B_PRIVATE_KEY_MLDSA, we store	*/
/*  only the 32-byte seed ξ. OpenSSL 3.5+ ML-DSA provider accepts "seed" as	*/
/*  an import parameter and reconstructs the expanded private key on demand.	*/
/*										*/
/********************************************************************************/

#include "Tpm.h"

#if ALG_MLDSA || ALG_HASH_MLDSA

#include "CryptMlDsa_fp.h"

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Parameter-set dispatch helpers                                           */
/* ------------------------------------------------------------------------ */

LIB_EXPORT const char *
CryptMlDsaAlgName(TPMI_MLDSA_PARAMETER_SET paramSet)
{
    switch (paramSet) {
        case TPM_MLDSA_44: return "ML-DSA-44";
        case TPM_MLDSA_65: return "ML-DSA-65";
        case TPM_MLDSA_87: return "ML-DSA-87";
        default:           return NULL;
    }
}

LIB_EXPORT UINT16
CryptMlDsaPubKeySize(TPMI_MLDSA_PARAMETER_SET paramSet)
{
    switch (paramSet) {
        case TPM_MLDSA_44: return MLDSA_44_PUBLIC_KEY_SIZE;  /* 1312 */
        case TPM_MLDSA_65: return MLDSA_65_PUBLIC_KEY_SIZE;  /* 1952 */
        case TPM_MLDSA_87: return MLDSA_87_PUBLIC_KEY_SIZE;  /* 2592 */
        default:           return 0;
    }
}

LIB_EXPORT UINT16
CryptMlDsaSigSize(TPMI_MLDSA_PARAMETER_SET paramSet)
{
    switch (paramSet) {
        case TPM_MLDSA_44: return MLDSA_44_SIGNATURE_SIZE;   /* 2420 */
        case TPM_MLDSA_65: return MLDSA_65_SIGNATURE_SIZE;   /* 3309 */
        case TPM_MLDSA_87: return MLDSA_87_SIGNATURE_SIZE;   /* 4627 */
        default:           return 0;
    }
}

/* Pull the parameter set from a TPMT_PUBLIC for either alg ID. */
static TPMI_MLDSA_PARAMETER_SET
GetParamSet(const TPMT_PUBLIC *publicArea)
{
#if ALG_MLDSA
    if (publicArea->type == TPM_ALG_MLDSA)
        return publicArea->parameters.mldsaDetail.parameterSet;
#endif
#if ALG_HASH_MLDSA
    if (publicArea->type == TPM_ALG_HASH_MLDSA)
        return publicArea->parameters.hashMldsaDetail.parameterSet;
#endif
    return TPM_MLDSA_NONE;
}

/* Map a TPM hash alg to the OpenSSL ML-DSA pre-hash instance string.
 * Returns NULL if not a valid HashML-DSA variant. */
#if ALG_HASH_MLDSA
static const char *
HashMlDsaInstance(TPMI_MLDSA_PARAMETER_SET paramSet, TPMI_ALG_HASH hashAlg)
{
    const char *ps = CryptMlDsaAlgName(paramSet);
    if (ps == NULL) return NULL;
    /* The instance string pattern: "{ML-DSA-XX}-with-{HASH}" */
    static char buf[48];
    const char *hash = NULL;
    switch (hashAlg) {
        case TPM_ALG_SHA256:   hash = "SHA256";   break;
        case TPM_ALG_SHA384:   hash = "SHA384";   break;
        case TPM_ALG_SHA512:   hash = "SHA512";   break;
        case TPM_ALG_SHA3_256: hash = "SHA3-256"; break;
        case TPM_ALG_SHA3_384: hash = "SHA3-384"; break;
        case TPM_ALG_SHA3_512: hash = "SHA3-512"; break;
        default:               return NULL;
    }
    /* "ML-DSA-65-with-SHA512" fits easily in buf[48]. */
    snprintf(buf, sizeof(buf), "%s-with-%s", ps, hash);
    return buf;
}
#endif

/* ------------------------------------------------------------------------ */
/* Key construction helpers (seed → EVP_PKEY round-trip)                    */
/* ------------------------------------------------------------------------ */

/* Build an EVP_PKEY for ML-DSA from a 32-byte seed. Caller frees.
 *
 * Per FIPS 204 §7.1, ML-DSA.KeyGen is fully determined by the 32-byte seed ξ.
 * OpenSSL 3.6 accepts OSSL_PKEY_PARAM_ML_DSA_SEED ("seed") as an import
 * parameter on EVP_PKEY_fromdata — the provider derives (pk, sk) internally.
 */
static EVP_PKEY *
PkeyFromSeed(const char *algName, const BYTE *seed, size_t seedLen)
{
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx  = NULL;
    OSSL_PARAM    params[2];

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    if (ctx == NULL) goto cleanup;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto cleanup;

    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_ML_DSA_SEED, (void *)seed, seedLen);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        pkey = NULL;
    }

 cleanup:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Build an EVP_PKEY from an ML-DSA public key blob. Caller frees. */
static EVP_PKEY *
PkeyFromPub(const char *algName, const BYTE *pub, size_t pubLen)
{
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx  = NULL;
    OSSL_PARAM    params[2];

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    if (ctx == NULL) goto cleanup;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto cleanup;

    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, pubLen);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        pkey = NULL;
    }

 cleanup:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* ------------------------------------------------------------------------ */
/* Keygen                                                                    */
/* ------------------------------------------------------------------------ */

LIB_EXPORT TPM_RC
CryptMlDsaGenerateKey(TPMT_PUBLIC    *publicArea,
                      TPMT_SENSITIVE *sensitive,
                      OBJECT         *mldsaKey,
                      RAND_STATE     *rand)
{
    TPM_RC                    result     = TPM_RC_FAILURE;
    TPMI_MLDSA_PARAMETER_SET  paramSet   = GetParamSet(publicArea);
    const char               *algName    = CryptMlDsaAlgName(paramSet);
    EVP_PKEY                 *pkey       = NULL;
    EVP_PKEY_CTX             *ctx        = NULL;
    BYTE                      seed[MLDSA_PRIVATE_SEED_SIZE];
    size_t                    seedLen    = 0;
    UINT16                    expectedPub;
    BYTE                     *pubBuf;
    size_t                    pubLen     = 0;

    (void)mldsaKey;  /* not currently needed — kept for signature parity with RSA */

    if (algName == NULL)
        return TPM_RC_SCHEME;

    expectedPub = CryptMlDsaPubKeySize(paramSet);
    if (expectedPub == 0)
        return TPM_RC_SCHEME;

    /* Draw the 32-byte seed ξ. If a deterministic RAND_STATE is provided,
     * honor it (DRBG_Generate matches the libtpms contract for RSA/ECC).
     * Otherwise fall back to OpenSSL OS RNG. */
    if (rand != NULL) {
        if (DRBG_Generate(rand, seed, (UINT16)sizeof(seed)) != sizeof(seed))
            return TPM_RC_NO_RESULT;
    } else {
        if (RAND_bytes(seed, (int)sizeof(seed)) != 1)
            return TPM_RC_NO_RESULT;
    }
    seedLen = sizeof(seed);

    /* Prefer the seed-based import path (OpenSSL 3.6+). If that fails (e.g.
     * older provider), fall back to EVP_PKEY_generate with an RNG we seed
     * manually via OSSL_PKEY_PARAM_ML_DSA_SEED on the ctx params. */
    pkey = PkeyFromSeed(algName, seed, seedLen);

    if (pkey == NULL) {
        /* Fallback: keygen_init + params(seed) + generate. */
        OSSL_PARAM p[2];
        p[0] = OSSL_PARAM_construct_octet_string(
                   OSSL_PKEY_PARAM_ML_DSA_SEED, seed, seedLen);
        p[1] = OSSL_PARAM_construct_end();

        ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
        if (ctx == NULL) { result = TPM_RC_FAILURE; goto cleanup; }
        if (EVP_PKEY_keygen_init(ctx) <= 0) { result = TPM_RC_FAILURE; goto cleanup; }
        if (EVP_PKEY_CTX_set_params(ctx, p) <= 0) { result = TPM_RC_FAILURE; goto cleanup; }
        if (EVP_PKEY_generate(ctx, &pkey) <= 0) { result = TPM_RC_FAILURE; goto cleanup; }
    }

    /* Extract the public key. */
    pubBuf = publicArea->unique.mldsa.t.buffer;
    if (EVP_PKEY_get_octet_string_param(pkey,
            OSSL_PKEY_PARAM_PUB_KEY,
            pubBuf,
            sizeof(publicArea->unique.mldsa.t.buffer),
            &pubLen) <= 0) {
        result = TPM_RC_FAILURE;
        goto cleanup;
    }
    if (pubLen != expectedPub) {
        result = TPM_RC_FAILURE;
        goto cleanup;
    }
    publicArea->unique.mldsa.t.size = (UINT16)pubLen;

    /* Store the seed as the sensitive private key. */
    memcpy(sensitive->sensitive.mldsa.t.buffer, seed, seedLen);
    sensitive->sensitive.mldsa.t.size = (UINT16)seedLen;

    result = TPM_RC_SUCCESS;

 cleanup:
    OPENSSL_cleanse(seed, sizeof(seed));
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

/* ------------------------------------------------------------------------ */
/* Sign                                                                      */
/* ------------------------------------------------------------------------ */

LIB_EXPORT TPM_RC
CryptMlDsaSign(TPMT_SIGNATURE            *sigOut,
               OBJECT                    *key,
               TPM2B_DIGEST              *hIn,
               RAND_STATE                *rand,
               const TPM2B_SIGNATURE_CTX *ctx,
               const TPM2B_SIGNATURE_HINT *hint)
{
    TPM_RC                    result     = TPM_RC_FAILURE;
    TPMT_PUBLIC              *pub        = &key->publicArea;
    TPMI_MLDSA_PARAMETER_SET  paramSet   = GetParamSet(pub);
    const char               *algName    = CryptMlDsaAlgName(paramSet);
    EVP_PKEY                 *pkey       = NULL;
    EVP_MD_CTX               *mdctx      = NULL;
    EVP_PKEY_CTX             *pctx       = NULL;
    OSSL_PARAM                initParams[3];   /* instance + end (HashML-DSA) */
    OSSL_PARAM                ctxParams[2];    /* context-string + end        */
    size_t                    sigLen     = 0;
    BYTE                     *sigBuf     = NULL;
    UINT16                    expectedSigSize;

    (void)rand;
    (void)hint;  /* OpenSSL 3.6 doesn't expose rnd override; accepted, not forwarded */

    if (algName == NULL)
        return TPM_RC_SCHEME;

    expectedSigSize = CryptMlDsaSigSize(paramSet);
    if (expectedSigSize == 0)
        return TPM_RC_SCHEME;

    pkey = PkeyFromSeed(algName,
                        key->sensitive.sensitive.mldsa.t.buffer,
                        key->sensitive.sensitive.mldsa.t.size);
    if (pkey == NULL)
        return TPM_RC_KEY;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) goto cleanup;

    /* Build init params: HashML-DSA instance selector (if applicable). */
    {
        int i = 0;
#if ALG_HASH_MLDSA
        if (pub->type == TPM_ALG_HASH_MLDSA) {
            const char *inst = HashMlDsaInstance(paramSet, pub->nameAlg);
            if (inst == NULL) { result = TPM_RC_SCHEME; goto cleanup; }
            initParams[i++] = OSSL_PARAM_construct_utf8_string(
                                  OSSL_SIGNATURE_PARAM_INSTANCE, (char *)inst, 0);
        }
#endif
        initParams[i] = OSSL_PARAM_construct_end();
    }

    if (EVP_DigestSignInit_ex(mdctx, &pctx, NULL, NULL, NULL, pkey,
                              (pub->type == TPM_ALG_HASH_MLDSA) ? initParams : NULL) <= 0)
        goto cleanup;

    /* Wire FIPS 204 context string via OSSL_SIGNATURE_PARAM_CONTEXT_STRING.
     * Applies to both ML-DSA (pure) and HashML-DSA. Empty ctx = no param set. */
    if (ctx != NULL && ctx->t.size > 0) {
        ctxParams[0] = OSSL_PARAM_construct_octet_string(
                           OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                           (void *)ctx->t.context, ctx->t.size);
        ctxParams[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(pctx, ctxParams) <= 0)
            goto cleanup;
    }

    /* Probe output size. */
    if (EVP_DigestSign(mdctx, NULL, &sigLen, hIn->t.buffer, hIn->t.size) <= 0)
        goto cleanup;
    if (sigLen != (size_t)expectedSigSize)
        goto cleanup;

#if ALG_MLDSA
    if (pub->type == TPM_ALG_MLDSA) {
        sigOut->sigAlg = TPM_ALG_MLDSA;
        sigBuf = sigOut->signature.mldsa.t.buffer;
    }
#endif
#if ALG_HASH_MLDSA
    if (pub->type == TPM_ALG_HASH_MLDSA) {
        sigOut->sigAlg = TPM_ALG_HASH_MLDSA;
        sigBuf = sigOut->signature.hash_mldsa.signature.t.buffer;
    }
#endif

    if (EVP_DigestSign(mdctx, sigBuf, &sigLen, hIn->t.buffer, hIn->t.size) <= 0)
        goto cleanup;

#if ALG_MLDSA
    if (sigOut->sigAlg == TPM_ALG_MLDSA)
        sigOut->signature.mldsa.t.size = (UINT16)sigLen;
#endif
#if ALG_HASH_MLDSA
    if (sigOut->sigAlg == TPM_ALG_HASH_MLDSA)
        sigOut->signature.hash_mldsa.signature.t.size = (UINT16)sigLen;
#endif

    result = TPM_RC_SUCCESS;

 cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return result;
}

/* ------------------------------------------------------------------------ */
/* Verify                                                                    */
/* ------------------------------------------------------------------------ */

LIB_EXPORT TPM_RC
CryptMlDsaValidateSignature(TPMT_SIGNATURE            *sig,
                            OBJECT                    *key,
                            TPM2B_DIGEST              *digest,
                            const TPM2B_SIGNATURE_CTX *ctx)
{
    TPM_RC                    result     = TPM_RC_SIGNATURE;
    TPMT_PUBLIC              *pub        = &key->publicArea;
    TPMI_MLDSA_PARAMETER_SET  paramSet   = GetParamSet(pub);
    const char               *algName    = CryptMlDsaAlgName(paramSet);
    EVP_PKEY                 *pkey       = NULL;
    EVP_MD_CTX               *mdctx      = NULL;
    EVP_PKEY_CTX             *pctx       = NULL;
    OSSL_PARAM                initParams[3];
    OSSL_PARAM                ctxParams[2];
    UINT16                    expectedSigSize;
    const BYTE               *sigBuf;
    size_t                    sigLen;

    if (algName == NULL)
        return TPM_RC_SCHEME;

    expectedSigSize = CryptMlDsaSigSize(paramSet);
    if (expectedSigSize == 0)
        return TPM_RC_SCHEME;

    /* Read from the typed TPMU_SIGNATURE union member (V1.85 §11.3.5) */
#if ALG_MLDSA
    if (sig->sigAlg == TPM_ALG_MLDSA) {
        sigBuf = sig->signature.mldsa.t.buffer;
        sigLen = sig->signature.mldsa.t.size;
    } else
#endif
#if ALG_HASH_MLDSA
    if (sig->sigAlg == TPM_ALG_HASH_MLDSA) {
        sigBuf = sig->signature.hash_mldsa.signature.t.buffer;
        sigLen = sig->signature.hash_mldsa.signature.t.size;
    } else
#endif
    {
        return TPM_RC_SCHEME;
    }
    if (sigLen != (size_t)expectedSigSize)
        return TPM_RC_SIGNATURE;

    pkey = PkeyFromPub(algName,
                       pub->unique.mldsa.t.buffer,
                       pub->unique.mldsa.t.size);
    if (pkey == NULL)
        return TPM_RC_KEY;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) goto cleanup;

    {
        int i = 0;
#if ALG_HASH_MLDSA
        if (pub->type == TPM_ALG_HASH_MLDSA) {
            const char *inst = HashMlDsaInstance(paramSet, pub->nameAlg);
            if (inst == NULL) { result = TPM_RC_SCHEME; goto cleanup; }
            initParams[i++] = OSSL_PARAM_construct_utf8_string(
                                  OSSL_SIGNATURE_PARAM_INSTANCE, (char *)inst, 0);
        }
#endif
        initParams[i] = OSSL_PARAM_construct_end();
    }

    if (EVP_DigestVerifyInit_ex(mdctx, &pctx, NULL, NULL, NULL, pkey,
                                (pub->type == TPM_ALG_HASH_MLDSA) ? initParams : NULL) <= 0) {
        result = TPM_RC_FAILURE;
        goto cleanup;
    }

    if (ctx != NULL && ctx->t.size > 0) {
        ctxParams[0] = OSSL_PARAM_construct_octet_string(
                           OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                           (void *)ctx->t.context, ctx->t.size);
        ctxParams[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(pctx, ctxParams) <= 0) {
            result = TPM_RC_FAILURE;
            goto cleanup;
        }
    }

    if (EVP_DigestVerify(mdctx, sigBuf, sigLen, digest->t.buffer, digest->t.size) == 1)
        result = TPM_RC_SUCCESS;
    else
        result = TPM_RC_SIGNATURE;

 cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return result;
}

#endif  // ALG_MLDSA || ALG_HASH_MLDSA
