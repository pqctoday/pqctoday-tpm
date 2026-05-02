/********************************************************************************/
/*										*/
/*		   ML-KEM (FIPS 203) implementation for libtpms			*/
/*		Written for pqctoday-tpm (Copyright 2026 PQC Today)		*/
/*										*/
/*  BSD-3-Clause clean-room implementation against OpenSSL 3.6+ EVP.		*/
/*  FIPS 203 (August 2024). TCG Library V1.85 RC4 Part 2 §14.			*/
/*										*/
/*  Private key storage: 64-byte seed d‖z per TPM2B_PRIVATE_KEY_MLKEM. OpenSSL	*/
/*  3.6+ accepts OSSL_PKEY_PARAM_ML_KEM_SEED on EVP_PKEY_fromdata — the		*/
/*  provider expands (pk, sk) internally per FIPS 203 §7.1.			*/
/*										*/
/********************************************************************************/

#include "Tpm.h"

#if ALG_MLKEM

#include "CryptMlKem_fp.h"

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Parameter-set dispatch                                                    */
/* ------------------------------------------------------------------------ */

LIB_EXPORT const char *
CryptMlKemAlgName(TPMI_MLKEM_PARAMETER_SET paramSet)
{
    switch (paramSet) {
        case TPM_MLKEM_512:  return "ML-KEM-512";
        case TPM_MLKEM_768:  return "ML-KEM-768";
        case TPM_MLKEM_1024: return "ML-KEM-1024";
        default:             return NULL;
    }
}

LIB_EXPORT UINT16
CryptMlKemPubKeySize(TPMI_MLKEM_PARAMETER_SET paramSet)
{
    switch (paramSet) {
        case TPM_MLKEM_512:  return MLKEM_512_PUBLIC_KEY_SIZE;   /* 800 */
        case TPM_MLKEM_768:  return MLKEM_768_PUBLIC_KEY_SIZE;   /* 1184 */
        case TPM_MLKEM_1024: return MLKEM_1024_PUBLIC_KEY_SIZE;  /* 1568 */
        default:             return 0;
    }
}

LIB_EXPORT UINT16
CryptMlKemCtSize(TPMI_MLKEM_PARAMETER_SET paramSet)
{
    switch (paramSet) {
        case TPM_MLKEM_512:  return MLKEM_512_CIPHERTEXT_SIZE;   /* 768 */
        case TPM_MLKEM_768:  return MLKEM_768_CIPHERTEXT_SIZE;   /* 1088 */
        case TPM_MLKEM_1024: return MLKEM_1024_CIPHERTEXT_SIZE;  /* 1568 */
        default:             return 0;
    }
}

static TPMI_MLKEM_PARAMETER_SET
GetParamSet(const TPMT_PUBLIC *pub)
{
    if (pub->type == TPM_ALG_MLKEM)
        return pub->parameters.mlkemDetail.parameterSet;
    return TPM_MLKEM_NONE;
}

/* ------------------------------------------------------------------------ */
/* Key construction                                                          */
/* ------------------------------------------------------------------------ */

static EVP_PKEY *
PkeyFromSeed(const char *algName, const BYTE *seed, size_t seedLen)
{
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx  = NULL;
    OSSL_PARAM    params[2];

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    if (ctx == NULL) goto done;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed, seedLen);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        pkey = NULL;

 done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *
PkeyFromPub(const char *algName, const BYTE *pub, size_t pubLen)
{
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx  = NULL;
    OSSL_PARAM    params[2];

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    if (ctx == NULL) goto done;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, pubLen);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        pkey = NULL;

 done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* ------------------------------------------------------------------------ */
/* Keygen                                                                    */
/* ------------------------------------------------------------------------ */

LIB_EXPORT TPM_RC
CryptMlKemGenerateKey(TPMT_PUBLIC    *publicArea,
                      TPMT_SENSITIVE *sensitive,
                      OBJECT         *mlkemKey,
                      RAND_STATE     *rand)
{
    TPM_RC                    result    = TPM_RC_FAILURE;
    TPMI_MLKEM_PARAMETER_SET  paramSet  = GetParamSet(publicArea);
    const char               *algName   = CryptMlKemAlgName(paramSet);
    EVP_PKEY                 *pkey      = NULL;
    EVP_PKEY_CTX             *ctx       = NULL;
    BYTE                      seed[MLKEM_PRIVATE_SEED_SIZE];
    size_t                    seedLen   = 0;
    UINT16                    expectedPub;
    size_t                    pubLen    = 0;

    (void)mlkemKey;

    if (algName == NULL)
        return TPM_RC_SCHEME;

    expectedPub = CryptMlKemPubKeySize(paramSet);
    if (expectedPub == 0)
        return TPM_RC_SCHEME;

    if (rand != NULL) {
        if (DRBG_Generate(rand, seed, (UINT16)sizeof(seed)) != sizeof(seed))
            return TPM_RC_NO_RESULT;
    } else {
        if (RAND_bytes(seed, (int)sizeof(seed)) != 1)
            return TPM_RC_NO_RESULT;
    }
    seedLen = sizeof(seed);

    pkey = PkeyFromSeed(algName, seed, seedLen);

    if (pkey == NULL) {
        OSSL_PARAM p[2];
        p[0] = OSSL_PARAM_construct_octet_string(
                   OSSL_PKEY_PARAM_ML_KEM_SEED, seed, seedLen);
        p[1] = OSSL_PARAM_construct_end();

        ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
        if (ctx == NULL) { result = TPM_RC_FAILURE; goto cleanup; }
        if (EVP_PKEY_keygen_init(ctx) <= 0) { result = TPM_RC_FAILURE; goto cleanup; }
        if (EVP_PKEY_CTX_set_params(ctx, p) <= 0) { result = TPM_RC_FAILURE; goto cleanup; }
        if (EVP_PKEY_generate(ctx, &pkey) <= 0) { result = TPM_RC_FAILURE; goto cleanup; }
    }

    if (EVP_PKEY_get_octet_string_param(pkey,
            OSSL_PKEY_PARAM_PUB_KEY,
            publicArea->unique.mlkem.t.buffer,
            sizeof(publicArea->unique.mlkem.t.buffer),
            &pubLen) <= 0) {
        result = TPM_RC_FAILURE;
        goto cleanup;
    }
    if (pubLen != expectedPub) {
        result = TPM_RC_FAILURE;
        goto cleanup;
    }
    publicArea->unique.mlkem.t.size = (UINT16)pubLen;

    memcpy(sensitive->sensitive.mlkem.t.buffer, seed, seedLen);
    sensitive->sensitive.mlkem.t.size = (UINT16)seedLen;

    result = TPM_RC_SUCCESS;

 cleanup:
    OPENSSL_cleanse(seed, sizeof(seed));
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

/* ------------------------------------------------------------------------ */
/* Encapsulate                                                               */
/* ------------------------------------------------------------------------ */

LIB_EXPORT TPM_RC
CryptMlKemEncapsulate(TPM2B_SHARED_SECRET  *sharedSecret,
                      TPM2B_KEM_CIPHERTEXT *ciphertext,
                      OBJECT               *kemKey,
                      RAND_STATE           *rand)
{
    TPM_RC                    result    = TPM_RC_FAILURE;
    TPMT_PUBLIC              *pub       = &kemKey->publicArea;
    TPMI_MLKEM_PARAMETER_SET  paramSet  = GetParamSet(pub);
    const char               *algName   = CryptMlKemAlgName(paramSet);
    EVP_PKEY                 *pkey      = NULL;
    EVP_PKEY_CTX             *ctx       = NULL;
    size_t                    ctLen     = sizeof(ciphertext->t.buffer);
    size_t                    ssLen     = sizeof(sharedSecret->t.buffer);
    UINT16                    expectedCt;

    (void)rand;  /* ML-KEM encap randomness comes from OpenSSL's RNG */

    if (algName == NULL)
        return TPM_RC_SCHEME;

    expectedCt = CryptMlKemCtSize(paramSet);
    if (expectedCt == 0)
        return TPM_RC_SCHEME;

    pkey = PkeyFromPub(algName, pub->unique.mlkem.t.buffer, pub->unique.mlkem.t.size);
    if (pkey == NULL)
        return TPM_RC_KEY;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) goto cleanup;
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) goto cleanup;

    if (EVP_PKEY_encapsulate(ctx,
                             ciphertext->t.buffer, &ctLen,
                             sharedSecret->t.buffer, &ssLen) <= 0)
        goto cleanup;

    if (ctLen != expectedCt || ssLen != MLKEM_SHARED_SECRET_SIZE) {
        result = TPM_RC_SIZE;
        goto cleanup;
    }

    ciphertext->t.size   = (UINT16)ctLen;
    sharedSecret->t.size = (UINT16)ssLen;
    result = TPM_RC_SUCCESS;

 cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

/* ------------------------------------------------------------------------ */
/* Decapsulate                                                               */
/* ------------------------------------------------------------------------ */

LIB_EXPORT TPM_RC
CryptMlKemDecapsulate(TPM2B_SHARED_SECRET        *sharedSecret,
                      const TPM2B_KEM_CIPHERTEXT *ciphertext,
                      OBJECT                     *kemKey)
{
    TPM_RC                    result    = TPM_RC_FAILURE;
    TPMT_PUBLIC              *pub       = &kemKey->publicArea;
    TPMI_MLKEM_PARAMETER_SET  paramSet  = GetParamSet(pub);
    const char               *algName   = CryptMlKemAlgName(paramSet);
    EVP_PKEY                 *pkey      = NULL;
    EVP_PKEY_CTX             *ctx       = NULL;
    size_t                    ssLen     = sizeof(sharedSecret->t.buffer);
    UINT16                    expectedCt;

    if (algName == NULL)
        return TPM_RC_SCHEME;

    expectedCt = CryptMlKemCtSize(paramSet);
    if (ciphertext->t.size != expectedCt)
        return TPM_RC_SIZE;

    pkey = PkeyFromSeed(algName,
                        kemKey->sensitive.sensitive.mlkem.t.buffer,
                        kemKey->sensitive.sensitive.mlkem.t.size);
    if (pkey == NULL)
        return TPM_RC_KEY;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) goto cleanup;
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) goto cleanup;

    if (EVP_PKEY_decapsulate(ctx,
                             sharedSecret->t.buffer, &ssLen,
                             ciphertext->t.buffer, ciphertext->t.size) <= 0)
        goto cleanup;

    if (ssLen != MLKEM_SHARED_SECRET_SIZE) {
        result = TPM_RC_SIZE;
        goto cleanup;
    }

    sharedSecret->t.size = (UINT16)ssLen;
    result = TPM_RC_SUCCESS;

 cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

#endif  // ALG_MLKEM
