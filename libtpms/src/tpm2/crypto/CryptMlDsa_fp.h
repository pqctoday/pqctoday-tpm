/********************************************************************************/
/*										*/
/*			  ML-DSA (FIPS 204) — Function Prototypes		*/
/*		Written for pqctoday-tpm (Copyright 2026 PQC Today)		*/
/*										*/
/*  Implements the libtpms crypto dispatcher contract for the three post-	*/
/*  quantum algorithms added in TCG TPM 2.0 Library Specification V1.85:	*/
/*  TPM_ALG_MLDSA (FIPS 204 ML-DSA) and TPM_ALG_HASH_MLDSA (pre-hash variant).	*/
/*  ML-KEM is in CryptMlKem.c.							*/
/*										*/
/*  BSD-3-Clause — clean-room implementation against OpenSSL 3.6+ EVP,		*/
/*  not copied from any other project.						*/
/*										*/
/********************************************************************************/

#ifndef _CRYPT_ML_DSA_FP_H_
#define _CRYPT_ML_DSA_FP_H_

#if ALG_MLDSA || ALG_HASH_MLDSA

#include "Tpm.h"

/* Parameter-set dispatch: map TPMI_MLDSA_PARAMETER_SET to OpenSSL algorithm name. */
LIB_EXPORT const char *CryptMlDsaAlgName(TPMI_MLDSA_PARAMETER_SET paramSet);

/* Size helpers — driven from the parameter set rather than TCG Max constants. */
LIB_EXPORT UINT16 CryptMlDsaPubKeySize(TPMI_MLDSA_PARAMETER_SET paramSet);
LIB_EXPORT UINT16 CryptMlDsaSigSize(TPMI_MLDSA_PARAMETER_SET paramSet);

/* Keygen: fills publicArea->unique.mldsa and sensitive->sensitive.mldsa (32-B seed). */
LIB_EXPORT TPM_RC CryptMlDsaGenerateKey(
    TPMT_PUBLIC*    publicArea,   // IN/OUT: public area; parameters.{mldsaDetail|hashMldsaDetail}
                                  //         already filled with parameter set. On success
                                  //         unique.mldsa.t.{size,buffer} is populated.
    TPMT_SENSITIVE* sensitive,    // OUT: sensitive.mldsa = 32-byte seed (ξ)
    OBJECT*         mldsaKey,     // IN/OUT: containing object (reserved for future use)
    RAND_STATE*     rand          // IN: deterministic RNG for tests (NULL = OS RNG)
);

/* Sign — both raw ML-DSA (TPM_ALG_MLDSA) and HashML-DSA (TPM_ALG_HASH_MLDSA).
 * ctx and hint are optional (NULL = absent). ctx is the FIPS 204 context string
 * (0–255 bytes); hint is a determinism seed override (V1.85 §11.3.9). */
LIB_EXPORT TPM_RC CryptMlDsaSign(
    TPMT_SIGNATURE*           sigOut,  // OUT: signature
    OBJECT*                   key,     // IN: signing key
    TPM2B_DIGEST*             hIn,     // IN: message / digest
    RAND_STATE*               rand,    // IN: deterministic RNG (NULL = OS RNG)
    const TPM2B_SIGNATURE_CTX *ctx,    // IN: FIPS 204 context string (NULL = empty)
    const TPM2B_SIGNATURE_HINT *hint   // IN: determinism hint (NULL = ignored)
);

/* Verify.  ctx is the FIPS 204 context string that was used during signing. */
LIB_EXPORT TPM_RC CryptMlDsaValidateSignature(
    TPMT_SIGNATURE*           sig,     // IN: signature
    OBJECT*                   key,     // IN: verification key (public only)
    TPM2B_DIGEST*             digest,  // IN: message / digest
    const TPM2B_SIGNATURE_CTX *ctx     // IN: FIPS 204 context string (NULL = empty)
);

/* Phase 4 — sign/verify of arbitrary-length messages (V1.85 §17.5/§20.6).
 * These mirror the digest-shaped helpers above but operate on raw byte
 * buffers up to MAX_PQC_SEQ_BUFFER. The TPM2B_DIGEST helpers cap at
 * MAX_DIGEST_SIZE (64 B) which is too small for the SignSequenceComplete
 * buffer parameter (TPM2B_MAX_BUFFER ≈ 1024 B) and verify-sequence
 * accumulated message (up to 4 KB in our V0). Internally these call
 * EVP_DigestSign / EVP_DigestVerify with the message bytes; ML-DSA in
 * OpenSSL 3.5+ computes µ internally per FIPS 204 §5.2. */
LIB_EXPORT TPM_RC CryptMlDsaSignMessage(
    TPMT_SIGNATURE*             sigOut,
    OBJECT*                     key,
    const BYTE*                 msg,
    UINT32                      msgLen,
    const TPM2B_SIGNATURE_CTX*  ctx
);

LIB_EXPORT TPM_RC CryptMlDsaValidateSignatureMessage(
    TPMT_SIGNATURE*             sig,
    OBJECT*                     key,
    const BYTE*                 msg,
    UINT32                      msgLen,
    const TPM2B_SIGNATURE_CTX*  ctx
);

#endif  // ALG_MLDSA || ALG_HASH_MLDSA
#endif  // _CRYPT_ML_DSA_FP_H_
