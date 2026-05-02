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

#endif  // ALG_MLDSA || ALG_HASH_MLDSA
#endif  // _CRYPT_ML_DSA_FP_H_
