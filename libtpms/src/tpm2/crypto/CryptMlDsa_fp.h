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
 * For HashML-DSA, the nameAlg of the key object selects the pre-hash variant. */
LIB_EXPORT TPM_RC CryptMlDsaSign(
    TPMT_SIGNATURE* sigOut,       // OUT: signature (sigAlg must be TPM_ALG_{MLDSA|HASH_MLDSA})
    OBJECT*         key,          // IN: signing key — unique.mldsa is pub, sensitive.mldsa is seed
    TPM2B_DIGEST*   hIn,          // IN: message (or digest, for HashML-DSA)
    RAND_STATE*     rand          // IN: deterministic RNG for tests (NULL = OS RNG)
);

/* Verify. */
LIB_EXPORT TPM_RC CryptMlDsaValidateSignature(
    TPMT_SIGNATURE* sig,          // IN: signature
    OBJECT*         key,          // IN: verification key (public only)
    TPM2B_DIGEST*   digest        // IN: message (or digest)
);

#endif  // ALG_MLDSA || ALG_HASH_MLDSA
#endif  // _CRYPT_ML_DSA_FP_H_
