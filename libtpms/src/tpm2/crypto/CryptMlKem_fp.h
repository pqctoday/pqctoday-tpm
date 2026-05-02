/********************************************************************************/
/*										*/
/*			  ML-KEM (FIPS 203) — Function Prototypes		*/
/*		Written for pqctoday-tpm (Copyright 2026 PQC Today)		*/
/*										*/
/*  Implements the libtpms crypto contract for TPM_ALG_MLKEM added in TCG TPM	*/
/*  2.0 Library Specification V1.85. ML-KEM is a Key Encapsulation Mechanism —	*/
/*  distinct from the RSA/ECC encrypt paradigm — so the public API adds three	*/
/*  new operations (keygen, encapsulate, decapsulate) rather than reusing the	*/
/*  RSA encrypt/decrypt signatures.						*/
/*										*/
/*  BSD-3-Clause — clean-room implementation against OpenSSL 3.6+ EVP.		*/
/*										*/
/********************************************************************************/

#ifndef _CRYPT_ML_KEM_FP_H_
#define _CRYPT_ML_KEM_FP_H_

#if ALG_MLKEM

#include "Tpm.h"

/* Parameter-set dispatch: map TPMI_MLKEM_PARAMETER_SET to OpenSSL algorithm name. */
LIB_EXPORT const char *CryptMlKemAlgName(TPMI_MLKEM_PARAMETER_SET paramSet);

/* Size helpers. */
LIB_EXPORT UINT16 CryptMlKemPubKeySize(TPMI_MLKEM_PARAMETER_SET paramSet);
LIB_EXPORT UINT16 CryptMlKemCtSize(TPMI_MLKEM_PARAMETER_SET paramSet);

/* Keygen: fills publicArea->unique.mlkem (pk) and sensitive->sensitive.mlkem
 * (64-byte d‖z seed per FIPS 203 §7.1 / TCG V1.85 Part 2 TPM2B_PRIVATE_KEY_MLKEM). */
LIB_EXPORT TPM_RC CryptMlKemGenerateKey(
    TPMT_PUBLIC*    publicArea,   // IN/OUT: parameters.mlkemDetail already set
    TPMT_SENSITIVE* sensitive,    // OUT: sensitive.mlkem = 64-byte seed
    OBJECT*         mlkemKey,     // IN/OUT: containing object
    RAND_STATE*     rand          // IN: deterministic RNG for tests (NULL = OS RNG)
);

/* Encapsulate (public operation). Uses OpenSSL EVP_PKEY_encapsulate.
 * Writes directly into V1.85 typed output buffers (§10.3.12-14). */
LIB_EXPORT TPM_RC CryptMlKemEncapsulate(
    TPM2B_SHARED_SECRET*    sharedSecret,  // OUT: 32-byte shared secret (Table 99)
    TPM2B_KEM_CIPHERTEXT*   ciphertext,    // OUT: ciphertext (Table 101)
    OBJECT*                 kemKey,         // IN: public-key object
    RAND_STATE*             rand            // IN: deterministic RNG (NULL = OS RNG)
);

/* Decapsulate (private operation). Uses OpenSSL EVP_PKEY_decapsulate. */
LIB_EXPORT TPM_RC CryptMlKemDecapsulate(
    TPM2B_SHARED_SECRET*        sharedSecret,  // OUT: 32-byte shared secret
    const TPM2B_KEM_CIPHERTEXT* ciphertext,    // IN: ciphertext
    OBJECT*                     kemKey         // IN: private-key object (seed 64 B)
);

#endif  // ALG_MLKEM
#endif  // _CRYPT_ML_KEM_FP_H_
