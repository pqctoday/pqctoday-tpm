/********************************************************************************/
/*                                                                              */
/*  TPM2_Encapsulate / TPM2_Decapsulate — V1.85 ML-KEM commands               */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  V1.85 Part 3 §29.5.1 (Encapsulate) and §29.5.2 (Decapsulate).             */
/*  Both delegate to CryptMlKemEncapsulate / CryptMlKemDecapsulate which call  */
/*  OpenSSL 3.6+ EVP_PKEY_encapsulate / EVP_PKEY_decapsulate.                 */
/*                                                                              */
/********************************************************************************/

#include "Tpm.h"

/* ── TPM2_Encapsulate ─────────────────────────────────────────────────────── */

#include "Encapsulate_fp.h"

#if CC_Encapsulate

/*
 * Using a loaded ML-KEM public-key object, generate a fresh encapsulation:
 * return (ciphertext, sharedSecret). The caller uses sharedSecret as KDF
 * input; the remote holder decapsulates ciphertext to reproduce it.
 *
 * Return:
 *   TPM_RC_ATTRIBUTES   keyHandle does not reference an ML-KEM public key
 *   TPM_RC_KEY          EVP key construction failed (corrupt public key)
 *   TPM_RC_FAILURE      OpenSSL encapsulate call failed
 */
TPM_RC
TPM2_Encapsulate(Encapsulate_In *in, Encapsulate_Out *out)
{
    OBJECT *kemKey = HandleToObject(in->keyHandle);

    if(kemKey->publicArea.type != TPM_ALG_MLKEM)
        return TPM_RCS_ATTRIBUTES + RC_Encapsulate_keyHandle;

    return CryptMlKemEncapsulate(&out->sharedSecret, &out->ciphertext, kemKey, NULL);
}

#endif  /* CC_Encapsulate */

/* ── TPM2_Decapsulate ─────────────────────────────────────────────────────── */

#include "Decapsulate_fp.h"

#if CC_Decapsulate

/*
 * Using a loaded ML-KEM private-key object and the supplied ciphertext,
 * recover the sharedSecret that was produced during encapsulation.
 *
 * Return:
 *   TPM_RC_ATTRIBUTES   keyHandle does not reference an ML-KEM private key
 *   TPM_RC_SIZE         ciphertext length wrong for this parameter set
 *   TPM_RC_KEY          EVP key construction failed (corrupt seed)
 *   TPM_RC_FAILURE      OpenSSL decapsulate call failed
 */
TPM_RC
TPM2_Decapsulate(Decapsulate_In *in, Decapsulate_Out *out)
{
    OBJECT *kemKey = HandleToObject(in->keyHandle);

    if(kemKey->publicArea.type != TPM_ALG_MLKEM)
        return TPM_RCS_ATTRIBUTES + RC_Decapsulate_keyHandle;

    /* CryptMlKemDecapsulate validates ciphertext size internally. */
    return CryptMlKemDecapsulate(&out->sharedSecret, &in->ciphertext, kemKey);
}

#endif  /* CC_Decapsulate */
