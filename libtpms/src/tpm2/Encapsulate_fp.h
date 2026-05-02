/********************************************************************************/
/*                                                                              */
/*  TPM2_Encapsulate — V1.85 ML-KEM key encapsulation (§29.5.1)               */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#ifndef ENCAPSULATE_FP_H
#define ENCAPSULATE_FP_H

#if ALG_MLKEM

typedef struct {
    TPMI_DH_OBJECT  keyHandle;   /* IN  H1: loaded ML-KEM public-key object */
} Encapsulate_In;

#define RC_Encapsulate_keyHandle    (TPM_RC_H + TPM_RC_1)

typedef struct {
    /* V1.85 RC4 Part 3 §14.10 Table 61 — wire order is { sharedSecret, ciphertext }.
     * Struct field order MUST match the spec wire order so the dispatcher's
     * paramOffsets[] arithmetic walks the output buffer correctly. */
    TPM2B_SHARED_SECRET   sharedSecret;  /* OUT 1st: 32-byte shared secret */
    TPM2B_KEM_CIPHERTEXT  ciphertext;    /* OUT 2nd: encapsulation ciphertext */
} Encapsulate_Out;

TPM_RC
TPM2_Encapsulate(
    Encapsulate_In  *in,
    Encapsulate_Out *out
);

#endif  /* ALG_MLKEM */
#endif  /* ENCAPSULATE_FP_H */
