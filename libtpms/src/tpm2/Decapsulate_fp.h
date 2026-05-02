/********************************************************************************/
/*                                                                              */
/*  TPM2_Decapsulate — V1.85 ML-KEM key decapsulation (§29.5.2)               */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#ifndef DECAPSULATE_FP_H
#define DECAPSULATE_FP_H

#if ALG_MLKEM

typedef struct {
    TPMI_DH_OBJECT        keyHandle;    /* IN  H1: loaded ML-KEM private-key object */
    TPM2B_KEM_CIPHERTEXT  ciphertext;   /* IN  P1: encapsulation ciphertext          */
} Decapsulate_In;

#define RC_Decapsulate_keyHandle    (TPM_RC_H + TPM_RC_1)
#define RC_Decapsulate_ciphertext   (TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_SHARED_SECRET  sharedSecret;  /* OUT: 32-byte shared secret */
} Decapsulate_Out;

TPM_RC
TPM2_Decapsulate(
    Decapsulate_In  *in,
    Decapsulate_Out *out
);

#endif  /* ALG_MLKEM */
#endif  /* DECAPSULATE_FP_H */
