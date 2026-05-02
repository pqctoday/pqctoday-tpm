/********************************************************************************/
/*                                                                              */
/*  TPM2_VerifyDigestSignature — V1.85 ML-DSA verify over digest (§29.2.2)   */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#ifndef VERIFYDIGESTSIGNATURE_FP_H
#define VERIFYDIGESTSIGNATURE_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT       keyHandle;   /* IN  H1: loaded ML-DSA verification key       */
    TPM2B_DIGEST         digest;      /* IN  P1: pre-computed message digest            */
    TPMT_SIGNATURE       signature;   /* IN  P2: ML-DSA / HashML-DSA signature to verify */
    TPM2B_SIGNATURE_CTX  context;     /* IN  P3: domain-separation context (may be empty) */
} VerifyDigestSignature_In;

#define RC_VerifyDigestSignature_keyHandle   (TPM_RC_H + TPM_RC_1)
#define RC_VerifyDigestSignature_digest      (TPM_RC_P + TPM_RC_1)
#define RC_VerifyDigestSignature_signature   (TPM_RC_P + TPM_RC_2)
#define RC_VerifyDigestSignature_context     (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPMT_TK_VERIFIED  validation;  /* OUT: TPM_ST_DIGEST_VERIFIED ticket */
} VerifyDigestSignature_Out;

TPM_RC
TPM2_VerifyDigestSignature(
    VerifyDigestSignature_In  *in,
    VerifyDigestSignature_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* VERIFYDIGESTSIGNATURE_FP_H */
