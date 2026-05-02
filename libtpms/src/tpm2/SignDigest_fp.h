/********************************************************************************/
/*                                                                              */
/*  TPM2_SignDigest — V1.85 ML-DSA / HashML-DSA sign over digest (§29.2.1)   */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#ifndef SIGNDIGEST_FP_H
#define SIGNDIGEST_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT       keyHandle;  /* IN  H1: loaded ML-DSA signing key          */
    TPMT_SIG_SCHEME      inScheme;   /* IN  P1: signing scheme (TPM_ALG_NULL→key default) */
    TPM2B_DIGEST         digest;     /* IN  P2: pre-computed message digest          */
    TPM2B_SIGNATURE_CTX  context;    /* IN  P3: domain-separation context (may be empty) */
    TPM2B_SIGNATURE_HINT hint;       /* IN  P4: determinism hint (may be empty)      */
} SignDigest_In;

#define RC_SignDigest_keyHandle  (TPM_RC_H + TPM_RC_1)
#define RC_SignDigest_inScheme   (TPM_RC_P + TPM_RC_1)
#define RC_SignDigest_digest     (TPM_RC_P + TPM_RC_2)
#define RC_SignDigest_context    (TPM_RC_P + TPM_RC_3)
#define RC_SignDigest_hint       (TPM_RC_P + TPM_RC_4)

typedef struct {
    TPMT_SIGNATURE  signature;  /* OUT: ML-DSA / HashML-DSA signature */
} SignDigest_Out;

TPM_RC
TPM2_SignDigest(
    SignDigest_In  *in,
    SignDigest_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* SIGNDIGEST_FP_H */
