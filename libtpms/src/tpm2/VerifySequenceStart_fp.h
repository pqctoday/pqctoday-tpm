/********************************************************************************/
/*                                                                              */
/*  TPM2_VerifySequenceStart — V1.85 begin streaming ML-DSA verify (§29.4.1) */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Phase 4 — requires MLDSA_SEQUENCE_OBJECT (cross-command EVP_MD_CTX).      */
/*  Dispatcher infrastructure is present; handler returns TPM_RC_COMMAND_CODE. */
/*                                                                              */
/********************************************************************************/

#ifndef VERIFYSEQUENCESTART_FP_H
#define VERIFYSEQUENCESTART_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT       keyHandle;   /* IN  H1: loaded ML-DSA verification key          */
    TPMT_SIG_SCHEME      inScheme;    /* IN  P1: signature scheme                         */
    TPMT_SIGNATURE       signature;   /* IN  P2: ML-DSA signature to verify against stream */
    TPM2B_SIGNATURE_CTX  context;     /* IN  P3: domain-separation context (may be empty)  */
} VerifySequenceStart_In;

#define RC_VerifySequenceStart_keyHandle   (TPM_RC_H + TPM_RC_1)
#define RC_VerifySequenceStart_inScheme    (TPM_RC_P + TPM_RC_1)
#define RC_VerifySequenceStart_signature   (TPM_RC_P + TPM_RC_2)
#define RC_VerifySequenceStart_context     (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPMI_DH_OBJECT  sequenceHandle;  /* OUT H1: transient sequence object handle */
} VerifySequenceStart_Out;

TPM_RC
TPM2_VerifySequenceStart(
    VerifySequenceStart_In  *in,
    VerifySequenceStart_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* VERIFYSEQUENCESTART_FP_H */
