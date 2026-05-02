/********************************************************************************/
/*                                                                              */
/*  TPM2_SignSequenceStart — V1.85 begin streaming ML-DSA sign (§29.3.1)      */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Phase 4 — requires MLDSA_SEQUENCE_OBJECT (cross-command EVP_MD_CTX).      */
/*  Dispatcher infrastructure is present; handler returns TPM_RC_COMMAND_CODE. */
/*                                                                              */
/********************************************************************************/

#ifndef SIGNSEQUENCESTART_FP_H
#define SIGNSEQUENCESTART_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT       keyHandle;  /* IN  H1: loaded ML-DSA signing key          */
    TPMT_SIG_SCHEME      inScheme;   /* IN  P1: signing scheme                      */
    TPM2B_SIGNATURE_CTX  context;    /* IN  P2: domain-separation context (may be empty) */
    TPM2B_SIGNATURE_HINT hint;       /* IN  P3: determinism hint (may be empty)     */
} SignSequenceStart_In;

#define RC_SignSequenceStart_keyHandle  (TPM_RC_H + TPM_RC_1)
#define RC_SignSequenceStart_inScheme   (TPM_RC_P + TPM_RC_1)
#define RC_SignSequenceStart_context    (TPM_RC_P + TPM_RC_2)
#define RC_SignSequenceStart_hint       (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPMI_DH_OBJECT  sequenceHandle;  /* OUT H1: transient sequence object handle */
} SignSequenceStart_Out;

TPM_RC
TPM2_SignSequenceStart(
    SignSequenceStart_In  *in,
    SignSequenceStart_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* SIGNSEQUENCESTART_FP_H */
