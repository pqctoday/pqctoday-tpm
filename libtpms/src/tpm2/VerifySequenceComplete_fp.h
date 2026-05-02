/********************************************************************************/
/*                                                                              */
/*  TPM2_VerifySequenceComplete — V1.85 finish streaming verify (§29.4.2)    */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Phase 4 — requires MLDSA_SEQUENCE_OBJECT (cross-command EVP_MD_CTX).      */
/*  Dispatcher infrastructure is present; handler returns TPM_RC_COMMAND_CODE. */
/*                                                                              */
/********************************************************************************/

#ifndef VERIFYSEQUENCECOMPLETE_FP_H
#define VERIFYSEQUENCECOMPLETE_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT   sequenceHandle;  /* IN  H1: sequence object from VerifySequenceStart */
    TPM2B_MAX_BUFFER buffer;          /* IN  P1: final (or only) message block             */
} VerifySequenceComplete_In;

#define RC_VerifySequenceComplete_sequenceHandle  (TPM_RC_H + TPM_RC_1)
#define RC_VerifySequenceComplete_buffer          (TPM_RC_P + TPM_RC_1)

typedef struct {
    TPMT_TK_VERIFIED  validation;  /* OUT: TPM_ST_DIGEST_VERIFIED ticket */
} VerifySequenceComplete_Out;

TPM_RC
TPM2_VerifySequenceComplete(
    VerifySequenceComplete_In  *in,
    VerifySequenceComplete_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* VERIFYSEQUENCECOMPLETE_FP_H */
