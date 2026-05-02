/********************************************************************************/
/*                                                                              */
/*  TPM2_SignSequenceComplete — V1.85 finish streaming ML-DSA sign (§29.3.2)  */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Phase 4 — requires MLDSA_SEQUENCE_OBJECT (cross-command EVP_MD_CTX).      */
/*  Dispatcher infrastructure is present; handler returns TPM_RC_COMMAND_CODE. */
/*                                                                              */
/********************************************************************************/

#ifndef SIGNSEQUENCECOMPLETE_FP_H
#define SIGNSEQUENCECOMPLETE_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT   sequenceHandle;  /* IN  H1: sequence object from SignSequenceStart */
    TPM2B_MAX_BUFFER buffer;          /* IN  P1: final (or only) message block           */
} SignSequenceComplete_In;

#define RC_SignSequenceComplete_sequenceHandle  (TPM_RC_H + TPM_RC_1)
#define RC_SignSequenceComplete_buffer          (TPM_RC_P + TPM_RC_1)

typedef struct {
    TPMT_SIGNATURE  signature;  /* OUT: completed ML-DSA / HashML-DSA signature */
} SignSequenceComplete_Out;

TPM_RC
TPM2_SignSequenceComplete(
    SignSequenceComplete_In  *in,
    SignSequenceComplete_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* SIGNSEQUENCECOMPLETE_FP_H */
