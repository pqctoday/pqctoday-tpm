/********************************************************************************/
/*                                                                              */
/*  TPM2_VerifySequenceComplete — V1.85 RC4 Part 3 §20.3 Tables 118-119       */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Wire format (Table 118 Command):                                            */
/*    Handles: @sequenceHandle (auth, USER), keyHandle (no auth)                */
/*    Params:  signature (TPMT_SIGNATURE)                                       */
/*  Wire format (Table 119 Response):                                           */
/*    Params:  validation (TPMT_TK_VERIFIED)  — tag = TPM_ST_MESSAGE_VERIFIED  */
/*                                                                              */
/*  §20.3: if keyHandle differs from the one bound at Start, return             */
/*  TPM_RC_SIGN_CONTEXT_KEY. If signature check fails, TPM_RC_SIGNATURE.        */
/*  Note: per §20.3 the message is supplied via SequenceUpdate, NOT via a       */
/*  buffer parameter to Complete.                                               */
/*                                                                              */
/********************************************************************************/

#ifndef VERIFYSEQUENCECOMPLETE_FP_H
#define VERIFYSEQUENCECOMPLETE_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT   sequenceHandle;  /* IN  H1: sequence object from VerifySequenceStart */
    TPMI_DH_OBJECT   keyHandle;       /* IN  H2: must match key bound at Start */
    TPMT_SIGNATURE   signature;       /* IN  P1: signature to verify */
} VerifySequenceComplete_In;

#define RC_VerifySequenceComplete_sequenceHandle  (TPM_RC_H + TPM_RC_1)
#define RC_VerifySequenceComplete_keyHandle       (TPM_RC_H + TPM_RC_2)
#define RC_VerifySequenceComplete_signature       (TPM_RC_P + TPM_RC_1)

typedef struct {
    TPMT_TK_VERIFIED  validation;  /* OUT: tag = TPM_ST_MESSAGE_VERIFIED */
} VerifySequenceComplete_Out;

TPM_RC
TPM2_VerifySequenceComplete(
    VerifySequenceComplete_In  *in,
    VerifySequenceComplete_Out *out
);

#endif  /* ALG_MLDSA || ALG_HASH_MLDSA */
#endif  /* VERIFYSEQUENCECOMPLETE_FP_H */
