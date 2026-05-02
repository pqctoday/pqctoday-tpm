/********************************************************************************/
/*                                                                              */
/*  TPM2_SignSequenceComplete — V1.85 RC4 Part 3 §20.6 Tables 124-125         */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Wire format (Table 124 Command):                                            */
/*    Handles: @sequenceHandle (auth, USER), @keyHandle (auth, USER)            */
/*    Params:  buffer (TPM2B_MAX_BUFFER)                                        */
/*  Wire format (Table 125 Response):                                           */
/*    Params:  signature (TPMT_SIGNATURE)                                       */
/*                                                                              */
/*  §20.6: if scheme requires multi-pass (e.g. EDDSA, ML-DSA) AND               */
/*  sequenceHandle has had any TPM2_SequenceUpdate calls, return                */
/*  TPM_RC_ONE_SHOT_SIGNATURE. If keyHandle differs from the one bound at       */
/*  Start, return TPM_RC_SIGN_CONTEXT_KEY.                                      */
/*                                                                              */
/********************************************************************************/

#ifndef SIGNSEQUENCECOMPLETE_FP_H
#define SIGNSEQUENCECOMPLETE_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT   sequenceHandle;  /* IN  H1: sequence object from SignSequenceStart */
    TPMI_DH_OBJECT   keyHandle;       /* IN  H2: must match key bound at Start */
    TPM2B_MAX_BUFFER buffer;          /* IN  P1: final (or only) message block */
} SignSequenceComplete_In;

#define RC_SignSequenceComplete_sequenceHandle  (TPM_RC_H + TPM_RC_1)
#define RC_SignSequenceComplete_keyHandle       (TPM_RC_H + TPM_RC_2)
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
