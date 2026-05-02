/********************************************************************************/
/*                                                                              */
/*  TPM2_VerifySequenceStart — V1.85 RC4 Part 3 §17.6 Tables 87-88            */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Wire format (Table 87 Command):                                             */
/*    Handle:  keyHandle (TPMI_DH_OBJECT)  — Auth Index: None                  */
/*    Params:  auth (TPM2B_AUTH), hint (TPM2B_SIGNATURE_HINT),                  */
/*             context (TPM2B_SIGNATURE_CTX)                                    */
/*  Wire format (Table 88 Response):                                            */
/*    Handle:  sequenceHandle (TPMI_DH_OBJECT)                                  */
/*                                                                              */
/********************************************************************************/

#ifndef VERIFYSEQUENCESTART_FP_H
#define VERIFYSEQUENCESTART_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT       keyHandle;  /* IN  H1: loaded verification key */
    TPM2B_AUTH           auth;       /* IN  P1: authorization for subsequent sequence use */
    TPM2B_SIGNATURE_HINT hint;       /* IN  P2: must be zero-length unless TPM_ALG_EDDSA */
    TPM2B_SIGNATURE_CTX  context;    /* IN  P3: FIPS 204 context (may be zero-length) */
} VerifySequenceStart_In;

#define RC_VerifySequenceStart_keyHandle  (TPM_RC_H + TPM_RC_1)
#define RC_VerifySequenceStart_auth       (TPM_RC_P + TPM_RC_1)
#define RC_VerifySequenceStart_hint       (TPM_RC_P + TPM_RC_2)
#define RC_VerifySequenceStart_context    (TPM_RC_P + TPM_RC_3)

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
