/********************************************************************************/
/*                                                                              */
/*  TPM2_SignSequenceStart — V1.85 RC4 Part 3 §17.5 Tables 89-90              */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Wire format (Table 89 Command):                                             */
/*    Handle:  keyHandle (TPMI_DH_OBJECT)  — Auth Index: None (auth checked    */
/*             at SignSequenceComplete time per §17.5)                          */
/*    Params:  auth (TPM2B_AUTH), context (TPM2B_SIGNATURE_CTX)                 */
/*  Wire format (Table 90 Response):                                            */
/*    Handle:  sequenceHandle (TPMI_DH_OBJECT)                                  */
/*                                                                              */
/********************************************************************************/

#ifndef SIGNSEQUENCESTART_FP_H
#define SIGNSEQUENCESTART_FP_H

#if ALG_MLDSA || ALG_HASH_MLDSA

typedef struct {
    TPMI_DH_OBJECT       keyHandle;  /* IN  H1: loaded ML-DSA signing key */
    TPM2B_AUTH           auth;       /* IN  P1: authorization for subsequent sequence use */
    TPM2B_SIGNATURE_CTX  context;    /* IN  P2: FIPS 204 context (may be zero-length) */
} SignSequenceStart_In;

#define RC_SignSequenceStart_keyHandle  (TPM_RC_H + TPM_RC_1)
#define RC_SignSequenceStart_auth       (TPM_RC_P + TPM_RC_1)
#define RC_SignSequenceStart_context    (TPM_RC_P + TPM_RC_2)

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
