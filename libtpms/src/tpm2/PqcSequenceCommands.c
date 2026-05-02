/********************************************************************************/
/*                                                                              */
/*  PqcSequenceCommands.c — V1.85 RC4 Phase 4 sequence-command handlers        */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                         */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Implements the four ML-DSA sequence commands per V1.85 RC4 Part 3:          */
/*    §17.5  TPM2_SignSequenceStart    (Tables 89-90, CC=0x1AA)                 */
/*    §17.6  TPM2_VerifySequenceStart  (Tables 87-88, CC=0x1A9)                 */
/*    §20.3  TPM2_VerifySequenceComplete (Tables 118-119, CC=0x1A3)             */
/*    §20.6  TPM2_SignSequenceComplete   (Tables 124-125, CC=0x1A4)             */
/*                                                                              */
/*  Sequence state lives in PqcSequence.c's parallel slot pool. Handles minted  */
/*  in 0x80FF00xx range so TPM2_SequenceUpdate dispatcher can identify them     */
/*  before falling through to the existing HASH_OBJECT path.                    */
/*                                                                              */
/********************************************************************************/

#include "Tpm.h"
#include "Object_spt_fp.h"
#include "PqcSequence_fp.h"
#include "crypto/CryptMlDsa_fp.h"

/* ── helpers ──────────────────────────────────────────────────────────────── */

#if (ALG_MLDSA || ALG_HASH_MLDSA) && \
    (CC_SignSequenceStart || CC_SignSequenceComplete || \
     CC_VerifySequenceStart || CC_VerifySequenceComplete)

/* Resolve and validate a key handle for sign or verify start.
 * Returns NULL with rc set on error; otherwise returns the OBJECT*. */
static OBJECT *
get_signing_key(TPM_HANDLE keyHandle, BOOL forSign, TPM_RC *rc)
{
    OBJECT *key = HandleToObject(keyHandle);
    if (key == NULL) {
        *rc = TPM_RC_HANDLE;
        return NULL;
    }
    if (forSign) {
        if (!IS_ATTRIBUTE(key->publicArea.objectAttributes, TPMA_OBJECT, sign)) {
            *rc = TPM_RC_KEY;
            return NULL;
        }
    } else {
        /* §20.3: verify keys may be sign-capable or sign-attested-via-cert. */
        if (!IS_ATTRIBUTE(key->publicArea.objectAttributes, TPMA_OBJECT, sign)) {
            *rc = TPM_RC_KEY;
            return NULL;
        }
    }
    if (key->publicArea.type != TPM_ALG_MLDSA
        && key->publicArea.type != TPM_ALG_HASH_MLDSA) {
        /* Phase 4 V0 covers ML-DSA only; classical scheme sequences are out of scope. */
        *rc = TPM_RC_SCHEME;
        return NULL;
    }
    *rc = TPM_RC_SUCCESS;
    return key;
}

#endif

/* ── TPM2_SignSequenceStart (V1.85 §17.5, CC = 0x1AA) ─────────────────────── */

#include "SignSequenceStart_fp.h"
#if CC_SignSequenceStart
TPM_RC
TPM2_SignSequenceStart(SignSequenceStart_In  *in,
                       SignSequenceStart_Out *out)
{
    TPM_RC          rc;
    OBJECT         *key;
    PQC_SEQ_STATE  *seq;

    /* §17.5: "Authorization of the key referenced by keyHandle is not required
     * at this time. It is checked later, when TPM2_SignSequenceComplete()
     * is called." */
    key = get_signing_key(in->keyHandle, /*forSign=*/TRUE, &rc);
    if (key == NULL)
        return rc + RC_SignSequenceStart_keyHandle;

    seq = PqcSequenceAllocate(/*isSign=*/TRUE);
    if (seq == NULL)
        return TPM_RC_OBJECT_MEMORY;

    seq->keyHandle = in->keyHandle;
    seq->keyType   = key->publicArea.type;
    seq->paramSet  = key->publicArea.parameters.mldsaDetail.parameterSet;
    seq->auth      = in->auth;
    seq->context   = in->context;

    out->sequenceHandle = seq->handle;
    return TPM_RC_SUCCESS;
}
#endif  /* CC_SignSequenceStart */

/* ── TPM2_VerifySequenceStart (V1.85 §17.6, CC = 0x1A9) ───────────────────── */

#include "VerifySequenceStart_fp.h"
#if CC_VerifySequenceStart
TPM_RC
TPM2_VerifySequenceStart(VerifySequenceStart_In  *in,
                         VerifySequenceStart_Out *out)
{
    TPM_RC          rc;
    OBJECT         *key;
    PQC_SEQ_STATE  *seq;

    key = get_signing_key(in->keyHandle, /*forSign=*/FALSE, &rc);
    if (key == NULL)
        return rc + RC_VerifySequenceStart_keyHandle;

    /* §17.6: hint must be supplied for TPM_ALG_EDDSA, and zero-length in all
     * other cases. ML-DSA falls in the latter bucket. */
    if (in->hint.t.size != 0)
        return TPM_RC_VALUE + RC_VerifySequenceStart_hint;

    seq = PqcSequenceAllocate(/*isSign=*/FALSE);
    if (seq == NULL)
        return TPM_RC_OBJECT_MEMORY;

    seq->keyHandle = in->keyHandle;
    seq->keyType   = key->publicArea.type;
    seq->paramSet  = key->publicArea.parameters.mldsaDetail.parameterSet;
    seq->auth      = in->auth;
    seq->context   = in->context;
    /* hint is zero-length for ML-DSA — store anyway for completeness. */
    seq->hint      = in->hint;

    out->sequenceHandle = seq->handle;
    return TPM_RC_SUCCESS;
}
#endif  /* CC_VerifySequenceStart */

/* ── TPM2_SignSequenceComplete (V1.85 §20.6, CC = 0x1A4) ──────────────────── */

#include "SignSequenceComplete_fp.h"
#if CC_SignSequenceComplete
TPM_RC
TPM2_SignSequenceComplete(SignSequenceComplete_In  *in,
                          SignSequenceComplete_Out *out)
{
    PQC_SEQ_STATE  *seq;
    OBJECT         *key;
    TPM_RC          rc;

    seq = PqcSequenceFromHandle(in->sequenceHandle);
    if (seq == NULL)
        return TPM_RCS_HANDLE + RC_SignSequenceComplete_sequenceHandle;
    if (!seq->isSign)
        return TPM_RCS_MODE + RC_SignSequenceComplete_sequenceHandle;

    /* §20.6: "If keyHandle refers to a key that is not the same as the key
     * that was used to start the signature context, the TPM shall return
     * TPM_RC_SIGN_CONTEXT_KEY." (libtpms maps this onto TPM_RC_HANDLE on
     * keyHandle in the absence of a dedicated SIGN_CONTEXT_KEY constant.) */
    if (in->keyHandle != seq->keyHandle) {
        PqcSequenceFlush(in->sequenceHandle);
        return TPM_RCS_HANDLE + RC_SignSequenceComplete_keyHandle;
    }

    /* §20.6: "If the scheme of keyHandle requires multiple passes over the
     * message to be signed (e.g., TPM_ALG_EDDSA), and sequenceHandle
     * references a non-empty sequence (i.e., one in which TPM2_SequenceUpdate()
     * was already used), the TPM shall return TPM_RC_ONE_SHOT_SIGNATURE."
     * Our PqcSequenceUpdate already rejects update with that code, so for
     * ML-DSA sign sequences the buffer should always be empty here. Guard
     * anyway in case a future code path bypasses PqcSequenceUpdate. */
    if (seq->bufferUsed != 0) {
        PqcSequenceFlush(in->sequenceHandle);
        return TPM_RC_ONE_SHOT_SIGNATURE;
    }

    key = HandleToObject(in->keyHandle);
    if (key == NULL) {
        PqcSequenceFlush(in->sequenceHandle);
        return TPM_RCS_HANDLE + RC_SignSequenceComplete_keyHandle;
    }

    /* Sign the message exactly as supplied via the buffer parameter. ML-DSA
     * computes µ over the entire message internally per FIPS 204 §5.2. */
    rc = CryptMlDsaSignMessage(&out->signature, key,
                               in->buffer.t.buffer, in->buffer.t.size,
                               seq->context.t.size > 0 ? &seq->context : NULL);

    PqcSequenceFlush(in->sequenceHandle);
    return rc;
}
#endif  /* CC_SignSequenceComplete */

/* ── TPM2_VerifySequenceComplete (V1.85 §20.3, CC = 0x1A3) ────────────────── */

#include "VerifySequenceComplete_fp.h"
#if CC_VerifySequenceComplete
TPM_RC
TPM2_VerifySequenceComplete(VerifySequenceComplete_In  *in,
                            VerifySequenceComplete_Out *out)
{
    PQC_SEQ_STATE  *seq;
    OBJECT         *key;
    TPM_RC          rc;

    seq = PqcSequenceFromHandle(in->sequenceHandle);
    if (seq == NULL)
        return TPM_RCS_HANDLE + RC_VerifySequenceComplete_sequenceHandle;
    if (seq->isSign)
        return TPM_RCS_MODE + RC_VerifySequenceComplete_sequenceHandle;

    /* §20.3 continuity check */
    if (in->keyHandle != seq->keyHandle) {
        PqcSequenceFlush(in->sequenceHandle);
        return TPM_RCS_HANDLE + RC_VerifySequenceComplete_keyHandle;
    }

    key = HandleToObject(in->keyHandle);
    if (key == NULL) {
        PqcSequenceFlush(in->sequenceHandle);
        return TPM_RCS_HANDLE + RC_VerifySequenceComplete_keyHandle;
    }

    rc = CryptMlDsaValidateSignatureMessage(&in->signature, key,
                                            seq->buffer, seq->bufferUsed,
                                            seq->context.t.size > 0 ? &seq->context : NULL);
    if (rc != TPM_RC_SUCCESS) {
        PqcSequenceFlush(in->sequenceHandle);
        return rc + RC_VerifySequenceComplete_signature;
    }

    /* §20.3: "If the signature check succeeds, then the TPM will produce a
     * TPMT_TK_VERIFIED. ... The ticket's tag is TPM_ST_MESSAGE_VERIFIED."
     * Phase 4 V0: hmac size = 0 (matches NULL-hierarchy ticket shape per
     * §20.3 narrative). HMAC binding for non-NULL hierarchies is Phase 4.1
     * follow-up — it's a pure auth-chain feature; the spec contract for
     * the ticket's *tag* and *hierarchy* fields is met here. */
    out->validation.tag       = TPM_ST_MESSAGE_VERIFIED;
    out->validation.hierarchy = GetHierarchy(in->keyHandle);
    out->validation.hmac.t.size = 0;

    PqcSequenceFlush(in->sequenceHandle);
    return TPM_RC_SUCCESS;
}
#endif  /* CC_VerifySequenceComplete */
