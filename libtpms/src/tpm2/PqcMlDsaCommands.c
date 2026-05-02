/********************************************************************************/
/*                                                                              */
/*  V1.85 ML-DSA / HashML-DSA command handlers                                 */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                        */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/*  Implemented:                                                                */
/*    TPM2_SignDigest              (§29.2.1) — real, calls CryptMlDsaSign      */
/*    TPM2_VerifyDigestSignature   (§29.2.2) — real, calls CryptMlDsaValidate  */
/*                                                                              */
/*  Phase 4 (streaming, needs MLDSA_SEQUENCE_OBJECT):                          */
/*    TPM2_SignSequenceStart       (§29.3.1) — returns TPM_RC_COMMAND_CODE     */
/*    TPM2_SignSequenceComplete    (§29.3.2) — returns TPM_RC_COMMAND_CODE     */
/*    TPM2_VerifySequenceStart     (§29.4.1) — returns TPM_RC_COMMAND_CODE     */
/*    TPM2_VerifySequenceComplete  (§29.4.2) — returns TPM_RC_COMMAND_CODE     */
/*                                                                              */
/********************************************************************************/

#include "Tpm.h"

/* ── TPM2_SignDigest ──────────────────────────────────────────────────────── */

#include "SignDigest_fp.h"

#if CC_SignDigest

#  include "Attest_spt_fp.h"    /* IsSigningObject() */

/*
 * Sign a pre-computed digest using a loaded ML-DSA or HashML-DSA key.
 *
 * Unlike TPM2_Sign, no hash-check ticket is required — the caller supplies
 * the digest directly (§29.2.1).  context and hint may be zero-length.
 *
 * Return:
 *   TPM_RC_KEY        keyHandle does not reference a signing key
 *   TPM_RC_SCHEME     scheme not compatible with key type or hash
 *   TPM_RC_ATTRIBUTES key does not have the 'sign' attribute
 *   TPM_RC_FAILURE    crypto engine failure
 */
TPM_RC
TPM2_SignDigest(SignDigest_In *in, SignDigest_Out *out)
{
    OBJECT *signObject = HandleToObject(in->keyHandle);

    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_SignDigest_keyHandle;

    /* ML-DSA and HashML-DSA are the only algorithms supported by this command. */
    if(signObject->publicArea.type != TPM_ALG_MLDSA
       && signObject->publicArea.type != TPM_ALG_HASH_MLDSA)
        return TPM_RCS_ATTRIBUTES + RC_SignDigest_keyHandle;

    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_SignDigest_inScheme;

    return CryptMlDsaSign(
        &out->signature,
        signObject,
        &in->digest,
        NULL,
        in->context.t.size > 0 ? &in->context : NULL,
        in->hint.t.size    > 0 ? &in->hint    : NULL);
}

#endif  /* CC_SignDigest */

/* ── TPM2_VerifyDigestSignature ──────────────────────────────────────────── */

#include "VerifyDigestSignature_fp.h"

#if CC_VerifyDigestSignature

/*
 * Verify an ML-DSA or HashML-DSA signature over a pre-computed digest.
 * On success returns a TPM_ST_DIGEST_VERIFIED ticket.
 *
 * Return:
 *   TPM_RC_ATTRIBUTES   keyHandle is not a signing/verification key
 *   TPM_RC_SIGNATURE    signature fails verification
 *   TPM_RC_SCHEME       signature scheme not compatible with key
 *   TPM_RC_FAILURE      crypto engine failure
 */
TPM_RC
TPM2_VerifyDigestSignature(VerifyDigestSignature_In  *in,
                           VerifyDigestSignature_Out *out)
{
    TPM_RC  result;
    OBJECT *signObject = HandleToObject(in->keyHandle);

    if(!IS_ATTRIBUTE(signObject->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RCS_ATTRIBUTES + RC_VerifyDigestSignature_keyHandle;

    result = CryptMlDsaValidateSignature(
        &in->signature,
        signObject,
        &in->digest,
        in->context.t.size > 0 ? &in->context : NULL);

    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_VerifyDigestSignature_signature);

    /* Build a TPM_ST_DIGEST_VERIFIED ticket (V1.85 §10.6.5 Table 112). */
    {
        TPMI_RH_HIERARCHY hier = GetHierarchy(in->keyHandle);
        if(hier == TPM_RH_NULL
           || signObject->publicArea.nameAlg == TPM_ALG_NULL)
        {
            out->validation.tag               = TPM_ST_DIGEST_VERIFIED;
            out->validation.hierarchy         = TPM_RH_NULL;
            out->validation.metadata.digestVerified = TPM_ALG_NULL;
            out->validation.hmac.t.size       = 0;
        }
        else
        {
            result = TicketComputeVerified(
                hier, &in->digest, &signObject->name, &out->validation);
            if(result != TPM_RC_SUCCESS)
                return result;
            /* Override tag to DIGEST_VERIFIED and record hash algorithm. */
            out->validation.tag = TPM_ST_DIGEST_VERIFIED;
            out->validation.metadata.digestVerified =
                in->signature.sigAlg == TPM_ALG_HASH_MLDSA
                    ? in->signature.signature.hash_mldsa.hash
                    : TPM_ALG_NULL;
        }
    }

    return TPM_RC_SUCCESS;
}

#endif  /* CC_VerifyDigestSignature */

/* ── Phase 4 streaming stubs ─────────────────────────────────────────────── */

#include "SignSequenceStart_fp.h"

#if CC_SignSequenceStart
TPM_RC
TPM2_SignSequenceStart(SignSequenceStart_In *in, SignSequenceStart_Out *out)
{
    /* Phase 4: requires MLDSA_SEQUENCE_OBJECT (cross-command EVP_MD_CTX). */
    (void)in; (void)out;
    return TPM_RC_COMMAND_CODE;
}
#endif

#include "SignSequenceComplete_fp.h"

#if CC_SignSequenceComplete
TPM_RC
TPM2_SignSequenceComplete(SignSequenceComplete_In *in, SignSequenceComplete_Out *out)
{
    (void)in; (void)out;
    return TPM_RC_COMMAND_CODE;
}
#endif

#include "VerifySequenceStart_fp.h"

#if CC_VerifySequenceStart
TPM_RC
TPM2_VerifySequenceStart(VerifySequenceStart_In *in, VerifySequenceStart_Out *out)
{
    (void)in; (void)out;
    return TPM_RC_COMMAND_CODE;
}
#endif

#include "VerifySequenceComplete_fp.h"

#if CC_VerifySequenceComplete
TPM_RC
TPM2_VerifySequenceComplete(VerifySequenceComplete_In *in, VerifySequenceComplete_Out *out)
{
    (void)in; (void)out;
    return TPM_RC_COMMAND_CODE;
}
#endif
