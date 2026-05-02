/********************************************************************************/
/*                                                                              */
/*  PqcSequence.c — V1.85 RC4 Phase 4 sign/verify sequence slot pool            */
/*  Written for pqctoday-tpm (Copyright 2026 PQC Today)                         */
/*  BSD-3-Clause                                                                */
/*                                                                              */
/********************************************************************************/

#include "Tpm.h"
#include "PqcSequence_fp.h"

#if (ALG_MLDSA || ALG_HASH_MLDSA) && (CC_SignSequenceStart || CC_SignSequenceComplete \
                                       || CC_VerifySequenceStart || CC_VerifySequenceComplete)

/* Static slot pool; kept module-private so the only ways to mutate state are
 * the Allocate / Flush / Update functions exported below. */
static PQC_SEQ_STATE s_pqcSequences[MAX_PQC_SEQ_OBJECTS];

/* Sequence handles are recycled — the next-allocate counter wraps around. */
static UINT16 s_nextSeqIndex;

LIB_EXPORT void
PqcSequenceStartup(void)
{
    MemorySet(s_pqcSequences, 0, sizeof(s_pqcSequences));
    s_nextSeqIndex = 0;
}

LIB_EXPORT PQC_SEQ_STATE *
PqcSequenceAllocate(BOOL isSign)
{
    UINT16 i;
    for (i = 0; i < MAX_PQC_SEQ_OBJECTS; i++) {
        if (!s_pqcSequences[i].occupied) {
            PQC_SEQ_STATE *seq = &s_pqcSequences[i];
            MemorySet(seq, 0, sizeof(*seq));
            seq->occupied = TRUE;
            seq->isSign   = isSign;
            seq->handle   = (TPM_HANDLE)(PQC_SEQ_HANDLE_BASE + i);
            return seq;
        }
    }
    return NULL;  /* TPM_RC_OBJECT_MEMORY at caller */
}

LIB_EXPORT BOOL
PqcSequenceIsHandle(TPM_HANDLE handle)
{
    return handle >= PQC_SEQ_HANDLE_BASE && handle <= PQC_SEQ_HANDLE_MAX;
}

LIB_EXPORT PQC_SEQ_STATE *
PqcSequenceFromHandle(TPM_HANDLE handle)
{
    UINT16 idx;
    if (!PqcSequenceIsHandle(handle))
        return NULL;
    idx = (UINT16)(handle - PQC_SEQ_HANDLE_BASE);
    if (idx >= MAX_PQC_SEQ_OBJECTS)
        return NULL;
    return s_pqcSequences[idx].occupied ? &s_pqcSequences[idx] : NULL;
}

LIB_EXPORT void
PqcSequenceFlush(TPM_HANDLE handle)
{
    PQC_SEQ_STATE *seq = PqcSequenceFromHandle(handle);
    if (seq) {
        /* Zero the whole struct — buffer may carry secret-adjacent data
         * (the message being signed/verified is not necessarily secret,
         * but defensive zeroing is cheap). */
        MemorySet(seq, 0, sizeof(*seq));
    }
    (void)s_nextSeqIndex; /* reserved for future round-robin allocation */
}

LIB_EXPORT TPM_RC
PqcSequenceUpdate(PQC_SEQ_STATE *seq, const BYTE *data, UINT16 dataLen)
{
    if (seq == NULL)
        return TPM_RC_HANDLE;

    /* V1.85 §17.5: "for EdDSA signing, TPM2_SequenceUpdate() is not allowed,
     * because the TPM needs to buffer the entire message when producing
     * EdDSA signatures." FIPS 204 ML-DSA has the same property (μ is
     * computed over the entire message before the signing iteration), so
     * we apply the same gate. The error code is TPM_RC_ONE_SHOT_SIGNATURE
     * per V1.85 §6.6.4 + §20.6. */
    if (seq->isSign)
        return TPM_RC_ONE_SHOT_SIGNATURE;

    if (dataLen == 0)
        return TPM_RC_SUCCESS;
    if ((UINT32)seq->bufferUsed + dataLen > MAX_PQC_SEQ_BUFFER)
        return TPM_RC_SIZE;
    MemoryCopy(&seq->buffer[seq->bufferUsed], data, dataLen);
    seq->bufferUsed += dataLen;
    return TPM_RC_SUCCESS;
}

#endif  /* sequence commands enabled */
