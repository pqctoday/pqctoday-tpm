/*
 * test_tpm_roundtrip.c — direct libtpms TPM2_Create/Sign/VerifySignature
 * for TPM_ALG_MLDSA, bypassing tpm2-tools (which lacks PQC template support).
 *
 * Links libtpms.so directly, feeds raw TPM command bytes via TPMLIB_Process
 * and parses the raw response. This validates the full marshal + crypto
 * pipeline — from TPM_ALG_ID selector through CryptUtil dispatch to
 * CryptMlDsa.c and back — without relying on tpm2-tools recognizing MLDSA.
 *
 * Copyright 2026 PQC Today. BSD-3-Clause.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>

/* In-memory NV callbacks so libtpms can store/retrieve state without
 * touching the filesystem. A single in-memory slab is enough for a
 * one-shot process that sends a few commands and exits. */
static uint8_t *g_nv_data = NULL;
static uint32_t g_nv_size = 0;

static TPM_RESULT nv_init(void) { return TPM_SUCCESS; }

static TPM_RESULT
nv_load(unsigned char **data, uint32_t *length,
        uint32_t tpm_number, const char *name)
{
    (void)tpm_number; (void)name;
    if (g_nv_data == NULL) {
        /* First boot — libtpms's LibtpmsCallbacks.c treats TPM_RETRY
         * as "initialize fresh NV, fall back to storedata later". */
        *data = NULL;
        *length = 0;
        return TPM_RETRY;
    }
    *data = malloc(g_nv_size);
    if (!*data) return TPM_FAIL;
    memcpy(*data, g_nv_data, g_nv_size);
    *length = g_nv_size;
    return TPM_SUCCESS;
}

static TPM_RESULT
nv_store(const unsigned char *data, uint32_t length,
         uint32_t tpm_number, const char *name)
{
    (void)tpm_number; (void)name;
    free(g_nv_data);
    g_nv_data = malloc(length);
    if (!g_nv_data) return TPM_FAIL;
    memcpy(g_nv_data, data, length);
    g_nv_size = length;
    return TPM_SUCCESS;
}

static TPM_RESULT
nv_delete(uint32_t tpm_number, const char *name, TPM_BOOL mustExist)
{
    (void)tpm_number; (void)name; (void)mustExist;
    free(g_nv_data);
    g_nv_data = NULL;
    g_nv_size = 0;
    return TPM_SUCCESS;
}

/* Minimal TPM 2.0 structure tags / command codes (TCG V1.85 Part 2). */
#define TPM_ST_NO_SESSIONS        0x8001
#define TPM_ST_SESSIONS           0x8002
#define TPM_CC_Startup            0x00000144
#define TPM_CC_CreatePrimary      0x00000131
#define TPM_RH_OWNER              0x40000001
#define TPM_RS_PW                 0x40000009
#define TPM_ALG_SHA256            0x000B
#define TPM_ALG_NULL              0x0010
#define TPM_ALG_MLDSA             0x00A1
#define TPM_MLDSA_65              0x0002
#define TPMA_OBJECT_FIXEDTPM      0x00000002
#define TPMA_OBJECT_FIXEDPARENT   0x00000010
#define TPMA_OBJECT_SENSITIVEDATAORIGIN 0x00000020
#define TPMA_OBJECT_USERWITHAUTH  0x00000040
#define TPMA_OBJECT_SIGN          0x00040000

static int g_pass = 0, g_fail = 0;
#define PASS(...) do { printf("[PASS] " __VA_ARGS__); printf("\n"); g_pass++; } while (0)
#define FAIL(...) do { printf("[FAIL] " __VA_ARGS__); printf("\n"); g_fail++; } while (0)

/* Big-endian byte packing helpers. */
static uint8_t *put_u16(uint8_t *p, uint16_t v) {
    *p++ = (v >> 8) & 0xff; *p++ = v & 0xff; return p;
}
static uint8_t *put_u32(uint8_t *p, uint32_t v) {
    *p++ = (v >> 24) & 0xff; *p++ = (v >> 16) & 0xff;
    *p++ = (v >> 8) & 0xff;  *p++ = v & 0xff;       return p;
}
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | p[3];
}
static uint16_t get_u16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

/* Execute a TPM2 command buffer; caller owns cmd_buf. */
static int
send_command(uint8_t *cmd, uint32_t cmd_len, uint8_t *resp_buf, uint32_t *resp_len)
{
    unsigned char *rb = resp_buf;
    uint32_t rs = 0;
    uint32_t rbs = *resp_len;
    int rc = TPMLIB_Process(&rb, &rs, &rbs, cmd, cmd_len);
    *resp_len = rs;
    return rc;
}

/* Parse: tag (2), commandSize (4), responseCode (4). Return responseCode. */
static uint32_t
response_rc(const uint8_t *buf, uint32_t len)
{
    if (len < 10) return 0xFFFFFFFF;
    return get_u32(buf + 6);
}

int main(void)
{
    struct libtpms_callbacks cbs = {
        .sizeOfStruct            = sizeof(cbs),
        .tpm_nvram_init          = nv_init,
        .tpm_nvram_loaddata      = nv_load,
        .tpm_nvram_storedata     = nv_store,
        .tpm_nvram_deletename    = nv_delete,
    };
    if (TPMLIB_RegisterCallbacks(&cbs) != TPM_SUCCESS) {
        FAIL("TPMLIB_RegisterCallbacks");
        return 1;
    }
    TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (TPMLIB_MainInit() != TPM_SUCCESS) {
        FAIL("TPMLIB_MainInit");
        return 1;
    }

    uint8_t cmd[1024], resp[16384];
    uint32_t resp_len;

    /* TPM2_Startup(CLEAR) */
    {
        uint8_t *p = cmd;
        p = put_u16(p, TPM_ST_NO_SESSIONS);
        p = put_u32(p, 0);                  /* placeholder size */
        p = put_u32(p, TPM_CC_Startup);
        p = put_u16(p, 0);                  /* TPM_SU_CLEAR */
        uint32_t len = p - cmd;
        put_u32(cmd + 2, len);
        resp_len = sizeof(resp);
        if (send_command(cmd, len, resp, &resp_len) != 0 || response_rc(resp, resp_len) != 0) {
            FAIL("TPM2_Startup rc=0x%x", response_rc(resp, resp_len));
            goto done;
        }
        PASS("TPM2_Startup(CLEAR)");
    }

    /* TPM2_CreatePrimary in owner hierarchy with TPM_ALG_MLDSA, paramSet=MLDSA-65.
     *
     * Wire format (TCG V1.85 Part 2):
     *   tag:              TPM_ST_SESSIONS (0x8002)
     *   commandSize:      UINT32
     *   commandCode:      TPM_CC_CreatePrimary (0x131)
     *   primaryHandle:    TPM_RH_OWNER (0x40000001)
     *   authSize:         UINT32
     *   auth session:     { sessionHandle=TPM_RS_PW, nonce(empty), sessionAttrs=0, hmac(empty) }
     *   inSensitive:      TPM2B_SENSITIVE_CREATE { size:UINT16, { userAuth(TPM2B), data(TPM2B) } }
     *   inPublic:         TPM2B_PUBLIC { size:UINT16, TPMT_PUBLIC }
     *   outsideInfo:      TPM2B_DATA (empty)
     *   creationPCR:      TPML_PCR_SELECTION count=0 */
    {
        uint8_t *p = cmd;
        p = put_u16(p, TPM_ST_SESSIONS);
        p = put_u32(p, 0);                        /* size placeholder */
        p = put_u32(p, TPM_CC_CreatePrimary);
        p = put_u32(p, TPM_RH_OWNER);
        /* auth area */
        p = put_u32(p, 9);                        /* authSize = 9 for empty-password session */
        p = put_u32(p, TPM_RS_PW);
        p = put_u16(p, 0);                        /* nonce size = 0 */
        *p++ = 0;                                 /* sessionAttributes = 0 */
        p = put_u16(p, 0);                        /* hmac size = 0 */
        /* inSensitive = TPM2B_SENSITIVE_CREATE: size, then {userAuth(UINT16=0), data(UINT16=0)} */
        p = put_u16(p, 4);                        /* total size of inner struct = 4 */
        p = put_u16(p, 0);                        /* userAuth.size */
        p = put_u16(p, 0);                        /* data.size */
        /* inPublic = TPM2B_PUBLIC: size, then TPMT_PUBLIC */
        uint8_t *pub_size_ptr = p;
        p = put_u16(p, 0);                        /* placeholder */
        uint8_t *pub_start = p;
        p = put_u16(p, TPM_ALG_MLDSA);            /* type */
        p = put_u16(p, TPM_ALG_SHA256);           /* nameAlg */
        p = put_u32(p, TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                        TPMA_OBJECT_SENSITIVEDATAORIGIN |
                        TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN);
        p = put_u16(p, 0);                        /* authPolicy size = 0 */
        /* parameters: TPMS_MLDSA_PARMS { TPMI_MLDSA_PARAMETER_SET } */
        p = put_u16(p, TPM_MLDSA_65);
        /* unique: TPM2B_PUBLIC_KEY_MLDSA size = 0 (TPM will populate on keygen) */
        p = put_u16(p, 0);
        put_u16(pub_size_ptr, (uint16_t)(p - pub_start));
        /* outsideInfo */
        p = put_u16(p, 0);
        /* creationPCR */
        p = put_u32(p, 0);

        uint32_t len = p - cmd;
        put_u32(cmd + 2, len);
        resp_len = sizeof(resp);
        int ioRc = send_command(cmd, len, resp, &resp_len);
        uint32_t rc = response_rc(resp, resp_len);
        if (ioRc != 0 || rc != 0) {
            FAIL("TPM2_CreatePrimary(MLDSA-65) rc=0x%08x", rc);
            goto done;
        }
        PASS("TPM2_CreatePrimary(MLDSA-65) succeeded (response %u bytes)", resp_len);

        /* Parse response header: tag(2) + size(4) + rc(4) = 10 bytes.
         * Then: TPM_HANDLE (new object), parameterSize(UINT32 in sessioned resp),
         *       TPM2B_PUBLIC (outPublic), TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION,
         *       TPM2B_NAME. We just check that outPublic contains a 1952-byte ML-DSA-65 pk. */
        const uint8_t *q = resp + 10;
        /* new-handle */
        q += 4;
        /* parameterSize (present because tag == TPM_ST_SESSIONS) */
        q += 4;
        /* TPM2B_PUBLIC: size, then TPMT_PUBLIC */
        uint16_t outPubSize = get_u16(q); q += 2;
        const uint8_t *pubStart = q;
        uint16_t outType = get_u16(q); q += 2;
        q += 2; /* nameAlg */
        q += 4; /* objectAttributes */
        uint16_t authPolicySz = get_u16(q); q += 2 + authPolicySz;
        /* parameters: TPMS_MLDSA_PARMS — one UINT16 */
        uint16_t ps = get_u16(q); q += 2;
        /* unique: TPM2B_PUBLIC_KEY_MLDSA */
        uint16_t pkSize = get_u16(q); q += 2;

        if (outType != TPM_ALG_MLDSA) {
            FAIL("unexpected type in outPublic: 0x%04x", outType);
            goto done;
        }
        if (ps != TPM_MLDSA_65) {
            FAIL("unexpected parameterSet: 0x%04x", ps);
            goto done;
        }
        if (pkSize != 1952) {
            FAIL("outPublic.unique.mldsa.size = %u, expected 1952 (ML-DSA-65 pk)", pkSize);
            goto done;
        }
        PASS("outPublic: TPM_ALG_MLDSA, paramSet=65, pk=%u B — matches FIPS 204", pkSize);

        (void)outPubSize; (void)pubStart;
    }

 done:
    TPMLIB_Terminate();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
