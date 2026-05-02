/*
 * test_tpm_roundtrip.c — direct libtpms TPM2_CreatePrimary for TPM_ALG_MLDSA,
 * bypassing tpm2-tools (which lacks PQC template support).
 *
 * Links libtpms.so directly, feeds raw TPM command bytes via TPMLIB_Process
 * and parses the raw response. This validates the full marshal + crypto
 * pipeline — from TPM_ALG_ID selector through CryptUtil dispatch to
 * CryptMlDsa.c and back — without relying on tpm2-tools recognising MLDSA.
 *
 * NV strategy: use file-backed NV in a temp directory (no custom callbacks).
 * With custom in-memory callbacks, libtpms_plat__NVEnable() is called twice
 * during MainInit: once for manufacture (zeroes s_NV), and once from
 * _TPM_Init() via _rpc__Signal_NvOn(). With callbacks, the second call
 * re-zeroes s_NV because nv_load still returns TPM_RETRY (nv_store hasn't
 * committed yet). File-backed NV avoids this: s_NvFile != NULL short-circuits
 * the second _plat__NVEnable_NVChipFile() call, preserving manufactured state.
 *
 * Copyright 2026 PQC Today. BSD-3-Clause.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>

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

/* Parse tag(2) + size(4) + responseCode(4). Return responseCode. */
static uint32_t
response_rc(const uint8_t *buf, uint32_t len)
{
    if (len < 10) return 0xFFFFFFFF;
    return get_u32(buf + 6);
}

/* Remove a file by name, ignoring errors. */
static void rm_f(const char *path) { (void)remove(path); }

int main(void)
{
    /* Create a temp directory and chdir into it so libtpms's file-backed NV
     * (NVChip file) lands there and is cleaned up on exit. */
    char tmpdir[] = "/tmp/tpm2-rtrip-XXXXXX";
    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp");
        FAIL("mkdtemp");
        return 1;
    }
    /* Save original cwd so we can clean up tmpdir later. */
    char origcwd[4096];
    if (getcwd(origcwd, sizeof(origcwd)) == NULL) {
        perror("getcwd");
        FAIL("getcwd");
        return 1;
    }
    if (chdir(tmpdir) != 0) {
        perror("chdir");
        FAIL("chdir %s", tmpdir);
        return 1;
    }

    /* No custom NV callbacks: libtpms uses file-backed NV (NVChip in cwd).
     * Manufacture writes NVChip; second _plat__NVEnable_NVChipFile() call is
     * a no-op (s_NvFile != NULL), so manufactured state is preserved. */
    TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (TPMLIB_MainInit() != TPM_SUCCESS) {
        FAIL("TPMLIB_MainInit");
        goto cleanup;
    }
    PASS("TPMLIB_MainInit (file-backed NV in %s)", tmpdir);

    uint8_t cmd[1024], resp[16384];
    uint32_t resp_len;

    /* TPM2_Startup(CLEAR) */
    {
        uint8_t *p = cmd;
        p = put_u16(p, TPM_ST_NO_SESSIONS);
        p = put_u32(p, 0);                  /* placeholder size */
        p = put_u32(p, TPM_CC_Startup);
        p = put_u16(p, 0);                  /* TPM_SU_CLEAR */
        uint32_t len = (uint32_t)(p - cmd);
        put_u32(cmd + 2, len);
        resp_len = sizeof(resp);
        if (send_command(cmd, len, resp, &resp_len) != 0
                || response_rc(resp, resp_len) != 0) {
            FAIL("TPM2_Startup(CLEAR) rc=0x%08x", response_rc(resp, resp_len));
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
        /* auth area: 9 bytes for empty-password session */
        p = put_u32(p, 9);
        p = put_u32(p, TPM_RS_PW);
        p = put_u16(p, 0);                        /* nonce size = 0 */
        *p++ = 0;                                 /* sessionAttributes = 0 */
        p = put_u16(p, 0);                        /* hmac size = 0 */
        /* inSensitive: size=4, userAuth.size=0, data.size=0 */
        p = put_u16(p, 4);
        p = put_u16(p, 0);
        p = put_u16(p, 0);
        /* inPublic: TPM2B_PUBLIC with TPMT_PUBLIC */
        uint8_t *pub_size_ptr = p;
        p = put_u16(p, 0);                        /* placeholder */
        uint8_t *pub_start = p;
        p = put_u16(p, TPM_ALG_MLDSA);            /* type */
        p = put_u16(p, TPM_ALG_SHA256);           /* nameAlg */
        p = put_u32(p, TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                        TPMA_OBJECT_SENSITIVEDATAORIGIN |
                        TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN);
        p = put_u16(p, 0);                        /* authPolicy size = 0 */
        /* TPMS_MLDSA_PARMS (V1.85 RC4 Table 229): { parameterSet, allowExternalMu } */
        p = put_u16(p, TPM_MLDSA_65);
        *p++ = 0;                                 /* allowExternalMu = NO */
        /* unique: TPM2B_PUBLIC_KEY_MLDSA size = 0 (TPM populates on keygen) */
        p = put_u16(p, 0);
        put_u16(pub_size_ptr, (uint16_t)(p - pub_start));
        /* outsideInfo */
        p = put_u16(p, 0);
        /* creationPCR count=0 */
        p = put_u32(p, 0);

        uint32_t len = (uint32_t)(p - cmd);
        put_u32(cmd + 2, len);
        resp_len = sizeof(resp);
        int io_rc = send_command(cmd, len, resp, &resp_len);
        uint32_t rc = response_rc(resp, resp_len);
        if (io_rc != 0 || rc != 0) {
            FAIL("TPM2_CreatePrimary(MLDSA-65) rc=0x%08x", rc);
            goto done;
        }
        PASS("TPM2_CreatePrimary(MLDSA-65) succeeded (%u byte response)", resp_len);

        /* Parse the response to verify outPublic fields.
         * Layout after header (10 B): new-handle(4), paramSize(4),
         * TPM2B_PUBLIC{size(2), TPMT_PUBLIC{type(2), nameAlg(2),
         * attributes(4), authPolicy(2+), parms(2), unique(2+pk)}}, ... */
        const uint8_t *q = resp + 10;
        q += 4;                              /* new-handle */
        q += 4;                              /* parameterSize (TPM_ST_SESSIONS) */
        uint16_t out_pub_sz = get_u16(q); q += 2;
        (void)out_pub_sz;
        const uint8_t *pub_start_r = q;
        uint16_t out_type = get_u16(q); q += 2;
        q += 2;                              /* nameAlg */
        q += 4;                              /* objectAttributes */
        uint16_t auth_pol_sz = get_u16(q); q += 2 + auth_pol_sz;
        /* TPMS_MLDSA_PARMS = { parameterSet(2), allowExternalMu(1) } = 3 B */
        uint16_t ps = get_u16(q); q += 2;
        q += 1;                              /* allowExternalMu byte */
        uint16_t pk_sz = get_u16(q);        /* unique.size */
        (void)pub_start_r;

        if (out_type != TPM_ALG_MLDSA) {
            FAIL("outPublic.type=0x%04x expected TPM_ALG_MLDSA(0x%04x)",
                 out_type, TPM_ALG_MLDSA);
            goto done;
        }
        if (ps != TPM_MLDSA_65) {
            FAIL("outPublic parameterSet=0x%04x expected MLDSA_65(0x%04x)",
                 ps, TPM_MLDSA_65);
            goto done;
        }
        if (pk_sz != 1952) {
            FAIL("outPublic.unique.size=%u, expected 1952 (ML-DSA-65 pk per FIPS 204)",
                 pk_sz);
            goto done;
        }
        PASS("outPublic: TPM_ALG_MLDSA, paramSet=MLDSA-65, pk=%u B — FIPS 204 compliant",
             pk_sz);
    }

 done:
    TPMLIB_Terminate();

 cleanup:
    /* Clean up temp NV file and directory. */
    if (chdir(origcwd) == 0) {
        char nvpath[4096 + 8];
        snprintf(nvpath, sizeof(nvpath), "%s/NVChip", tmpdir);
        rm_f(nvpath);
        rmdir(tmpdir);
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
