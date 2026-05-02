/*
 * test_pqc_phase3.c — Phase 3 PQC key hierarchy + credential roundtrip tests.
 *
 * Tests (all via TPMLIB_Process — no swtpm socket):
 *   1. TPM2_CreatePrimary(ML-KEM-768) in Endorsement hierarchy → pk = 1184 B
 *   2. TPM2_CreatePrimary(ML-DSA-65 restricted+sign) in Owner hierarchy → pk = 1952 B
 *   3. TPM2_ReadPublic + TPM2_MakeCredential + TPM2_ActivateCredential roundtrip
 *      via ML-KEM-768 transport (CryptSecretEncrypt / CryptSecretDecrypt path)
 *   4. TPM2_SignDigest with restricted ML-DSA AK → TPM_RC_ATTRIBUTES (V1.85 §29.2.1
 *      restriction: arbitrary-digest signing is not allowed on restricted keys)
 *   5. TPM2_CreatePrimary(ML-DSA-65 unrestricted) + TPM2_SignDigest → success;
 *      verify sigAlg = MLDSA, sig size = 3309 B (FIPS 204 ML-DSA-65 signature size)
 *
 * Spec references (all TCG TPM 2.0 Library Spec V1.85 RC4):
 *   ML-KEM-768 ciphertext size 1088 B: Part 2 §11.2.6 Table 204
 *   ML-DSA-65 public key  size 1952 B: Part 2 §11.2.7 Table 207
 *   ML-DSA-65 signature   size 3309 B: Part 2 §11.2.7 Table 207
 *   MakeCredential / ActivateCredential: Part 3 §12.5-§12.6
 *   TPM2_SignDigest restriction: Part 3 §29.2.1; Part 1 §22.1.2
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

/* ── TPM 2.0 constants (TCG V1.85 RC4) ──────────────────────────────────── */

#define TPM_ST_NO_SESSIONS        0x8001u
#define TPM_ST_SESSIONS           0x8002u
#define TPM_CC_Startup            0x00000144u
#define TPM_CC_CreatePrimary      0x00000131u
#define TPM_CC_ReadPublic         0x00000173u
#define TPM_CC_MakeCredential     0x00000168u  /* Part 2 Table 11 */
#define TPM_CC_ActivateCredential 0x00000147u
#define TPM_CC_SignDigest         0x000001A6u  /* V1.85 §29.2.1 */

#define TPM_RH_OWNER              0x40000001u
#define TPM_RH_ENDORSEMENT        0x4000000Bu
#define TPM_RS_PW                 0x40000009u  /* password pseudo-session */

#define TPM_ALG_SHA256            0x000Bu
#define TPM_ALG_AES               0x0006u
#define TPM_ALG_CFB               0x0043u
#define TPM_ALG_NULL              0x0010u
#define TPM_ALG_MLDSA             0x00A1u  /* TCG Algorithm Registry */
#define TPM_ALG_MLKEM             0x00A0u  /* TCG Algorithm Registry */
#define TPM_MLDSA_65              0x0002u  /* Part 2 Table 207 */
#define TPM_MLKEM_768             0x0002u  /* Part 2 Table 204 */
#define TPM_NO                    0x00u
#define TPM_YES                   0x01u

/* TPMA_OBJECT bit fields (Part 2 §8.3 Table 36) */
#define TPMA_FIXEDTPM             0x00000002u
#define TPMA_FIXEDPARENT          0x00000010u
#define TPMA_SENSITIVEDATA        0x00000020u
#define TPMA_USERWITHAUTH         0x00000040u
#define TPMA_RESTRICTED           0x00010000u
#define TPMA_DECRYPT              0x00020000u
#define TPMA_SIGN                 0x00040000u

/* Error code constants (Part 2 §6.6 Table 17) */
#define RC_FMT1                   0x00000080u   /* format-1 error bit */
#define RC_ATTRIBUTES             (RC_FMT1 | 0x002u)  /* 0x082 */

/* PQC size constants (Part 2 Tables 204, 207 — spec-authoritative) */
#define MLKEM_768_PK_SIZE         1184
#define MLKEM_768_CT_SIZE         1088
#define MLDSA_65_PK_SIZE          1952
#define MLDSA_65_SIG_SIZE         3309

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;
#define PASS(...) do { printf("[PASS] " __VA_ARGS__); printf("\n"); g_pass++; } while (0)
#define FAIL(...) do { printf("[FAIL] " __VA_ARGS__); printf("\n"); g_fail++; } while (0)

static uint8_t *put_u16(uint8_t *p, uint16_t v)
{
    *p++ = (v >> 8) & 0xff; *p++ = v & 0xff; return p;
}
static uint8_t *put_u32(uint8_t *p, uint32_t v)
{
    *p++ = (v >> 24) & 0xff; *p++ = (v >> 16) & 0xff;
    *p++ = (v >> 8) & 0xff;  *p++ = v & 0xff; return p;
}
static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | p[3];
}
static uint16_t get_u16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static int
send_command(uint8_t *cmd, uint32_t cmd_len,
             uint8_t *resp_buf, uint32_t *resp_len)
{
    unsigned char *rb = resp_buf;
    uint32_t rs = 0, rbs = *resp_len;
    int rc = TPMLIB_Process(&rb, &rs, &rbs, cmd, cmd_len);
    *resp_len = rs;
    return rc;
}

static uint32_t
response_rc(const uint8_t *buf, uint32_t len)
{
    if (len < 10) return 0xFFFFFFFFu;
    return get_u32(buf + 6);
}

static void rm_f(const char *path) { (void)remove(path); }

/*
 * Build and send a TPM2_CreatePrimary for a PQC key.
 *
 * Template: type(algid) + nameAlg(SHA-256) + attrs + empty authPolicy +
 *           TPMS_{MLDSA|MLKEM}_PARMS{parameterSet} + empty unique.
 * The session is empty-password (TPM_RS_PW, empty auth).
 *
 * Returns the TPM response code; writes the full response to resp[resp_max].
 * On success (rc == 0) the transient handle is at resp[10..13].
 */
static uint32_t
do_create_primary(uint32_t hierarchy, uint16_t algid, uint16_t parameterset,
                  uint32_t attrs, uint8_t *resp, uint32_t resp_max)
{
    uint8_t cmd[512];
    uint8_t *p = cmd;

    p = put_u16(p, (uint16_t)TPM_ST_SESSIONS);
    p = put_u32(p, 0);                         /* size placeholder */
    p = put_u32(p, TPM_CC_CreatePrimary);
    p = put_u32(p, hierarchy);
    /* auth area: one empty-password session (9 bytes) */
    p = put_u32(p, 9);
    p = put_u32(p, TPM_RS_PW); p = put_u16(p, 0); *p++ = 0; p = put_u16(p, 0);
    /* inSensitive: size=4, userAuth.size=0, data.size=0 */
    p = put_u16(p, 4); p = put_u16(p, 0); p = put_u16(p, 0);
    /* inPublic: TPM2B_PUBLIC */
    uint8_t *pub_size_ptr = p;
    p = put_u16(p, 0);                         /* TPM2B size placeholder */
    uint8_t *pub_start = p;
    p = put_u16(p, algid);                     /* type */
    p = put_u16(p, (uint16_t)TPM_ALG_SHA256);  /* nameAlg */
    p = put_u32(p, attrs);                     /* objectAttributes */
    p = put_u16(p, 0);                         /* authPolicy.size = 0 */
    /* V1.85 RC4 Part 2 Tables 229-231: PQC parameter blocks. Layout depends
     * on the key type — we have to write the spec-canonical wire form here
     * because libtpms unmarshals byte-for-byte against TPMS_{MLKEM|MLDSA}_PARMS. */
    if (algid == (uint16_t)TPM_ALG_MLKEM) {
        /* TPMS_MLKEM_PARMS = { symmetric (TPMT_SYM_DEF_OBJECT+), parameterSet }.
         * For restricted decrypt keys, symmetric MUST be an AEAD-capable sym alg
         * (Part 2 §12.2.3.8); for unrestricted keys, TPM_ALG_NULL is required. */
        if (attrs & TPMA_RESTRICTED) {
            p = put_u16(p, (uint16_t)TPM_ALG_AES);  /* symmetric.algorithm */
            p = put_u16(p, 128);                    /* keyBits.aes */
            p = put_u16(p, (uint16_t)TPM_ALG_CFB);  /* mode.aes */
        } else {
            p = put_u16(p, (uint16_t)TPM_ALG_NULL); /* symmetric.algorithm = NULL → no keyBits/mode */
        }
        p = put_u16(p, parameterset);               /* parameterSet (last) */
    } else if (algid == (uint16_t)TPM_ALG_MLDSA) {
        /* TPMS_MLDSA_PARMS = { parameterSet, allowExternalMu }. */
        p = put_u16(p, parameterset);
        *p++ = TPM_NO;                              /* allowExternalMu = NO (default) */
    } else {
        /* HashML-DSA / unknown — keep simple parameterSet form for callers. */
        p = put_u16(p, parameterset);
    }
    /* unique: size = 0 (TPM generates) */
    p = put_u16(p, 0);
    put_u16(pub_size_ptr, (uint16_t)(p - pub_start));
    p = put_u16(p, 0);                         /* outsideInfo: empty */
    p = put_u32(p, 0);                         /* creationPCR: count = 0 */

    uint32_t len = (uint32_t)(p - cmd);
    put_u32(cmd + 2, len);

    uint32_t resp_len = resp_max;
    if (send_command(cmd, len, resp, &resp_len) != 0)
        return 0xFFFFFFFFu;
    return response_rc(resp, resp_len);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    char tmpdir[] = "/tmp/tpm2-ph3-XXXXXX";
    if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return 1; }

    char origcwd[4096];
    if (!getcwd(origcwd, sizeof(origcwd))) { perror("getcwd"); return 1; }
    if (chdir(tmpdir) != 0)               { perror("chdir");  return 1; }

    /* File-backed NV in mkdtemp(): second _plat__NVEnable_NVChipFile() call
     * short-circuits (s_NvFile != NULL), preserving manufactured state. */
    TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    /* Use default-v1 profile so V1.85 PQC commands (0x1a5-0x1a8) are enabled.
     * The null profile (used when no profile is set) is frozen at libtpms v0.9
     * and does not include commands beyond 0x197. */
    if (TPMLIB_SetProfile("{\"Name\":\"default-v1\"}") != TPM_SUCCESS) {
        FAIL("TPMLIB_SetProfile(default-v1)");
        goto cleanup;
    }
    if (TPMLIB_MainInit() != TPM_SUCCESS) {
        FAIL("TPMLIB_MainInit");
        goto cleanup;
    }
    PASS("TPMLIB_MainInit (file-backed NV in %s)", tmpdir);

    /* Single large buffer reused for every command / response pair. */
    uint8_t resp[8192];
    uint32_t resp_len;

    /* TPM2_Startup(CLEAR) */
    {
        uint8_t cmd[12]; uint8_t *p = cmd;
        p = put_u16(p, (uint16_t)TPM_ST_NO_SESSIONS);
        p = put_u32(p, 12);
        p = put_u32(p, TPM_CC_Startup);
        p = put_u16(p, 0);   /* TPM_SU_CLEAR */
        resp_len = sizeof(resp);
        if (send_command(cmd, 12, resp, &resp_len)
                || response_rc(resp, resp_len) != 0) {
            FAIL("TPM2_Startup(CLEAR) rc=0x%08x", response_rc(resp, resp_len));
            goto done;
        }
        PASS("TPM2_Startup(CLEAR)");
    }

    uint32_t ekHandle = 0, akHandle = 0;

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     * Test 1 — TPM2_CreatePrimary(ML-KEM-768) in Endorsement hierarchy
     * Validates: CryptIsAsymAlgorithm handles MLKEM, CryptMlKemGenerateKey
     * runs, public key size = 1184 B (FIPS 203 ML-KEM-768).
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    {
        uint32_t attrs = TPMA_FIXEDTPM | TPMA_FIXEDPARENT | TPMA_SENSITIVEDATA
                       | TPMA_USERWITHAUTH | TPMA_RESTRICTED | TPMA_DECRYPT;
        uint32_t rc = do_create_primary(TPM_RH_ENDORSEMENT, (uint16_t)TPM_ALG_MLKEM,
                                        (uint16_t)TPM_MLKEM_768, attrs,
                                        resp, sizeof(resp));
        if (rc != 0) {
            FAIL("CreatePrimary(ML-KEM-768) rc=0x%08x", rc);
            goto done;
        }
        ekHandle = get_u32(resp + 10);

        /* Parse outPublic. TPMS_MLKEM_PARMS for restricted decrypt EK is
         * { sym.alg=AES(2), sym.keyBits=128(2), sym.mode=CFB(2), parameterSet(2) }
         * = 8 bytes. Layout: type(2)+nameAlg(2)+attrs(4)+policy(2)+parms(8). */
        const uint8_t *q = resp + 18;         /* start of outPublic TPM2B */
        q += 2;                               /* skip outPublic.size field */
        uint16_t pub_type = get_u16(q); q += 2+2+4+2+8;   /* type,alg,attr,policy,parms(8) */
        uint16_t pk_sz    = get_u16(q);       /* unique.size */

        if (pub_type != (uint16_t)TPM_ALG_MLKEM || pk_sz != MLKEM_768_PK_SIZE) {
            FAIL("EK type=0x%04x pk=%u — expected MLKEM+%d", pub_type, pk_sz, MLKEM_768_PK_SIZE);
            goto done;
        }
        PASS("CreatePrimary(ML-KEM-768): handle=0x%08x, pk=%u B (FIPS 203)", ekHandle, pk_sz);
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     * Test 2 — TPM2_CreatePrimary(ML-DSA-65 restricted+sign) in Owner hierarchy
     * Validates: CryptIsAsymAlgorithm handles MLDSA, CryptMlDsaGenerateKey
     * runs, public key size = 1952 B (FIPS 204 ML-DSA-65).
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    {
        uint32_t attrs = TPMA_FIXEDTPM | TPMA_FIXEDPARENT | TPMA_SENSITIVEDATA
                       | TPMA_USERWITHAUTH | TPMA_RESTRICTED | TPMA_SIGN;
        uint32_t rc = do_create_primary(TPM_RH_OWNER, (uint16_t)TPM_ALG_MLDSA,
                                        (uint16_t)TPM_MLDSA_65, attrs,
                                        resp, sizeof(resp));
        if (rc != 0) {
            FAIL("CreatePrimary(ML-DSA-65 restricted) rc=0x%08x", rc);
            goto done;
        }
        akHandle = get_u32(resp + 10);

        /* TPMS_MLDSA_PARMS = { parameterSet(2), allowExternalMu(1) } = 3 bytes.
         * Layout: type(2)+nameAlg(2)+attrs(4)+policy(2)+parms(3). */
        const uint8_t *q = resp + 18;
        q += 2;
        uint16_t pub_type = get_u16(q); q += 2+2+4+2+3;
        uint16_t pk_sz    = get_u16(q);

        if (pub_type != (uint16_t)TPM_ALG_MLDSA || pk_sz != MLDSA_65_PK_SIZE) {
            FAIL("AK type=0x%04x pk=%u — expected MLDSA+%d", pub_type, pk_sz, MLDSA_65_PK_SIZE);
            goto done;
        }
        PASS("CreatePrimary(ML-DSA-65 restricted+sign): handle=0x%08x, pk=%u B", akHandle, pk_sz);
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     * Test 3 — MakeCredential + ActivateCredential roundtrip via ML-KEM-768
     *
     * MakeCredential uses CryptSecretEncrypt(ML-KEM-768) to protect a seed;
     * ActivateCredential uses CryptSecretDecrypt(ML-KEM-768) to recover it.
     * Verifies the full KEM-based credential transport path.
     *
     * Steps:
     *   3a  ReadPublic(akHandle)       → save AK name (34 B for SHA-256)
     *   3b  MakeCredential(ekHandle, credential[16], akName)
     *         → credentialBlob + encryptedSecret (1088 B ML-KEM-768 ciphertext)
     *   3c  ActivateCredential(akHandle, ekHandle, credBlob, encSecret)
     *         → certInfo must equal original credential
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    {
        /* 3a ── ReadPublic(akHandle) ─────────────────────────────────────── */
        {
            uint8_t cmd[14]; uint8_t *p = cmd;
            p = put_u16(p, (uint16_t)TPM_ST_NO_SESSIONS);
            p = put_u32(p, 14);
            p = put_u32(p, TPM_CC_ReadPublic);
            p = put_u32(p, akHandle);
            resp_len = sizeof(resp);
            if (send_command(cmd, 14, resp, &resp_len)
                    || response_rc(resp, resp_len) != 0) {
                FAIL("ReadPublic(akHandle) rc=0x%08x", response_rc(resp, resp_len));
                goto done;
            }
        }

        /* ReadPublic response (TPM_ST_NO_SESSIONS):
         *   header(10) | outPublic TPM2B {size(2) + TPMT_PUBLIC} | name TPM2B | qualName TPM2B
         * Skip past outPublic to reach the name. */
        uint8_t ak_name[68];    /* SHA-256 name = 2-byte alg + 32-byte digest = 34 B max */
        uint16_t ak_name_size;
        {
            const uint8_t *rp = resp + 10;
            uint16_t op_sz = get_u16(rp); rp += 2 + op_sz;  /* skip outPublic TPM2B */
            ak_name_size = get_u16(rp); rp += 2;
            if (ak_name_size == 0 || ak_name_size > (uint16_t)sizeof(ak_name)) {
                FAIL("AK name size=%u out of expected range", ak_name_size);
                goto done;
            }
            memcpy(ak_name, rp, ak_name_size);
        }
        PASS("ReadPublic(AK): name=%u B (SHA-256: 0x000B + 32-byte digest)", ak_name_size);

        /* 3b ── MakeCredential ────────────────────────────────────────────── */
        /* The credential is a 16-byte secret the caller wants to protect. */
        static const uint8_t credential[16] = {
            0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
            0x09,0x0A,0x0B,0x0C, 0x0D,0x0E,0x0F,0x10
        };
        {
            /* MakeCredential (TPM_ST_NO_SESSIONS):
             *   header(10) | H1: objectHandle(4) | P1: credential TPM2B | P2: objectName TPM2B */
            uint8_t cmd[512]; uint8_t *p = cmd;
            p = put_u16(p, (uint16_t)TPM_ST_NO_SESSIONS);
            p = put_u32(p, 0);                          /* size placeholder */
            p = put_u32(p, TPM_CC_MakeCredential);
            p = put_u32(p, ekHandle);                   /* H1: key used to protect seed */
            p = put_u16(p, 16);                         /* P1: credential.size */
            memcpy(p, credential, 16); p += 16;
            p = put_u16(p, ak_name_size);               /* P2: objectName.size */
            memcpy(p, ak_name, ak_name_size); p += ak_name_size;
            uint32_t len = (uint32_t)(p - cmd);
            put_u32(cmd + 2, len);
            resp_len = sizeof(resp);
            if (send_command(cmd, len, resp, &resp_len)
                    || response_rc(resp, resp_len) != 0) {
                FAIL("MakeCredential rc=0x%08x", response_rc(resp, resp_len));
                goto done;
            }
        }

        /* Extract credentialBlob and encryptedSecret from MakeCredential response.
         * Response (TPM_ST_NO_SESSIONS): header(10) | credentialBlob TPM2B | encryptedSecret TPM2B */
        uint8_t blob_buf[256];
        uint8_t enc_buf[2048];      /* ML-KEM-768 ciphertext = 1088 B */
        uint16_t blob_size, enc_size;
        {
            const uint8_t *mc = resp + 10;
            blob_size = get_u16(mc); mc += 2;
            if (blob_size > (uint16_t)sizeof(blob_buf)) {
                FAIL("credentialBlob too large: %u B", blob_size); goto done;
            }
            memcpy(blob_buf, mc, blob_size); mc += blob_size;
            enc_size = get_u16(mc); mc += 2;
            if (enc_size > (uint16_t)sizeof(enc_buf)) {
                FAIL("encryptedSecret too large: %u B", enc_size); goto done;
            }
            memcpy(enc_buf, mc, enc_size);
        }
        if (enc_size != MLKEM_768_CT_SIZE) {
            FAIL("encryptedSecret size=%u expected %d (ML-KEM-768 ciphertext per FIPS 203 Table 2)",
                 enc_size, MLKEM_768_CT_SIZE);
            goto done;
        }
        PASS("MakeCredential: blob=%u B, encSecret=%u B (ML-KEM-768 ciphertext)", blob_size, enc_size);

        /* 3c ── ActivateCredential ────────────────────────────────────────── */
        /* ActivateCredential (TPM_ST_SESSIONS):
         *   header(10) | H1: activateHandle(4) | H2: keyHandle(4)
         *   authArea(4+18): two password sessions (18 B each minus 4 for size field)
         *   P1: credentialBlob TPM2B | P2: encryptedSecret TPM2B
         *
         * Both handles have userWithAuth + empty auth → password sessions satisfy auth. */
        {
            uint8_t cmd[2560]; uint8_t *p = cmd;
            p = put_u16(p, (uint16_t)TPM_ST_SESSIONS);
            p = put_u32(p, 0);                          /* size placeholder */
            p = put_u32(p, TPM_CC_ActivateCredential);
            p = put_u32(p, akHandle);                   /* H1: activate object */
            p = put_u32(p, ekHandle);                   /* H2: key for decryption */
            /* authArea: 18 bytes (2 × password sessions) */
            p = put_u32(p, 18);
            /* session 1 — akHandle auth (empty password) */
            p = put_u32(p, TPM_RS_PW); p = put_u16(p, 0); *p++ = 0; p = put_u16(p, 0);
            /* session 2 — ekHandle auth (empty password) */
            p = put_u32(p, TPM_RS_PW); p = put_u16(p, 0); *p++ = 0; p = put_u16(p, 0);
            /* P1: credentialBlob */
            p = put_u16(p, blob_size);
            memcpy(p, blob_buf, blob_size); p += blob_size;
            /* P2: encryptedSecret */
            p = put_u16(p, enc_size);
            memcpy(p, enc_buf, enc_size); p += enc_size;
            uint32_t len = (uint32_t)(p - cmd);
            put_u32(cmd + 2, len);
            resp_len = sizeof(resp);
            if (send_command(cmd, len, resp, &resp_len)) {
                FAIL("ActivateCredential: TPMLIB_Process error");
                goto done;
            }
            uint32_t rc = response_rc(resp, resp_len);
            if (rc != 0) {
                FAIL("ActivateCredential rc=0x%08x", rc);
                goto done;
            }
        }

        /* Verify certInfo equals the original credential.
         * Response (TPM_ST_SESSIONS): header(10) | paramSize(4) | certInfo TPM2B | authArea */
        {
            const uint8_t *ac = resp + 10 + 4;      /* skip header + paramSize */
            uint16_t cert_sz = get_u16(ac); ac += 2;
            if (cert_sz != 16 || memcmp(ac, credential, 16) != 0) {
                FAIL("ActivateCredential: certInfo mismatch (size=%u)", cert_sz);
                goto done;
            }
        }
        PASS("MakeCredential + ActivateCredential roundtrip via ML-KEM-768 EK");
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     * Test 4 — SignDigest with restricted ML-DSA AK → TPM_RC_ATTRIBUTES
     *
     * V1.85 §29.2.1: TPM2_SignDigest accepts an arbitrary pre-hashed digest
     * without a hashcheck ticket.  Allowing restricted signing keys here would
     * bypass the restriction property (only TPM-attested hashes may be signed).
     * Expect error class: RC_FMT1 | ATTRIBUTES = 0x082 (handle-1 subject).
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    {
        static const uint8_t digest[32] = {
            0xDE,0xAD,0xBE,0xEF, 0xDE,0xAD,0xBE,0xEF,
            0xDE,0xAD,0xBE,0xEF, 0xDE,0xAD,0xBE,0xEF,
            0xDE,0xAD,0xBE,0xEF, 0xDE,0xAD,0xBE,0xEF,
            0xDE,0xAD,0xBE,0xEF, 0xDE,0xAD,0xBE,0xEF,
        };
        uint8_t cmd[256]; uint8_t *p = cmd;
        p = put_u16(p, (uint16_t)TPM_ST_SESSIONS);
        p = put_u32(p, 0);
        p = put_u32(p, TPM_CC_SignDigest);
        p = put_u32(p, akHandle);               /* H1: restricted ML-DSA AK */
        /* authArea: 1 password session (9 bytes) */
        p = put_u32(p, 9);
        p = put_u32(p, TPM_RS_PW); p = put_u16(p, 0); *p++ = 0; p = put_u16(p, 0);
        /* P1: inScheme = TPM_ALG_NULL (2 bytes; TPMS_EMPTY details for NULL) */
        p = put_u16(p, (uint16_t)TPM_ALG_NULL);
        /* P2: digest (TPM2B_DIGEST: 32 bytes) */
        p = put_u16(p, 32); memcpy(p, digest, 32); p += 32;
        /* P3: context (empty) */
        p = put_u16(p, 0);
        /* P4: hint (empty) */
        p = put_u16(p, 0);
        uint32_t len = (uint32_t)(p - cmd);
        put_u32(cmd + 2, len);
        resp_len = sizeof(resp);
        send_command(cmd, len, resp, &resp_len);
        uint32_t rc = response_rc(resp, resp_len);
        if (rc == 0) {
            FAIL("SignDigest(restricted AK): expected TPM_RC_ATTRIBUTES, got TPM_RC_SUCCESS");
            goto done;
        }
        /* Check error class: bits 7:0 must be RC_FMT1 | ATTRIBUTES = 0x082 */
        if ((rc & 0x0ffu) != RC_ATTRIBUTES) {
            FAIL("SignDigest(restricted AK): expected ATTRIBUTES error (0x082), got rc=0x%08x", rc);
            goto done;
        }
        PASS("SignDigest(restricted ML-DSA AK) → ATTRIBUTES (0x%08x) — restriction enforced", rc);
    }

    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     * Test 5 — CreatePrimary(ML-DSA-65 unrestricted) + SignDigest → success
     *
     * Validates: CryptSelectSignScheme synthesises TPMT_SIG_SCHEME for ML-DSA,
     * CryptMlDsaSign runs end-to-end, signature size = 3309 B (FIPS 204).
     * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    {
        /* 5a: Create an unrestricted ML-DSA-65 signing key */
        uint32_t dsaHandle;
        {
            uint32_t attrs = TPMA_FIXEDTPM | TPMA_FIXEDPARENT | TPMA_SENSITIVEDATA
                           | TPMA_USERWITHAUTH | TPMA_SIGN;    /* no RESTRICTED */
            uint32_t rc = do_create_primary(TPM_RH_OWNER, (uint16_t)TPM_ALG_MLDSA,
                                            (uint16_t)TPM_MLDSA_65, attrs,
                                            resp, sizeof(resp));
            if (rc != 0) {
                FAIL("CreatePrimary(ML-DSA-65 unrestricted) rc=0x%08x", rc);
                goto done;
            }
            dsaHandle = get_u32(resp + 10);
            PASS("CreatePrimary(ML-DSA-65 unrestricted): handle=0x%08x", dsaHandle);
        }

        /* 5b: SignDigest with the unrestricted key */
        static const uint8_t digest[32] = {
            0xCA,0xFE,0xBA,0xBE, 0xCA,0xFE,0xBA,0xBE,
            0xCA,0xFE,0xBA,0xBE, 0xCA,0xFE,0xBA,0xBE,
            0xCA,0xFE,0xBA,0xBE, 0xCA,0xFE,0xBA,0xBE,
            0xCA,0xFE,0xBA,0xBE, 0xCA,0xFE,0xBA,0xBE,
        };
        {
            uint8_t cmd[256]; uint8_t *p = cmd;
            p = put_u16(p, (uint16_t)TPM_ST_SESSIONS);
            p = put_u32(p, 0);
            p = put_u32(p, TPM_CC_SignDigest);
            p = put_u32(p, dsaHandle);
            p = put_u32(p, 9);
            p = put_u32(p, TPM_RS_PW); p = put_u16(p, 0); *p++ = 0; p = put_u16(p, 0);
            p = put_u16(p, (uint16_t)TPM_ALG_NULL);   /* NULL → key default (ML-DSA) */
            p = put_u16(p, 32); memcpy(p, digest, 32); p += 32;
            p = put_u16(p, 0);   /* context: empty */
            p = put_u16(p, 0);   /* hint: empty */
            uint32_t len = (uint32_t)(p - cmd);
            put_u32(cmd + 2, len);
            resp_len = sizeof(resp);
            if (send_command(cmd, len, resp, &resp_len)) {
                FAIL("SignDigest(unrestricted): TPMLIB_Process error");
                goto done;
            }
            uint32_t rc = response_rc(resp, resp_len);
            if (rc != 0) {
                FAIL("SignDigest(ML-DSA-65 unrestricted) rc=0x%08x", rc);
                goto done;
            }
        }

        /* Parse TPMT_SIGNATURE from response:
         * (TPM_ST_SESSIONS) header(10) + paramSize(4) + sigAlg(2) + TPMU_SIGNATURE
         * For ML-DSA: TPMU_SIGNATURE.mldsa = TPM2B_SIGNATURE_MLDSA { size(2) + sig[size] } */
        {
            const uint8_t *q = resp + 14;     /* skip header + paramSize */
            uint16_t sig_alg = get_u16(q); q += 2;
            uint16_t sig_sz  = get_u16(q);    /* TPM2B_SIGNATURE_MLDSA.size */

            if (sig_alg != (uint16_t)TPM_ALG_MLDSA) {
                FAIL("SignDigest: sigAlg=0x%04x expected TPM_ALG_MLDSA(0x%04x)",
                     sig_alg, (uint16_t)TPM_ALG_MLDSA);
                goto done;
            }
            if (sig_sz != MLDSA_65_SIG_SIZE) {
                FAIL("SignDigest: sig size=%u expected %d (ML-DSA-65 per FIPS 204 Table 3)",
                     sig_sz, MLDSA_65_SIG_SIZE);
                goto done;
            }
            PASS("SignDigest(ML-DSA-65 unrestricted): sigAlg=MLDSA, sig=%u B — FIPS 204", sig_sz);
        }
    }

done:
    TPMLIB_Terminate();

cleanup:
    if (chdir(origcwd) == 0) {
        char nvpath[4096 + 8];
        snprintf(nvpath, sizeof(nvpath), "%s/NVChip", tmpdir);
        rm_f(nvpath);
        rmdir(tmpdir);
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
