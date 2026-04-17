/*
 * p11_helper.c — minimal PKCS#11 v3.2 client for cross-validation
 *
 * Uses the PKCS#11 v3.2 header from softhsmv3's src/lib/pkcs11/ tree
 * (ISO C declarations — no softhsmv3 internals). Loads libsofthsmv3.so
 * via dlopen + C_GetFunctionList; no softhsmv3 symbols are required at
 * link time, so the harness can also target third-party PKCS#11 modules.
 *
 * Copyright 2026 PQC Today. BSD-3-Clause.
 */

#include "p11_helper.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* PKCS#11 v3.2 essentials — embedded so we don't need softhsmv3 on    */
/* the include path at compile time.                                   */
/* ------------------------------------------------------------------ */

typedef unsigned long  CK_ULONG;
typedef unsigned char  CK_BYTE;
typedef CK_BYTE       *CK_BYTE_PTR;
typedef unsigned char  CK_BBOOL;
typedef void          *CK_VOID_PTR;
typedef CK_VOID_PTR   *CK_VOID_PTR_PTR;
typedef CK_ULONG       CK_RV;
typedef CK_ULONG       CK_SLOT_ID;
typedef CK_ULONG      *CK_ULONG_PTR;
typedef CK_ULONG       CK_SESSION_HANDLE;
typedef CK_ULONG       CK_OBJECT_HANDLE;
typedef CK_ULONG      *CK_SLOT_ID_PTR;
typedef CK_ULONG      *CK_SESSION_HANDLE_PTR;
typedef CK_ULONG      *CK_OBJECT_HANDLE_PTR;
typedef CK_ULONG       CK_FLAGS;
typedef CK_ULONG       CK_ATTRIBUTE_TYPE;
typedef CK_ULONG       CK_MECHANISM_TYPE;
typedef CK_ULONG       CK_OBJECT_CLASS;
typedef CK_ULONG       CK_KEY_TYPE;
typedef void          *CK_NOTIFY;

#define CKR_OK                      0x00UL
#define CK_TRUE                     1
#define CK_FALSE                    0

#define CKF_RW_SESSION              0x00000002UL
#define CKF_SERIAL_SESSION          0x00000004UL
#define CKU_SO                      0
#define CKU_USER                    1

#define CKO_PUBLIC_KEY              0x00000002UL
#define CKO_PRIVATE_KEY             0x00000003UL

#define CKA_CLASS                   0x00000000UL
#define CKA_TOKEN                   0x00000001UL
#define CKA_PRIVATE                 0x00000002UL
#define CKA_LABEL                   0x00000003UL
#define CKA_KEY_TYPE                0x00000100UL
#define CKA_ENCRYPT                 0x00000104UL
#define CKA_DECRYPT                 0x00000105UL
#define CKA_VERIFY                  0x0000010AUL
#define CKA_SIGN                    0x00000108UL
#define CKA_DERIVE                  0x0000010CUL
#define CKA_SENSITIVE               0x00000103UL
#define CKA_VALUE                   0x00000011UL
#define CKA_EXTRACTABLE             0x00000162UL
#define CKA_PARAMETER_SET           0x0000061DUL

#define CKK_ML_KEM                  0x00000049UL
#define CKK_ML_DSA                  0x0000004AUL
#define CKM_ML_KEM_KEY_PAIR_GEN     0x0000000FUL
#define CKM_ML_DSA_KEY_PAIR_GEN     0x0000001CUL
#define CKM_ML_DSA                  0x0000001DUL

#define CKP_ML_DSA_44               0x00000001UL
#define CKP_ML_DSA_65               0x00000002UL
#define CKP_ML_DSA_87               0x00000003UL
#define CKP_ML_KEM_512              0x00000001UL
#define CKP_ML_KEM_768              0x00000002UL
#define CKP_ML_KEM_1024             0x00000003UL

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE  type;
    CK_VOID_PTR        pValue;
    CK_ULONG           ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE  mechanism;
    CK_VOID_PTR        pParameter;
    CK_ULONG           ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM *CK_MECHANISM_PTR;

typedef struct CK_INFO {
    CK_BYTE cryptokiVersion[2];
    CK_BYTE manufacturerID[32];
    CK_FLAGS flags;
    CK_BYTE libraryDescription[32];
    CK_BYTE libraryVersion[2];
} CK_INFO;
typedef CK_INFO *CK_INFO_PTR;

typedef struct CK_TOKEN_INFO {
    CK_BYTE label[32];
    CK_BYTE manufacturerID[32];
    CK_BYTE model[16];
    CK_BYTE serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_BYTE hardwareVersion[2];
    CK_BYTE firmwareVersion[2];
    CK_BYTE utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

#define CKF_TOKEN_INITIALIZED       0x00000400UL

/* Only the function-list entries we use. */
typedef struct CK_FUNCTION_LIST {
    CK_BYTE version[2];
    CK_RV (*C_Initialize)(CK_VOID_PTR);
    CK_RV (*C_Finalize)(CK_VOID_PTR);
    CK_RV (*C_GetInfo)(CK_INFO_PTR);
    CK_RV (*C_GetFunctionList)(struct CK_FUNCTION_LIST **);
    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, CK_VOID_PTR);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_VOID_PTR, CK_ULONG_PTR);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_VOID_PTR);
    CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID);
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, CK_VOID_PTR);
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_SignRecover)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
                                CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
} CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

/* ------------------------------------------------------------------ */
/* Internal ctx                                                        */
/* ------------------------------------------------------------------ */

/* PKCS#11 v3.2 KEM functions — not in the v2.40 CK_FUNCTION_LIST layout,
 * resolved by dlsym against the module symbol table directly. */
typedef CK_RV (*p11_encapsulate_t)(
    CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*p11_decapsulate_t)(
    CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG,
    CK_OBJECT_HANDLE_PTR);

struct p11_ctx {
    void               *dl;
    CK_FUNCTION_LIST   *fn;
    CK_SLOT_ID          slot;
    CK_SESSION_HANDLE   session;
    CK_INFO             info;
    char                description[64];
    p11_encapsulate_t   C_EncapsulateKey;  /* may be NULL if module lacks v3.2 */
    p11_decapsulate_t   C_DecapsulateKey;
};

static const char *
ckr_str(CK_RV rv)
{
    static char buf[32];
    snprintf(buf, sizeof(buf), "0x%08lx", rv);
    return buf;
}

#define P11_CHECK(fncall, msg)  do {                                   \
    CK_RV _rv = (fncall);                                              \
    if (_rv != CKR_OK) {                                               \
        fprintf(stderr, "p11: %s: %s\n", (msg), ckr_str(_rv));          \
        goto fail;                                                      \
    }                                                                   \
} while (0)

/* ------------------------------------------------------------------ */
/* Module open / init                                                  */
/* ------------------------------------------------------------------ */

p11_ctx *
p11_open(const char *module_path, const char *so_pin, const char *user_pin)
{
    p11_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->dl = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
    if (!ctx->dl) {
        fprintf(stderr, "p11: dlopen(%s): %s\n", module_path, dlerror());
        goto fail;
    }

    CK_C_GetFunctionList getlist = (CK_C_GetFunctionList)dlsym(ctx->dl, "C_GetFunctionList");
    if (!getlist) {
        fprintf(stderr, "p11: dlsym(C_GetFunctionList): %s\n", dlerror());
        goto fail;
    }

    P11_CHECK(getlist(&ctx->fn), "C_GetFunctionList");
    P11_CHECK(ctx->fn->C_Initialize(NULL), "C_Initialize");
    P11_CHECK(ctx->fn->C_GetInfo(&ctx->info), "C_GetInfo");

    /* PKCS#11 v3.2 KEM entry points — dlsym because the legacy
     * CK_FUNCTION_LIST layout doesn't include them. */
    ctx->C_EncapsulateKey = (p11_encapsulate_t)dlsym(ctx->dl, "C_EncapsulateKey");
    ctx->C_DecapsulateKey = (p11_decapsulate_t)dlsym(ctx->dl, "C_DecapsulateKey");

    /* Pretty-print library description for the harness output. */
    memcpy(ctx->description, ctx->info.libraryDescription,
           sizeof(ctx->info.libraryDescription));
    /* Trim trailing spaces. */
    for (int i = 31; i >= 0 && ctx->description[i] == ' '; --i)
        ctx->description[i] = '\0';

    /* Find an uninitialized slot, init a token, login as SO to set user PIN.  */
    CK_ULONG slot_count = 0;
    P11_CHECK(ctx->fn->C_GetSlotList(CK_TRUE, NULL, &slot_count),
              "C_GetSlotList(count)");
    if (slot_count == 0) {
        fprintf(stderr, "p11: no slots available\n");
        goto fail;
    }
    CK_SLOT_ID *slots = calloc(slot_count, sizeof(CK_SLOT_ID));
    P11_CHECK(ctx->fn->C_GetSlotList(CK_TRUE, slots, &slot_count),
              "C_GetSlotList");
    /* Just use slot 0. Check if already initialized. */
    ctx->slot = slots[0];
    free(slots);

    CK_TOKEN_INFO tok;
    P11_CHECK(ctx->fn->C_GetTokenInfo(ctx->slot, &tok), "C_GetTokenInfo");
    if (!(tok.flags & CKF_TOKEN_INITIALIZED)) {
        /* Fresh token: initialize. SO PIN + label. */
        unsigned char label[32];
        memset(label, ' ', sizeof(label));
        memcpy(label, "pqctoday-crossval", 17);
        P11_CHECK(ctx->fn->C_InitToken(ctx->slot, (CK_BYTE_PTR)so_pin,
                                       strlen(so_pin), label),
                  "C_InitToken");
    }

    /* Open RW session, login as SO, set user PIN, then re-login as user. */
    P11_CHECK(ctx->fn->C_OpenSession(ctx->slot,
                                      CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                      NULL, NULL, &ctx->session),
              "C_OpenSession");

    /* SO login only required the first time to set the user PIN. If we fail
     * to login as SO, it may be because user PIN is already set; try user
     * login directly. */
    if (ctx->fn->C_Login(ctx->session, CKU_SO, (CK_BYTE_PTR)so_pin,
                         strlen(so_pin)) == CKR_OK) {
        /* Ignore errors — PIN may already be set from a prior run. */
        (void)ctx->fn->C_InitPIN(ctx->session, (CK_BYTE_PTR)user_pin,
                                  strlen(user_pin));
        (void)ctx->fn->C_Logout(ctx->session);
    }

    P11_CHECK(ctx->fn->C_Login(ctx->session, CKU_USER,
                                (CK_BYTE_PTR)user_pin, strlen(user_pin)),
              "C_Login(USER)");

    return ctx;

 fail:
    p11_close(ctx);
    return NULL;
}

void
p11_close(p11_ctx *ctx)
{
    if (!ctx) return;
    if (ctx->fn) {
        if (ctx->session) ctx->fn->C_CloseSession(ctx->session);
        ctx->fn->C_Finalize(NULL);
    }
    if (ctx->dl) dlclose(ctx->dl);
    free(ctx);
}

const char *
p11_module_description(p11_ctx *ctx)
{
    return ctx ? ctx->description : "(null ctx)";
}

/* ------------------------------------------------------------------ */
/* ML-DSA                                                              */
/* ------------------------------------------------------------------ */

int
p11_mldsa_generate(p11_ctx *ctx, uint32_t param_set,
                   uint8_t *pk_out, size_t *pk_len,
                   uint64_t *priv_handle_out)
{
    CK_MECHANISM mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_KEY_TYPE kt = CKK_ML_DSA;
    CK_OBJECT_CLASS pub_cls = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS prv_cls = CKO_PRIVATE_KEY;
    CK_ULONG ps = (CK_ULONG)param_set;

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_CLASS,          &pub_cls, sizeof(pub_cls) },
        { CKA_KEY_TYPE,       &kt,      sizeof(kt) },
        { CKA_PARAMETER_SET,  &ps,      sizeof(ps) },
        { CKA_TOKEN,          &bFalse,  sizeof(bFalse) },
        { CKA_VERIFY,         &bTrue,   sizeof(bTrue) },
    };
    CK_ATTRIBUTE prv_tmpl[] = {
        { CKA_CLASS,          &prv_cls, sizeof(prv_cls) },
        { CKA_KEY_TYPE,       &kt,      sizeof(kt) },
        { CKA_PARAMETER_SET,  &ps,      sizeof(ps) },
        { CKA_TOKEN,          &bFalse,  sizeof(bFalse) },
        { CKA_SIGN,           &bTrue,   sizeof(bTrue) },
        { CKA_SENSITIVE,      &bTrue,   sizeof(bTrue) },
        { CKA_EXTRACTABLE,    &bFalse,  sizeof(bFalse) },
    };
    CK_OBJECT_HANDLE pub_h = 0, prv_h = 0;

    CK_RV rv = ctx->fn->C_GenerateKeyPair(ctx->session, &mech,
        pub_tmpl, sizeof(pub_tmpl)/sizeof(pub_tmpl[0]),
        prv_tmpl, sizeof(prv_tmpl)/sizeof(prv_tmpl[0]),
        &pub_h, &prv_h);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_GenerateKeyPair(ML-DSA): %s\n", ckr_str(rv));
        return 0;
    }

    CK_ATTRIBUTE get[] = { { CKA_VALUE, pk_out, (CK_ULONG)*pk_len } };
    rv = ctx->fn->C_GetAttributeValue(ctx->session, pub_h, get, 1);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_GetAttributeValue(CKA_VALUE): %s\n", ckr_str(rv));
        return 0;
    }
    *pk_len = get[0].ulValueLen;
    *priv_handle_out = (uint64_t)prv_h;
    return 1;
}

int
p11_mldsa_sign(p11_ctx *ctx, uint64_t priv_handle,
               const uint8_t *msg, size_t msg_len,
               uint8_t *sig_out, size_t *sig_len)
{
    CK_MECHANISM mech = { CKM_ML_DSA, NULL, 0 };
    CK_ULONG slen = (CK_ULONG)*sig_len;

    CK_RV rv = ctx->fn->C_SignInit(ctx->session, &mech,
                                   (CK_OBJECT_HANDLE)priv_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_SignInit: %s\n", ckr_str(rv));
        return 0;
    }
    rv = ctx->fn->C_Sign(ctx->session, (CK_BYTE_PTR)msg, (CK_ULONG)msg_len,
                         sig_out, &slen);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_Sign: %s\n", ckr_str(rv));
        return 0;
    }
    *sig_len = slen;
    return 1;
}

/* ------------------------------------------------------------------ */
/* ML-KEM                                                              */
/* ------------------------------------------------------------------ */

int
p11_mlkem_generate(p11_ctx *ctx, uint32_t param_set,
                   uint8_t *pk_out, size_t *pk_len,
                   uint64_t *priv_handle_out)
{
    CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
    CK_KEY_TYPE kt = CKK_ML_KEM;
    CK_OBJECT_CLASS pub_cls = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS prv_cls = CKO_PRIVATE_KEY;
    CK_ULONG ps = (CK_ULONG)param_set;

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_CLASS,          &pub_cls, sizeof(pub_cls) },
        { CKA_KEY_TYPE,       &kt,      sizeof(kt) },
        { CKA_PARAMETER_SET,  &ps,      sizeof(ps) },
        { CKA_TOKEN,          &bFalse,  sizeof(bFalse) },
        { CKA_ENCRYPT,        &bTrue,   sizeof(bTrue) },
    };
    CK_ATTRIBUTE prv_tmpl[] = {
        { CKA_CLASS,          &prv_cls, sizeof(prv_cls) },
        { CKA_KEY_TYPE,       &kt,      sizeof(kt) },
        { CKA_PARAMETER_SET,  &ps,      sizeof(ps) },
        { CKA_TOKEN,          &bFalse,  sizeof(bFalse) },
        { CKA_DECRYPT,        &bTrue,   sizeof(bTrue) },
        { CKA_SENSITIVE,      &bTrue,   sizeof(bTrue) },
        { CKA_EXTRACTABLE,    &bFalse,  sizeof(bFalse) },
    };
    CK_OBJECT_HANDLE pub_h = 0, prv_h = 0;

    CK_RV rv = ctx->fn->C_GenerateKeyPair(ctx->session, &mech,
        pub_tmpl, sizeof(pub_tmpl)/sizeof(pub_tmpl[0]),
        prv_tmpl, sizeof(prv_tmpl)/sizeof(prv_tmpl[0]),
        &pub_h, &prv_h);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_GenerateKeyPair(ML-KEM): %s\n", ckr_str(rv));
        return 0;
    }

    CK_ATTRIBUTE get[] = { { CKA_VALUE, pk_out, (CK_ULONG)*pk_len } };
    rv = ctx->fn->C_GetAttributeValue(ctx->session, pub_h, get, 1);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_GetAttributeValue(CKA_VALUE): %s\n", ckr_str(rv));
        return 0;
    }
    *pk_len = get[0].ulValueLen;
    *priv_handle_out = (uint64_t)prv_h;
    return 1;
}

/* PKCS#11 v3.2 §6.46 — C_DecapsulateKey produces a new key object whose
 * CKA_VALUE is the 32-byte shared secret. We use CKO_SECRET_KEY +
 * CKK_GENERIC_SECRET as the template so CKA_VALUE is readable. */
#define CKO_SECRET_KEY              0x00000004UL
#define CKK_GENERIC_SECRET          0x00000010UL

int
p11_mlkem_decapsulate(p11_ctx *ctx, uint64_t priv_handle,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t *ss_out, size_t *ss_len)
{
    if (!ctx->C_DecapsulateKey) {
        fprintf(stderr, "p11: module does not export C_DecapsulateKey (PKCS#11 v3.2 required)\n");
        return 0;
    }

    #define CKM_ML_KEM_VAL  0x00000017UL
    CK_MECHANISM     mech         = { CKM_ML_KEM_VAL, NULL, 0 };
    CK_OBJECT_CLASS  cls          = CKO_SECRET_KEY;
    CK_KEY_TYPE      kt           = CKK_GENERIC_SECRET;
    CK_BBOOL         bTrue        = CK_TRUE;
    CK_BBOOL         bFalse       = CK_FALSE;
    CK_OBJECT_HANDLE ss_handle    = 0;
    CK_ATTRIBUTE     tpl[] = {
        { CKA_CLASS,       &cls,    sizeof(cls) },
        { CKA_KEY_TYPE,    &kt,     sizeof(kt) },
        { CKA_TOKEN,       &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue,  sizeof(bTrue) },
        { CKA_SENSITIVE,   &bFalse, sizeof(bFalse) },
    };

    CK_RV rv = ctx->C_DecapsulateKey(
                    ctx->session, &mech,
                    (CK_OBJECT_HANDLE)priv_handle,
                    tpl, sizeof(tpl)/sizeof(tpl[0]),
                    (CK_BYTE_PTR)ct, (CK_ULONG)ct_len,
                    &ss_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_DecapsulateKey: %s\n", ckr_str(rv));
        return 0;
    }

    CK_ATTRIBUTE get[] = { { CKA_VALUE, ss_out, (CK_ULONG)*ss_len } };
    rv = ctx->fn->C_GetAttributeValue(ctx->session, ss_handle, get, 1);
    if (rv != CKR_OK) {
        fprintf(stderr, "p11: C_GetAttributeValue(shared secret): %s\n", ckr_str(rv));
        (void)ctx->fn->C_DestroyObject(ctx->session, ss_handle);
        return 0;
    }
    *ss_len = get[0].ulValueLen;
    (void)ctx->fn->C_DestroyObject(ctx->session, ss_handle);
    return 1;
}
