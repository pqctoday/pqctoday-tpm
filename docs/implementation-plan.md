# pqctoday-tpm Implementation Plan

## TCG TPM 2.0 Library Specification V1.85 PQC Emulator

**Repository**: `pqctoday/pqctoday-tpm`
**License**: BSD-3-Clause
**Base projects**: libtpms (BSD-3) + swtpm (BSD-3)
**Created**: 2026-04-16

---

## Phase 1: Foundation (4-6 weeks)

### 1.1 Repository Setup (Week 1)

**Goal**: Fork libtpms + swtpm, establish CI, verify vanilla build.

#### Tasks

1. **Create GitHub repo** `pqctoday/pqctoday-tpm` (public, BSD-3-Clause)

2. **Fork upstream sources as git subtrees**
   ```bash
   # Clone fresh
   git clone https://github.com/pqctoday/pqctoday-tpm.git
   cd pqctoday-tpm

   # Add libtpms as subtree (track v0.11.x branch)
   git subtree add --prefix=libtpms \
     https://github.com/stefanberger/libtpms.git v0.11-stable --squash

   # Add swtpm as subtree (track v0.11.x branch)
   git subtree add --prefix=swtpm \
     https://github.com/stefanberger/swtpm.git v0.11-stable --squash
   ```

   **Why subtree over submodule**: Patches live in our tree, easier to maintain a
   quilt-style patch series for upstream submission. Submodules would require a
   separate fork repo for each.

3. **Verify vanilla build**
   ```bash
   # libtpms
   cd libtpms
   ./autogen.sh
   ./configure --with-tpm2 --with-openssl
   make -j$(nproc)
   make check  # run self-tests

   # swtpm (depends on libtpms installed)
   cd ../swtpm
   ./autogen.sh
   ./configure --with-openssl
   make -j$(nproc)
   ```

4. **Set up GitHub Actions CI**
   ```yaml
   # .github/workflows/ci.yml
   jobs:
     build:
       strategy:
         matrix:
           os: [ubuntu-24.04]
           openssl: ['3.6.2']
       steps:
         - Build OpenSSL from source (PQC support)
         - Build libtpms
         - Build swtpm
         - Run libtpms self-tests
         - Start swtpm, run smoke test with tpm2-tools
   ```

5. **Create top-level CMakeLists.txt** (optional — libtpms/swtpm use autotools,
   but a CMake wrapper simplifies the WASM build later)

6. **Docker development environment**
   ```dockerfile
   # docker/Dockerfile.dev
   FROM ubuntu:24.04
   RUN apt-get update && apt-get install -y \
     build-essential autoconf automake libtool pkg-config \
     libssl-dev libjson-glib-dev libglib2.0-dev \
     libtasn1-6-dev expect gawk socat \
     tpm2-tools tpm2-abrmd
   # Build OpenSSL 3.6.2 from source for PQC
   # (Ubuntu 24.04 ships 3.0.x which lacks ML-KEM/ML-DSA)
   ```

#### Deliverables
- [ ] GitHub repo created with README, LICENSE, .gitignore
- [ ] libtpms + swtpm subtrees imported
- [ ] Vanilla build succeeds on Ubuntu 24.04
- [ ] CI green on push
- [ ] Docker dev environment functional
- [ ] `swtpm socket` starts and `tpm2_startup -c` succeeds

---

### 1.2 V1.85 Algorithm IDs (Week 2, Days 1-2)

**Goal**: Register ML-DSA, HashML-DSA, and ML-KEM algorithm identifiers.

#### Source Files to Modify

| File | Purpose | Change |
|------|---------|--------|
| `libtpms/src/tpm2/TPMCmd/tpm/include/tpm_public/TpmTypes.h` | Algorithm ID definitions | Add `TPM_ALG_MLDSA`, `TPM_ALG_HASH_MLDSA`, `TPM_ALG_MLKEM` |
| `libtpms/src/tpm2/TPMCmd/tpm/include/TpmConfiguration/TpmProfile_Common.h` | Algorithm enable flags | Add `ALG_MLDSA`, `ALG_HASH_MLDSA`, `ALG_MLKEM` set to `ALG_YES` |
| `libtpms/src/tpm2/TPMCmd/tpm/include/tpm_public/TpmAlgorithmDefines.h` | Algorithm properties | Add key size constants, algorithm property flags |

#### Algorithm ID Values

Source: TCG Algorithm Registry Version 2.0 RC2 (April 2025).
Cross-reference: wolfTPM PR #445 for interpretation.

```c
// TpmTypes.h — algorithm IDs from TCG Algorithm Registry (Part 2 §6.3)
// Values confirmed against TCG TPM 2.0 Library Specification V1.85 RC4 and wolfTPM v4.0.0:
#define TPM_ALG_MLDSA          ((TPM_ALG_ID) 0x00A1)  // FIPS 204
#define TPM_ALG_HASH_MLDSA     ((TPM_ALG_ID) 0x00A2)  // FIPS 204 pre-hash
#define TPM_ALG_MLKEM          ((TPM_ALG_ID) 0x00A0)  // FIPS 203
```

```c
// TpmProfile_Common.h — enable PQC algorithms
#define ALG_MLDSA       ALG_YES
#define ALG_HASH_MLDSA  ALG_YES
#define ALG_MLKEM       ALG_YES
// Also enable hash-based sigs (already defined, currently ALG_NO):
#define ALG_LMS         ALG_YES
#define ALG_XMSS        ALG_YES
```

#### Key Size Constants

```c
// TpmAlgorithmDefines.h — PQC key/signature sizes
// ML-KEM parameter sets
#define MLKEM_768_PUBLIC_KEY_SIZE    1184
#define MLKEM_768_PRIVATE_KEY_SIZE   2400
#define MLKEM_768_CIPHERTEXT_SIZE    1088
#define MLKEM_768_SHARED_SECRET_SIZE   32

#define MLKEM_1024_PUBLIC_KEY_SIZE   1568
#define MLKEM_1024_PRIVATE_KEY_SIZE  3168
#define MLKEM_1024_CIPHERTEXT_SIZE   1568
#define MLKEM_1024_SHARED_SECRET_SIZE   32

// ML-DSA parameter sets
#define MLDSA_44_PUBLIC_KEY_SIZE     1312
#define MLDSA_44_PRIVATE_KEY_SIZE    2560
#define MLDSA_44_SIGNATURE_SIZE      2420

#define MLDSA_65_PUBLIC_KEY_SIZE     1952
#define MLDSA_65_PRIVATE_KEY_SIZE    4032
#define MLDSA_65_SIGNATURE_SIZE      3309

#define MLDSA_87_PUBLIC_KEY_SIZE     2592
#define MLDSA_87_PRIVATE_KEY_SIZE    4896
#define MLDSA_87_SIGNATURE_SIZE      4627

// Buffer sizing (largest values)
#define MAX_MLDSA_PUB_SIZE      MLDSA_87_PUBLIC_KEY_SIZE    // 2592
#define MAX_MLDSA_PRIV_SIZE     MLDSA_87_PRIVATE_KEY_SIZE   // 4896
#define MAX_MLDSA_SIG_SIZE      MLDSA_87_SIGNATURE_SIZE     // 4627
#define MAX_MLKEM_PUB_SIZE      MLKEM_1024_PUBLIC_KEY_SIZE   // 1568
#define MAX_MLKEM_PRIV_SIZE     MLKEM_1024_PRIVATE_KEY_SIZE  // 3168
#define MAX_MLKEM_CT_SIZE       MLKEM_1024_CIPHERTEXT_SIZE   // 1568
```

#### Verification
- [ ] `make` succeeds with new defines (no functional code yet, just constants)
- [ ] grep confirms all `TPM_ALG_MLDSA/MLKEM` symbols resolve

---

### 1.3 I/O Buffer Enlargement (Week 2, Days 3-4)

**Goal**: Increase command/response buffers to accommodate PQC key sizes.

Per libtpms issue #475: ML-DSA-87 signature = 4,627 bytes. Current
`MAX_COMMAND_SIZE` is ~4KB. Need ~8KB minimum.

#### Files to Modify

| File | Change |
|------|--------|
| `TpmProfile_Common.h` | `MAX_COMMAND_SIZE` 4096 → 8192 |
| `TpmProfile_Common.h` | `MAX_RESPONSE_SIZE` 4096 → 8192 |
| `TpmProfile_Common.h` | `MAX_NV_INDEX_SIZE` increase for PQC certs |
| `TpmProfile_Common.h` | `MAX_SYM_DATA` / `MAX_BUFFER` review |
| Marshal/unmarshal code | Verify no hardcoded 4K assumptions |

```c
// TpmProfile_Common.h changes
#define MAX_COMMAND_SIZE    8192    // was 4096
#define MAX_RESPONSE_SIZE   8192   // was 4096
// ML-DSA-87 certificate: ~5KB (2592 pub + 4627 sig + X.509 overhead)
#define MAX_NV_INDEX_SIZE   8192   // was 2048
```

#### swtpm Changes

swtpm's `mainloop.c` allocates response buffers based on libtpms constants.
Verify it picks up the new sizes automatically. If hardcoded:

| File | Change |
|------|--------|
| `swtpm/src/swtpm/mainloop.c` | Verify `rbuffer` allocation uses libtpms constants |
| `swtpm/src/swtpm/ctrlchannel.c` | Verify control channel buffer sizes |

#### Verification
- [ ] Build succeeds
- [ ] `swtpm` starts with enlarged buffers (check via debug log)
- [ ] Existing classical TPM operations still work (regression test)

---

### 1.4 ML-DSA Crypto Integration (Weeks 3-4)

**Goal**: Wire ML-DSA (FIPS 204) keygen, sign, and verify through OpenSSL EVP.

#### New Files

```
libtpms/src/tpm2/TPMCmd/tpm/src/crypt/CryptMlDsa.c     # ~400 lines
libtpms/src/tpm2/TPMCmd/tpm/include/Crypt/CryptMlDsa.h  # ~60 lines
```

#### Architecture

libtpms crypto dispatch follows this pattern (study `CryptRsa.c` as template):

```
TPM2_Sign command
  → CommandDispatcher → TPM2_Sign handler
    → CryptSign() in CryptUtil.c (line ~1567)
      → switch(algorithm) {
           case TPM_ALG_RSA:  return CryptRsaSign(...);
           case TPM_ALG_ECC:  return CryptEccSign(...);
           case TPM_ALG_MLDSA: return CryptMlDsaSign(...);  // NEW
         }
```

#### CryptMlDsa.c Implementation

```c
// CryptMlDsa.c — ML-DSA via OpenSSL 3.6+ EVP
//
// Reference: softhsmv3 src/lib/crypto/OSSLMLDSA.cpp (for EVP call patterns)
// License: BSD-3-Clause (fresh implementation, not copied from softhsmv3)

#include "Tpm.h"
#include "CryptMlDsa_fp.h"
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

// Parameter set name mapping
static const char* MlDsaParamName(UINT16 scheme) {
    switch(scheme) {
        case MLDSA_44: return "ML-DSA-44";
        case MLDSA_65: return "ML-DSA-65";
        case MLDSA_87: return "ML-DSA-87";
        default: return NULL;
    }
}

// Key generation
LIB_EXPORT TPM_RC
CryptMlDsaGenerateKey(
    OBJECT          *mldsaKey,      // IN/OUT: key object
    RAND_STATE      *rand           // IN: random state
    )
{
    // 1. EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)
    // 2. EVP_PKEY_keygen_init(ctx)
    // 3. EVP_PKEY_generate(ctx, &pkey)
    // 4. EVP_PKEY_get_octet_string_param(pkey, "pub", ...)
    // 5. EVP_PKEY_get_octet_string_param(pkey, "priv", ...)
    // 6. Copy into mldsaKey->publicArea / sensitive
}

// Sign
LIB_EXPORT TPM_RC
CryptMlDsaSign(
    TPMT_SIGNATURE  *sigOut,        // OUT: signature
    OBJECT          *sigKey,        // IN: signing key
    TPM2B_DIGEST    *digest         // IN: message digest (or full message)
    )
{
    // 1. Reconstruct EVP_PKEY from key object private bytes
    //    EVP_PKEY_new_raw_private_key_ex(NULL, "ML-DSA-65", NULL, priv, privLen)
    // 2. EVP_DigestSignInit_ex(mdCtx, NULL, NULL, NULL, NULL, pkey, NULL)
    // 3. EVP_DigestSign(mdCtx, sig, &sigLen, msg, msgLen)
    // 4. Copy signature to sigOut
}

// Verify
LIB_EXPORT TPM_RC
CryptMlDsaVerify(
    TPMT_SIGNATURE  *sig,           // IN: signature
    OBJECT          *sigKey,        // IN: verification key
    TPM2B_DIGEST    *digest         // IN: message digest
    )
{
    // 1. Reconstruct EVP_PKEY from key object public bytes
    //    EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65", NULL, pub, pubLen)
    // 2. EVP_DigestVerifyInit_ex(mdCtx, NULL, NULL, NULL, NULL, pkey, NULL)
    // 3. EVP_DigestVerify(mdCtx, sig, sigLen, msg, msgLen)
    // 4. Return TPM_RC_SUCCESS or TPM_RC_SIGNATURE
}
```

#### Files to Modify (Existing)

| File | Change |
|------|--------|
| `tpm/src/crypt/CryptUtil.c` | Add `CryptMlDsaSign()` / `CryptMlDsaVerify()` cases at lines ~1135 and ~1567 |
| `tpm/src/crypt/CryptUtil.c` | Add `CryptMlDsaGenerateKey()` case in `CryptGenerateKeyPair()` |
| `tpm/cryptolibs/Ossl/TpmToOsslMath.h` | Add ML-DSA EVP helpers if needed |
| `tpm/src/subsystem/Object_spt.c` | Add ML-DSA to key type validation |
| `Makefile.am` | Add CryptMlDsa.c to build |

#### HashML-DSA (Pre-hash Variant)

Same as ML-DSA but the message is hashed first, then the hash is signed.
OpenSSL handles this via the `instance` parameter:

```c
// For HashML-DSA: set OSSL_SIGNATURE_PARAM_INSTANCE to "ML-DSA-65-with-SHA512"
OSSL_PARAM params[] = {
    OSSL_PARAM_utf8_string("instance", "ML-DSA-65-with-SHA512", 0),
    OSSL_PARAM_END
};
EVP_DigestSignInit_ex(mdCtx, NULL, NULL, NULL, NULL, pkey, params);
```

#### Verification
- [ ] `CryptMlDsaGenerateKey()` produces valid key pair
- [ ] `CryptMlDsaSign()` + `CryptMlDsaVerify()` round-trips
- [ ] All three parameter sets (44, 65, 87) work
- [ ] HashML-DSA variant works
- [ ] Cross-validate: export ML-DSA pub key → verify with `openssl dgst` CLI
- [ ] Cross-validate: same message signed by softhsmv3 PKCS#11 → verify in TPM context

---

### 1.5 ML-KEM Crypto Integration (Weeks 4-5)

**Goal**: Wire ML-KEM (FIPS 203) keygen, encapsulate, and decapsulate through OpenSSL EVP.

#### New Files

```
libtpms/src/tpm2/TPMCmd/tpm/src/crypt/CryptMlKem.c     # ~350 lines
libtpms/src/tpm2/TPMCmd/tpm/include/Crypt/CryptMlKem.h  # ~50 lines
```

#### CryptMlKem.c Implementation

```c
// CryptMlKem.c — ML-KEM via OpenSSL 3.6+ EVP
//
// ML-KEM is a KEM (key encapsulation mechanism), NOT encryption.
// TPM 2.0 previously had no KEM concept — V1.85 adds TPM2_Encapsulate/Decapsulate.

// Key generation
LIB_EXPORT TPM_RC
CryptMlKemGenerateKey(
    OBJECT          *mlkemKey,
    RAND_STATE      *rand
    )
{
    // 1. EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL)
    // 2. EVP_PKEY_keygen_init(ctx)
    // 3. EVP_PKEY_generate(ctx, &pkey)
    // 4. Extract pub/priv into key object
}

// Encapsulate (public key operation → shared secret + ciphertext)
LIB_EXPORT TPM_RC
CryptMlKemEncapsulate(
    TPM2B_SHARED_SECRET    *secret,     // OUT: shared secret (32 bytes)
    TPM2B_KEM_CIPHERTEXT   *ciphertext, // OUT: ciphertext
    OBJECT                 *kemKey       // IN: public key
    )
{
    // 1. Reconstruct EVP_PKEY from public bytes
    // 2. EVP_PKEY_encapsulate_init(ctx, NULL)
    // 3. EVP_PKEY_encapsulate(ctx, ct, &ctLen, ss, &ssLen)
    // 4. Copy to output structures
}

// Decapsulate (private key operation → recover shared secret)
LIB_EXPORT TPM_RC
CryptMlKemDecapsulate(
    TPM2B_SHARED_SECRET    *secret,     // OUT: shared secret
    TPM2B_KEM_CIPHERTEXT   *ciphertext, // IN: ciphertext
    OBJECT                 *kemKey       // IN: private key
    )
{
    // 1. Reconstruct EVP_PKEY from private bytes
    // 2. EVP_PKEY_decapsulate_init(ctx, NULL)
    // 3. EVP_PKEY_decapsulate(ctx, ss, &ssLen, ct, ctLen)
    // 4. Copy to output
}
```

#### Files to Modify

| File | Change |
|------|--------|
| `CryptUtil.c` | Add KEM dispatch (new — no existing KEM path in libtpms) |
| `Object_spt.c` | Add ML-KEM to key type validation |
| `Makefile.am` | Add CryptMlKem.c |

#### Verification
- [ ] Keygen → Encapsulate → Decapsulate round-trip produces matching shared secrets
- [ ] ML-KEM-768 and ML-KEM-1024 both work
- [ ] Cross-validate: softhsmv3 encapsulates with TPM public key → TPM decapsulates → secrets match
- [ ] Cross-validate: TPM encapsulates → softhsmv3 decapsulates → secrets match

---

### 1.6 CryptUtil.c Dispatch Wiring (Week 5)

**Goal**: Integrate ML-DSA and ML-KEM into the central crypto dispatcher.

#### CryptUtil.c Modifications

```c
// CryptGenerateKeyPair() — add PQC cases (~line 1135-1142)
case TPM_ALG_MLDSA:
case TPM_ALG_HASH_MLDSA:
    result = CryptMlDsaGenerateKey(newObject, rand);
    break;
case TPM_ALG_MLKEM:
    result = CryptMlKemGenerateKey(newObject, rand);
    break;

// CryptSign() — add PQC case (~line 1567)
case TPM_ALG_MLDSA:
case TPM_ALG_HASH_MLDSA:
    result = CryptMlDsaSign(sigOut, signKey, digest);
    break;

// CryptValidateSignature() — add PQC case
case TPM_ALG_MLDSA:
case TPM_ALG_HASH_MLDSA:
    result = CryptMlDsaVerify(sig, sigKey, digest);
    break;

// NEW: CryptEncapsulate / CryptDecapsulate (no existing KEM path)
LIB_EXPORT TPM_RC
CryptEncapsulate(
    TPM2B_SHARED_SECRET    *secret,
    TPM2B_KEM_CIPHERTEXT   *ciphertext,
    OBJECT                 *kemKey
    )
{
    switch(kemKey->publicArea.type) {
        case TPM_ALG_MLKEM:
            return CryptMlKemEncapsulate(secret, ciphertext, kemKey);
        default:
            return TPM_RC_SCHEME;
    }
}
```

#### Verification
- [ ] `TPM2_Create -G mldsa65` produces a valid ML-DSA key (via existing TPM2_Create command)
- [ ] `TPM2_Sign` with ML-DSA key succeeds
- [ ] `TPM2_VerifySignature` with ML-DSA key succeeds
- [ ] End-to-end: `swtpm` → `tpm2_create` → `tpm2_sign` → `tpm2_verifysignature`

---

## Phase 2: V1.85 TPM Commands (4-6 weeks)

### 2.1 New Data Structures (Week 6)

**Goal**: Define all V1.85 PQC data structures in the TPM type system.

#### Files to Modify

| File | New Types |
|------|-----------|
| `TpmTypes.h` | `TPM2B_KEM_CIPHERTEXT`, `TPM2B_SHARED_SECRET`, `TPM2B_SIGNATURE_CTX` |
| `TpmTypes.h` | `TPM2B_PUBLIC_KEY_MLDSA`, `TPM2B_PRIVATE_KEY_MLDSA` |
| `TpmTypes.h` | `TPM2B_PUBLIC_KEY_MLKEM`, `TPM2B_PRIVATE_KEY_MLKEM` |
| `TpmTypes.h` | `TPMS_MLDSA_PARMS`, `TPMS_HASH_MLDSA_PARMS`, `TPMS_MLKEM_PARMS` |
| `TpmTypes.h` | `TPM_ST_MESSAGE_VERIFIED`, `TPM_ST_DIGEST_VERIFIED` structure tags |
| `TpmTypes.h` | `TPM_RC_EXT_MU` error code (RC_FMT1 + 0x02B) |

```c
// Key structures
typedef struct {
    UINT16 size;
    BYTE   buffer[MAX_MLDSA_PUB_SIZE];  // 2592
} TPM2B_PUBLIC_KEY_MLDSA;

typedef struct {
    UINT16 size;
    BYTE   buffer[MAX_MLDSA_PRIV_SIZE]; // 4896
} TPM2B_PRIVATE_KEY_MLDSA;

typedef struct {
    UINT16 size;
    BYTE   buffer[MAX_MLKEM_PUB_SIZE];  // 1568
} TPM2B_PUBLIC_KEY_MLKEM;

typedef struct {
    UINT16 size;
    BYTE   buffer[MAX_MLKEM_PRIV_SIZE]; // 3168
} TPM2B_PRIVATE_KEY_MLKEM;

// KEM operation structures
typedef struct {
    UINT16 size;
    BYTE   buffer[MAX_MLKEM_CT_SIZE];   // 1568
} TPM2B_KEM_CIPHERTEXT;

typedef struct {
    UINT16 size;
    BYTE   buffer[32];                  // Always 32 bytes for ML-KEM
} TPM2B_SHARED_SECRET;

// Algorithm parameter structures
typedef struct {
    TPMI_MLDSA_SCHEME  scheme;   // e.g., MLDSA_44, MLDSA_65, MLDSA_87
} TPMS_MLDSA_PARMS;

typedef struct {
    TPMI_MLDSA_SCHEME  scheme;
    TPMI_ALG_HASH      hashAlg;  // Hash for pre-hash variant
} TPMS_HASH_MLDSA_PARMS;

typedef struct {
    TPMI_MLKEM_SCHEME  scheme;   // e.g., MLKEM_768, MLKEM_1024
} TPMS_MLKEM_PARMS;
```

#### Marshal/Unmarshal

For each new type, add marshal/unmarshal functions. libtpms uses a table-driven
approach in `CommandDispatchData.h` (generated from spec tables). For initial
implementation, write manual marshal functions following the pattern in
`Marshal.c` / `Unmarshal.c`.

---

### 2.2 TPM2_Encapsulate / TPM2_Decapsulate (Weeks 7-8)

**Goal**: Implement the two KEM commands — entirely new to TPM 2.0.

#### New Files

```
libtpms/src/tpm2/TPMCmd/tpm/src/command/Object/Encapsulate.c
libtpms/src/tpm2/TPMCmd/tpm/src/command/Object/Decapsulate.c
```

#### TPM2_Encapsulate

```c
// Encapsulate.c
//
// Command: TPM2_Encapsulate
// Input:  TPMI_DH_OBJECT keyHandle (ML-KEM public key)
// Output: TPM2B_KEM_CIPHERTEXT ciphertext, TPM2B_SHARED_SECRET secret
//
// Authorization: None (public key operation)
// Restrictions: keyHandle must reference an ML-KEM key with usage=encapsulate

TPM_RC TPM2_Encapsulate(Encapsulate_In *in, Encapsulate_Out *out) {
    // 1. Load key object from handle
    // 2. Validate key type == TPM_ALG_MLKEM
    // 3. Validate key has encapsulate usage
    // 4. Call CryptMlKemEncapsulate(&out->secret, &out->ciphertext, key)
    // 5. Return TPM_RC_SUCCESS
}
```

#### TPM2_Decapsulate

```c
// Decapsulate.c
//
// Command: TPM2_Decapsulate
// Input:  TPMI_DH_OBJECT keyHandle (ML-KEM private key),
//         TPM2B_KEM_CIPHERTEXT ciphertext
// Output: TPM2B_SHARED_SECRET secret
//
// Authorization: USER auth on keyHandle
// Restrictions: keyHandle must reference an ML-KEM key with usage=decapsulate

TPM_RC TPM2_Decapsulate(Decapsulate_In *in, Decapsulate_Out *out) {
    // 1. Load key object from handle
    // 2. Validate key type == TPM_ALG_MLKEM
    // 3. Validate authorization
    // 4. Call CryptMlKemDecapsulate(&out->secret, &in->ciphertext, key)
    // 5. Return TPM_RC_SUCCESS
}
```

#### Command Code Registration

```c
// V1.85 PQC command codes — TCG Part 2 Table 11. 0x1A2 is RESERVED (not a command).
#define TPM_CC_Encapsulate      ((TPM_CC) 0x000001A7)
#define TPM_CC_Decapsulate      ((TPM_CC) 0x000001A8)
```

#### Verification
- [ ] Encapsulate with ML-KEM-768 public key → ciphertext + shared secret
- [ ] Decapsulate with matching private key → same shared secret
- [ ] Encapsulate with ML-KEM-1024 works
- [ ] Wrong key type → TPM_RC_SCHEME error
- [ ] Unauthorized decapsulate → TPM_RC_AUTH_FAIL
- [ ] Cross-engine: softhsmv3 `C_EncapsulateKey` output decapsulated by TPM

---

### 2.3 Sequence Sign/Verify Commands (Weeks 8-9)

**Goal**: Implement streaming sign/verify for large messages (ML-DSA operates on
full messages, not digests — streaming avoids TPM memory limits).

#### New Files

```
libtpms/src/tpm2/TPMCmd/tpm/src/command/Signature/SignSequenceStart.c
libtpms/src/tpm2/TPMCmd/tpm/src/command/Signature/SignSequenceComplete.c
libtpms/src/tpm2/TPMCmd/tpm/src/command/Signature/VerifySequenceStart.c
libtpms/src/tpm2/TPMCmd/tpm/src/command/Signature/VerifySequenceComplete.c
```

#### Design

ML-DSA signs the **full message**, not a hash of it. For large messages that
exceed TPM buffer size, V1.85 introduces streaming:

```
1. TPM2_SignSequenceStart(keyHandle) → sequenceHandle, contextBlob
2. TPM2_SequenceUpdate(sequenceHandle, data_chunk_1)  // existing command
3. TPM2_SequenceUpdate(sequenceHandle, data_chunk_2)
4. TPM2_SignSequenceComplete(sequenceHandle, data_chunk_last) → signature
```

Internally, the TPM accumulates message bytes (or uses a streaming hash context
for HashML-DSA) and produces the final signature on `Complete`.

#### Verification State

```c
// Signature context — stored in TPM volatile memory
typedef struct {
    TPMI_DH_OBJECT  keyHandle;
    TPM_ALG_ID      algorithm;      // MLDSA or HASH_MLDSA
    EVP_MD_CTX      *mdCtx;         // OpenSSL signing context
    BOOL            initialized;
} SIGN_SEQUENCE_STATE;
```

#### Verification
- [ ] Sign sequence: Start → Update(chunk1) → Update(chunk2) → Complete → valid signature
- [ ] Verify sequence matches signature from single-shot SignDigest
- [ ] Sequence timeout / abort cleans up state
- [ ] Multiple concurrent sequences work (different handles)

---

### 2.4 TPM2_SignDigest / TPM2_VerifyDigestSignature (Week 9)

**Goal**: Direct digest-based sign/verify (simpler than sequence for small messages).

#### New Files

```
libtpms/src/tpm2/TPMCmd/tpm/src/command/Signature/SignDigest.c
libtpms/src/tpm2/TPMCmd/tpm/src/command/Signature/VerifyDigestSignature.c
```

These are straightforward wrappers around `CryptMlDsaSign()` / `CryptMlDsaVerify()`.
The difference from existing `TPM2_Sign` is that these accept the raw message
(not a pre-hashed digest) for ML-DSA, or a digest for HashML-DSA.

#### Verification
- [ ] SignDigest + VerifyDigestSignature round-trip
- [ ] SignDigest output matches SignSequence output for same message
- [ ] HashML-DSA with SHA-512 works

---

### 2.5 Command Dispatch Table (Week 10)

**Goal**: Register all 8 new commands in the dispatch system.

#### Files to Modify

| File | Change |
|------|--------|
| `CommandDispatchData.h` | Add entries for 8 new TPM_CC codes |
| `CommandAttributes.c` | Add attribute flags (auth requirements, etc.) |
| `Marshal.c` / `Unmarshal.c` | Add marshal/unmarshal for new input/output structures |
| `Commands.h` | Add function prototypes |

#### New Command Codes — V1.85 spec-correct values (TCG Part 2 Table 11)

Note: 0x1A2 is RESERVED in the spec. Previous draft of this plan had all 8 codes wrong.

```c
#define TPM_CC_VerifySequenceComplete   ((TPM_CC) 0x000001A3)
#define TPM_CC_SignSequenceComplete      ((TPM_CC) 0x000001A4)
#define TPM_CC_VerifyDigestSignature    ((TPM_CC) 0x000001A5)
#define TPM_CC_SignDigest               ((TPM_CC) 0x000001A6)
#define TPM_CC_Encapsulate              ((TPM_CC) 0x000001A7)
#define TPM_CC_Decapsulate              ((TPM_CC) 0x000001A8)
#define TPM_CC_VerifySequenceStart      ((TPM_CC) 0x000001A9)
#define TPM_CC_SignSequenceStart        ((TPM_CC) 0x000001AA)
```

#### Verification
- [ ] All 8 commands dispatchable via raw TPM command bytes
- [ ] Unknown command code returns TPM_RC_COMMAND_CODE
- [ ] `swtpm` passes through all commands correctly

---

## Phase 3: Key Hierarchy & Hybrid (3-4 weeks)

### 3.1 PQC Endorsement Key (Week 11)

**Goal**: Support ML-KEM Endorsement Key alongside classical RSA/ECC EK.

#### swtpm_setup Changes

`swtpm_setup` provisions the TPM with initial keys (EK, SRK) and certificates.
Add ML-KEM EK provisioning:

```bash
# swtpm_setup currently creates:
# - RSA-2048 EK + self-signed EK certificate
# - ECC P-256 EK + self-signed EK certificate
# Add:
# - ML-KEM-768 EK + self-signed EK certificate (signed with ML-DSA-65)
# - ML-KEM-1024 EK + self-signed EK certificate (signed with ML-DSA-87)
```

#### Key Hierarchy

```
Platform Hierarchy
├── RSA-2048 EK (classical, existing)
├── ECC P-256 EK (classical, existing)
├── ML-KEM-768 EK (PQC, NEW)
└── ML-KEM-1024 EK (PQC, NEW)

Owner Hierarchy
├── RSA-2048 SRK (classical, existing)
├── ECC P-256 SRK (classical, existing)
└── ML-KEM-768 SRK (PQC, NEW)
    ├── ML-DSA-65 Signing Key (child)
    ├── ML-KEM-768 Transport Key (child)
    └── AES-256 Storage Key (child, wrapped by ML-KEM SRK)
```

#### Verification
- [ ] `swtpm_setup --create-ek-cert --create-platform-cert` provisions PQC EKs
- [ ] `tpm2_createek -G mlkem768` creates ML-KEM EK
- [ ] EK certificate is valid X.509 signed with ML-DSA

---

### 3.2 PQC Attestation Key (Week 12)

**Goal**: ML-DSA Attestation Key for remote attestation.

```bash
# Create ML-DSA AK under EK
tpm2_createak -C ek.ctx -G mldsa65 -c ak.ctx -u ak.pub
```

The AK is restricted to signing TPM-generated data (attestation quotes,
certify results). It cannot sign arbitrary data.

#### Verification
- [ ] AK creation under ML-KEM EK succeeds
- [ ] AK is restricted (cannot sign arbitrary data → TPM_RC_ATTRIBUTES)
- [ ] AK can sign TPM2_Quote output

---

### 3.3 Dual Classical+PQC Hierarchy (Weeks 12-13)

**Goal**: Hybrid mode where both classical and PQC key hierarchies coexist.

This is application-level — the TPM holds both key types. The attestation
verifier or TLS stack decides which to request. No composite keys at the
TPM level (V1.85 doesn't define composite).

#### Design

```c
// TPM2_CreatePrimary with ML-KEM type creates PQC primary
// TPM2_CreatePrimary with RSA type creates classical primary
// Both coexist in the same hierarchy — no conflict
// The relying party calls TPM2_ReadPublic to discover algorithm type
```

#### Verification
- [ ] Both RSA EK and ML-KEM EK exist simultaneously
- [ ] `tpm2_getcap algorithms` shows MLDSA + MLKEM alongside RSA + ECC
- [ ] Child keys created under either primary

---

## Phase 4: Attestation & Full Compliance (3-4 weeks)

### 4.1 TPM2_Quote with ML-DSA (Week 14)

**Goal**: Remote attestation quote signed with ML-DSA AK.

`TPM2_Quote` reads selected PCR values and signs them with an AK.
With PQC, the quote is signed using ML-DSA instead of RSA/ECDSA.

```bash
# Quote PCRs 0-3 with ML-DSA AK
tpm2_quote -c ak.ctx -l sha256:0,1,2,3 -o quote.dat -s quote.sig
# Signature is ML-DSA-65 (~3.3KB instead of RSA 256B)
```

#### Files to Modify

| File | Change |
|------|--------|
| `tpm/src/command/Attestation/Quote.c` | ML-DSA dispatch (should work via CryptSign) |
| `tpm/src/command/Attestation/Certify.c` | Same — add ML-DSA case |

The existing `Quote.c` calls `CryptSign()` which already dispatches to
`CryptMlDsaSign()` from Phase 1. The main work is ensuring the quote
structure accommodates ML-DSA's larger signatures.

#### Verification
- [ ] `TPM2_Quote` with ML-DSA AK produces valid quote
- [ ] Quote signature verifies with `tpm2_checkquote`
- [ ] Quote size is reasonable (~3.3KB signature + PCR data)

---

### 4.2 TPM2_Certify with PQC (Week 15)

**Goal**: Key certification (proving one key was created by this TPM).

```bash
# Certify that signing_key was created in this TPM
tpm2_certify -c signing_key.ctx -C ak.ctx -o certify.dat -s certify.sig
```

Same pattern as Quote — `Certify.c` calls `CryptSign()`, which dispatches
to ML-DSA. Main work: verify certify info structure handles PQC key
descriptions.

#### Verification
- [ ] Certify ML-DSA key with ML-DSA AK
- [ ] Certify ML-KEM key with ML-DSA AK
- [ ] Certify classical key with ML-DSA AK (cross-algorithm)

---

### 4.3 NV Storage & PCR Updates (Week 15)

**Goal**: Ensure NV storage and PCR operations work with PQC-sized objects.

- NV index size increased to 8KB (Phase 1.3)
- PCR extend operations are hash-based — no PQC impact
- NV-stored PQC certificates (~5KB for ML-DSA-87) must fit

#### Verification
- [ ] Store ML-DSA-87 certificate in NV index
- [ ] Read back and validate
- [ ] PCR extend + quote with PQC AK works end-to-end

---

### 4.4 V1.85 Compliance Test Suite (Week 16)

**Goal**: Comprehensive test coverage for all V1.85 PQC features.

```
tests/v185_compliance/
├── test_algorithm_ids.sh       # Algorithm enumeration
├── test_mldsa_keygen.sh        # ML-DSA key generation (44/65/87)
├── test_mldsa_sign_verify.sh   # Sign + verify round-trip
├── test_hash_mldsa.sh          # Pre-hash ML-DSA
├── test_mlkem_keygen.sh        # ML-KEM key generation (768/1024)
├── test_encapsulate.sh         # TPM2_Encapsulate
├── test_decapsulate.sh         # TPM2_Decapsulate
├── test_kem_roundtrip.sh       # Encap → Decap shared secret match
├── test_sign_sequence.sh       # Streaming sign/verify
├── test_sign_digest.sh         # Direct digest sign/verify
├── test_pqc_ek.sh              # PQC Endorsement Key
├── test_pqc_ak.sh              # PQC Attestation Key
├── test_pqc_quote.sh           # Quote with ML-DSA AK
├── test_pqc_certify.sh         # Certify with PQC keys
├── test_hybrid_hierarchy.sh    # Classical + PQC coexistence
├── test_buffer_sizes.sh        # Large key/sig handling
├── test_nv_pqc_cert.sh         # NV storage of PQC certificates
├── test_error_codes.sh         # TPM_RC_EXT_MU and other new errors
└── run_all.sh                  # Runner script
```

#### Interop Tests (with softhsmv3)

```
tests/interop/
├── test_mldsa_cross_sign.sh    # Sign in TPM → verify in PKCS#11
├── test_mldsa_cross_verify.sh  # Sign in PKCS#11 → verify in TPM
├── test_mlkem_cross_encap.sh   # Encap in TPM → Decap in PKCS#11
├── test_mlkem_cross_decap.sh   # Encap in PKCS#11 → Decap in TPM
└── run_interop.sh
```

---

## Phase 5: WASM Build for PQC Today (3-4 weeks)

### 5.1 Emscripten Build (Week 17)

**Goal**: Compile libtpms to WASM using Emscripten.

#### Approach

Follow the proven softhsmv3 Emscripten build pattern:

```cmake
# wasm/CMakeLists.txt
set(CMAKE_TOOLCHAIN_FILE ${EMSDK}/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake)

# Key flags (same as softhsmv3)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s WASM=1 -s ALLOW_MEMORY_GROWTH=1")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s EXPORTED_RUNTIME_METHODS=['ccall','cwrap']")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s MODULARIZE=1 -s EXPORT_NAME='PqcTpm'")

# Link OpenSSL WASM build (reuse softhsmv3's OpenSSL WASM)
target_link_libraries(pqctpm
    ${OPENSSL_WASM_DIR}/lib/libssl.a
    ${OPENSSL_WASM_DIR}/lib/libcrypto.a
)
```

#### Challenges & Mitigations

| Challenge | Mitigation |
|-----------|------------|
| libtpms uses `fork()` in some code paths | Disable/stub — WASM is single-threaded |
| File I/O for NV state | In-memory NVRAM (like softhsmv3 WASM) |
| Socket transport in swtpm | Not needed — call `TPMLIB_Process()` directly |
| OpenSSL WASM build | Already solved in softhsmv3 — reuse the same build |

#### WASM API Surface

```typescript
// wasm/pqctpm.ts — TypeScript wrapper

export interface PqcTpm {
  // Lifecycle
  startup(): void
  shutdown(): void

  // Raw command interface (for advanced use)
  process(command: Uint8Array): Uint8Array

  // High-level API
  createPrimary(hierarchy: 'ek' | 'srk', algorithm: 'mldsa65' | 'mlkem768' | ...): KeyHandle
  create(parent: KeyHandle, algorithm: string): { pub: Uint8Array, priv: Uint8Array }
  load(parent: KeyHandle, pub: Uint8Array, priv: Uint8Array): KeyHandle

  // PQC operations
  sign(key: KeyHandle, message: Uint8Array): Uint8Array
  verify(key: KeyHandle, message: Uint8Array, signature: Uint8Array): boolean
  encapsulate(key: KeyHandle): { secret: Uint8Array, ciphertext: Uint8Array }
  decapsulate(key: KeyHandle, ciphertext: Uint8Array): Uint8Array

  // Attestation
  quote(ak: KeyHandle, pcrs: number[]): { quote: Uint8Array, signature: Uint8Array }
  certify(key: KeyHandle, ak: KeyHandle): { certify: Uint8Array, signature: Uint8Array }

  // PCR
  pcrExtend(index: number, data: Uint8Array): void
  pcrRead(index: number): Uint8Array
}
```

#### Verification
- [ ] WASM build produces `pqctpm.wasm` + `pqctpm.js`
- [ ] `PqcTpm.startup()` succeeds in browser
- [ ] ML-DSA sign/verify works in browser
- [ ] ML-KEM encap/decap works in browser
- [ ] WASM size < 5MB (target: comparable to softhsmv3 ~2.3MB)

---

### 5.2 PQC Today Integration (Weeks 18-19)

**Goal**: Add TPM workshop tools to the PQC Timeline App.

#### New Module: TPM PQC Workshop

```
src/components/PKILearning/modules/SecureBootPQC/workshop/
├── TPMKeyHierarchyExplorer.tsx  # EXISTS — upgrade from static to live WASM
├── TPMPqcDemo.tsx               # NEW — live ML-DSA/ML-KEM via WASM TPM
├── TPMAttestationDemo.tsx       # NEW — quote/certify with PQC keys
└── TPMInteropDemo.tsx           # NEW — TPM ↔ softhsmv3 cross-validation
```

#### TPMPqcDemo.tsx Design

```
┌─────────────────────────────────────────────┐
│ TPM 2.0 V1.85 PQC Workshop                 │
├─────────────────────────────────────────────┤
│ [1] Create ML-KEM Endorsement Key           │
│     Algorithm: [ML-KEM-768 ▼]               │
│     [Generate EK]                           │
│     Public Key: 0x04a3b2... (1184 bytes)    │
│                                             │
│ [2] Create ML-DSA Attestation Key           │
│     Algorithm: [ML-DSA-65 ▼]               │
│     [Generate AK]                           │
│     Public Key: 0x7f2e... (1952 bytes)      │
│                                             │
│ [3] Encapsulate / Decapsulate               │
│     [Encapsulate] → Ciphertext: ...         │
│     [Decapsulate] → Shared Secret: ...      │
│     ✓ Secrets match                         │
│                                             │
│ [4] Sign / Verify                           │
│     Message: [Hello, TPM PQC!          ]    │
│     [Sign with AK]                          │
│     Signature: 0x3a... (3309 bytes)         │
│     [Verify] → ✓ Valid                      │
│                                             │
│ [PKCS#11 Log]  [TPM Command Log]            │
└─────────────────────────────────────────────┘
```

#### Verification
- [ ] TPMPqcDemo renders in browser
- [ ] All 4 steps work with live WASM TPM
- [ ] TPM command log shows raw TPM2_Encapsulate/Sign bytes
- [ ] Cross-validation with softhsmv3 PKCS#11 panel

---

### 5.3 KAT Tests for TPM PQC (Week 19)

**Goal**: Known Answer Tests validating TPM PQC operations.

Follow existing KAT pattern in `kat/kat_03282026.csv`:

```csv
KAT-TPM-1000,ML-DSA-65,/kat/SecureBootPQC/TPMPqcDemo/step_1_create_ek.json,...
KAT-TPM-1001,ML-DSA-65,/kat/SecureBootPQC/TPMPqcDemo/step_2_create_ak.json,...
KAT-TPM-1002,ML-KEM-768,/kat/SecureBootPQC/TPMPqcDemo/step_3_encapsulate.json,...
KAT-TPM-1003,ML-DSA-65,/kat/SecureBootPQC/TPMPqcDemo/step_4_sign_verify.json,...
```

---

## Dependencies & Prerequisites

### Required Before Phase 1 Start

1. **TCG Algorithm Registry 2.0 RC2** — download PDF manually from TCG site
   (Cloudflare blocks automation). Need exact `TPM_ALG_ID` numeric values.

2. **TCG TPM 2.0 Library Spec V1.85 RC4** — download all 4 parts:
   - Part 0: Introduction
   - Part 1: Architecture
   - Part 2: Structures
   - Part 3: Commands

3. **OpenSSL 3.6.2 source** — already available in pqc-timeline-app
   (`openssl-3.6.2-src/`). Reuse for libtpms build.

4. **wolfTPM PR #445 code review** — study implementation for spec interpretation
   (do NOT copy code — different license).

### Required Before Phase 5 Start

5. **Emscripten SDK** — already installed for softhsmv3 WASM builds.

6. **OpenSSL WASM build** — already built for softhsmv3. Reuse artifacts from
   `~/antigravity/softhsmv3/build-wasm/`.

---

## Success Criteria

| Milestone | Criteria | Target Date |
|-----------|----------|-------------|
| Phase 1 complete | ML-DSA + ML-KEM keygen/sign/verify/encap/decap via swtpm | TBD + 6 weeks |
| Phase 2 complete | All 8 V1.85 commands functional | TBD + 12 weeks |
| Phase 3 complete | PQC EK/AK, dual hierarchy | TBD + 16 weeks |
| Phase 4 complete | Attestation + compliance suite | TBD + 20 weeks |
| Phase 5 complete | WASM build + PQC Today integration | TBD + 24 weeks |
| Interop validated | softhsmv3 PKCS#11 ↔ TPM cross-check passes | Phase 4 |
| Hardware interop | Tested against SEALSQ QVault TPM 185 | Oct 2026 (external) |
| Upstream PR | Patch series submitted to libtpms | After Phase 2 |
