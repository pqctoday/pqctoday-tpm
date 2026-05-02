# pqctoday-tpm

Post-quantum TPM 2.0 emulator implementing [TCG TPM 2.0 Library Specification V1.85](https://trustedcomputinggroup.org/resource/tpm-library-specification/) PQC extensions.

Fork of [libtpms v0.10.2](https://github.com/stefanberger/libtpms) + [swtpm v0.10.1](https://github.com/stefanberger/swtpm) with **ML-KEM** (FIPS 203) and **ML-DSA** (FIPS 204) support via OpenSSL 3.6+ EVP.

---

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| **1 — Foundation** | Algorithm IDs, crypto primitives (ML-DSA + ML-KEM), marshal/unmarshal, NIST ACVP KATs | ✅ Complete |
| **2 — V1.85 Commands** | `TPM2_Encapsulate`, `TPM2_Decapsulate`, `TPM2_SignDigest`, `TPM2_VerifyDigestSignature` — live; sequence commands wired, pending Phase 4 | ✅ In progress (4/8 live) |
| **3 — Key Hierarchy** | ML-KEM EK + ML-DSA AK provisioning, `MakeCredential`/`ActivateCredential` via ML-KEM, `CryptSelectSignScheme` for ML-DSA, self-signed X.509 PQC EK certs | ✅ Complete |
| 4 — Attestation | `TPM2_Quote`, `TPM2_Certify`, PCR banks | 🔲 Not started |
| 5 — WASM | Emscripten build, browser API, PQC Today integration | 🔲 Not started |

**What works today:**

- `TPM2_CreatePrimary` / `TPM2_Create` / `TPM2_Load` with ML-DSA and ML-KEM keys
- `TPM2_Encapsulate` — encapsulate against a loaded ML-KEM public key, returns ciphertext + shared secret
- `TPM2_Decapsulate` — decapsulate with a loaded ML-KEM private key, returns shared secret
- `TPM2_SignDigest` — sign a pre-computed digest with a loaded ML-DSA or HashML-DSA key
- `TPM2_VerifyDigestSignature` — verify an ML-DSA / HashML-DSA signature over a pre-computed digest, returns `TPM_ST_DIGEST_VERIFIED` ticket
- `MakeCredential` / `ActivateCredential` transport via ML-KEM-768 (`CryptSecretEncrypt`/`Decrypt` ML-KEM path)
- ML-KEM-768 EK and ML-DSA-65 AK auto-provisioned by `swtpm_setup` at Docker startup (persistent handles `0x810100A0`/`0x810100A1`)
- Self-signed X.509 EK certs (`mlkem_ek.cert`, `mldsa_ak.cert`) emitted by `swtpm_setup --create-ek-cert`: ML-KEM-768 / ML-DSA-65 SPKI signed with an ephemeral ML-DSA-65 issuer (NIST CSOR OIDs auto-emitted by OpenSSL 3.5+; FIPS 204 §5.4 hash-and-sign internally)
- All classical TPM operations (RSA, ECC, symmetric) work unchanged via the swtpm socket
- TCG V1.85 PQC compliance suite: **92 passed, 0 failed, 0 skipped**

**Streaming sequence commands** (`TPM2_SignSequenceStart/Complete`, `TPM2_VerifySequenceStart/Complete`) are dispatch-wired and return `TPM_RC_COMMAND_CODE` until Phase 4, which requires a new `MLDSA_SEQUENCE_OBJECT` type for holding live `EVP_MD_CTX*` state across command boundaries.

---

## What V1.85 adds

### New algorithms

| Algorithm | TCG ID | FIPS standard | Key sizes |
| --- | --- | --- | --- |
| ML-KEM-512 / 768 / 1024 | `0x00A0` | FIPS 203 | pk 800/1184/1568 B, seed 64 B |
| ML-DSA-44 / 65 / 87 | `0x00A1` | FIPS 204 | pk 1312/1952/2592 B, seed 32 B |
| HashML-DSA | `0x00A2` | FIPS 204 §5.4 | pre-hash variant |

### New TPM command codes

| Command | Code | Status |
| --- | --- | --- |
| `TPM2_VerifyDigestSignature` | `0x1A5` | ✅ Live (Phase 2) |
| `TPM2_SignDigest` | `0x1A6` | ✅ Live (Phase 2) |
| `TPM2_Encapsulate` | `0x1A7` | ✅ Live (Phase 2) |
| `TPM2_Decapsulate` | `0x1A8` | ✅ Live (Phase 2) |
| `TPM2_VerifySequenceComplete` | `0x1A3` | 🔲 Phase 4 |
| `TPM2_SignSequenceComplete` | `0x1A4` | 🔲 Phase 4 |
| `TPM2_VerifySequenceStart` | `0x1A9` | 🔲 Phase 4 |
| `TPM2_SignSequenceStart` | `0x1AA` | 🔲 Phase 4 |

---

## Integrating as a swtpm socket consumer

### Prerequisites

- Docker (image built below, ~800 MB including OpenSSL 3.6.2 built from source)
- `tpm2-tools` v5+ on the host (for classical operations)

### Start the emulator

```bash
# Build the dev image (first time only — ~8 min)
docker build -f docker/Dockerfile.dev -t pqctoday-tpm-dev .

# Start swtpm on TCP socket 2321/2322
docker run -d --name pqc-tpm \
  -p 2321:2321 -p 2322:2322 \
  pqctoday-tpm-dev \
  swtpm socket --tpm2 \
    --server port=2321 \
    --ctrl type=tcp,port=2322 \
    --tpmstate dir=/tmp/tpm \
    --flags not-need-init
```

### Initialise and use (classical operations)

```bash
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"

tpm2_startup -c
tpm2_getcap algorithms | grep -E 'mldsa|mlkem|rsa|ecc'

# Classical regression: RSA create + sign + verify
tpm2_createprimary -G rsa -c primary.ctx
tpm2_create -C primary.ctx -G rsa -u key.pub -r key.priv
tpm2_load   -C primary.ctx -u key.pub -r key.priv -c key.ctx
echo "hello" | tpm2_sign    -c key.ctx -g sha256 -o sig.bin
echo "hello" | tpm2_verifysignature -c key.ctx -g sha256 -s sig.bin
```

### PQC keys (Phase 2 command surface)

`tpm2-tools` v5.x does not yet recognise `-G mldsa65` or accept raw algorithm IDs via `-G 0xa1`.
PQC key operations work through raw TPM command bytes, as demonstrated in
`tests/crossval/src/test_tpm_roundtrip.c`:

```bash
# Build and run the end-to-end test inside the container:
make crossval-build
docker run --rm -v "$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
  bash -c 'cd libtpms && make install > /dev/null 2>&1 && ldconfig && cd - && \
           tests/crossval/build/test_tpm_roundtrip'

# Expected output:
# [PASS] TPMLIB_MainInit (file-backed NV in /tmp/tpm2-rtrip-XXXXXX)
# [PASS] TPM2_Startup(CLEAR)
# [PASS] TPM2_CreatePrimary(MLDSA-65) succeeded (2190 byte response)
# [PASS] outPublic: TPM_ALG_MLDSA, paramSet=MLDSA-65, pk=1952 B — FIPS 204 compliant
# 4 passed, 0 failed
```

To drive PQC commands directly in your application today, use `TPMLIB_Process` (same pattern as
`test_tpm_roundtrip.c`) or any TPM 2.0 library that accepts raw TCTI commands:

```c
// tpm2-tss example (any TCTI)
TSS2_TCTI_CONTEXT *tcti = NULL;
Tss2_TctiLdr_Initialize("swtpm:host=localhost,port=2321", &tcti);

// Algorithm IDs (registered and usable from Phase 1)
// TPM_ALG_MLKEM = 0x00A0
// TPM_ALG_MLDSA = 0x00A1

// Phase 2 command codes (live)
// TPM2_Encapsulate CC            = 0x1A7
// TPM2_Decapsulate CC            = 0x1A8
// TPM2_SignDigest CC             = 0x1A6
// TPM2_VerifyDigestSignature CC  = 0x1A5
```

---

## Integrating as a browser WASM module (Phase 5)

> **Status: Not yet built.** The WASM target is Phase 5 of the roadmap. The
> design is defined in [`docs/wasm-integration.md`](docs/wasm-integration.md).
> This section describes the intended integration path.

The emulator will compile to a single `pqctpm.wasm` + `pqctpm.js` pair via
Emscripten, reusing the same OpenSSL 3.6 WASM build already proven in
[softhsmv3](https://github.com/pqctoday/softhsmv3). No server required — the
full TPM 2.0 state machine runs in the browser.

### Intended API (TypeScript wrapper)

```typescript
import { PqcTpm } from '@pqctoday/tpm-wasm'

const tpm = await PqcTpm.create()           // load + initialise WASM
await tpm.startup()                          // TPM2_Startup(CLEAR)

// Create an ML-DSA-65 signing key
const { handle, publicKey } = await tpm.createPrimary({
  algorithm: 'ML-DSA-65',
  hierarchy: 'owner',
})

// Sign a message
const signature = await tpm.sign({
  keyHandle: handle,
  message:   new TextEncoder().encode('hello world'),
  scheme:    'ML-DSA',
})

// Verify
const ok = await tpm.verify({ publicKey, message, signature })
```

---

## Build

### Docker dev environment (recommended)

```bash
# Build image — Ubuntu 24.04 + OpenSSL 3.6.2 (built from source) + tpm2-tools
docker build -f docker/Dockerfile.dev -t pqctoday-tpm-dev .

# Enter container with repo mounted
docker run --rm -it -v "$PWD:/workspace" -w /workspace pqctoday-tpm-dev bash
```

### libtpms (inside the container)

```bash
cd libtpms
./autogen.sh
./configure --with-tpm2 --with-openssl \
  PKG_CONFIG_PATH=/opt/openssl/lib64/pkgconfig \
  CFLAGS="-I/opt/openssl/include" \
  LDFLAGS="-L/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib64"
make -j$(nproc)
make check       # 10/10 tests green
```

### swtpm (inside the container)

```bash
cd swtpm
./autogen.sh --with-openssl
make -j$(nproc)
```

### Verify the PQC build (inside the container)

```bash
# Confirm OpenSSL 3.6 EVP algorithms are present
openssl list -kem-algorithms | grep ML-KEM
openssl list -signature-algorithms | grep ML-DSA

# Cross-validation: OpenSSL EVP round-trips + NIST ACVP KATs + TPM2_CreatePrimary
make crossval

# Full compliance: 83 checks across §5, §9-§15 of TCG V1.85
make compliance
```

---

## Tests

| Target | What runs | Expected |
| --- | --- | --- |
| `make crossval` | OpenSSL EVP round-trips (ML-DSA-{44,65,87}, ML-KEM-{512,768,1024}), 75 NIST ACVP ML-DSA keyGen KATs, `TPM2_CreatePrimary(MLDSA-65)` end-to-end + `test_pqc_phase3` | 7 + 4 + 11 pass |
| `make crossval-softhsm` | All of above + softhsmv3 C++ cross-verify (sign↔verify, encap↔decap) | all pass |
| `make compliance` | 96-check TCG V1.85 RC4 compliance suite | **96 PASS / 0 FAIL / 0 SKIP** |
| `make wolftpm-xcheck` | **Cross-implementation runtime check.** Drives wolfTPM v4.0.0 PR #445 (wolfCrypt backend) against our libtpms (OpenSSL 3.6.2) over swtpm socket — asserts FIPS 203/204 byte sizes for ML-KEM-{512,768,1024} Encap/Decap roundtrips and ML-DSA-{44,65,87} CreatePrimary | **23/23 pass** |
| `libtpms make check` | Upstream libtpms unit tests | 10/10 pass |

`make wolftpm-xcheck` is the strongest spec-conformance test we have — two completely independent V1.85 implementations agreeing on the byte-on-the-wire layout. Setup is one-shot: `make docker-xcheck` builds an image with pinned wolfSSL + wolfTPM (≈4 min); subsequent `make wolftpm-xcheck` runs in seconds.

> **macOS note:** The cross-val binaries are Linux ELF and run inside Docker. The compliance
> script auto-detects Homebrew OpenSSL 3.6 (`/opt/homebrew/opt/openssl@3.6/bin/openssl`) on
> macOS for static checks; the 2 Linux-ELF binary tests are auto-skipped instead of failing.

---

## Developer guide

### Adding a new V1.85 command

Follow this five-step pattern — each step has a direct model in the Phase 2 implementation.

#### 1. Define `_fp.h` — In/Out structs and RC handle constants

Create `libtpms/src/tpm2/MyCmd_fp.h`. The `RC_MyCmd_*` constants index into the
error-coding scheme; handle parameters start at `TPM_RC_H + TPM_RC_1`, subsequent
handles increment; parameter errors start at `TPM_RC_P + TPM_RC_1`.

```c
// MyCmd_fp.h
typedef struct {
    TPMI_DH_OBJECT  keyHandle;   // handle — excluded from paramOffsets
    TPM2B_DIGEST    input;       // first non-handle in-param
} MyCmd_In;
#define RC_MyCmd_keyHandle  (TPM_RC_H + TPM_RC_1)
#define RC_MyCmd_input      (TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_DIGEST    output;      // first out-param excluded from paramOffsets
} MyCmd_Out;

TPM_RC TPM2_MyCmd(MyCmd_In *in, MyCmd_Out *out);
```

#### 2. Add a `CC_MyCmd` guard in `TpmProfile_CommandList.h`

```c
#define CC_MyCmd  (CC_YES && ALG_MLDSA)   // or CC_YES for unconditional
```

#### 3. Register in `RuntimeCommands.c`

```c
COMMAND(MyCmd, true, 1),   // true = enabled by default; 1 = libtpms-added
```

#### 4. Wire the dispatch table in `CommandDispatchData.h`

Two arrays need entries: `s_unmarshalArray` (input parameter types and handle types),
and `s_marshalArray` (output parameter types). A parallel struct holds the
`paramOffsets` array — byte offsets into the `In` struct for non-handle parameters
(handles are excluded), and into the `Out` struct for output parameters (the first
output parameter gets offset 0 by convention and is excluded from the array).

Add new type codes if your command uses types not already present (e.g., adding
`TPM2B_MY_TYPE_P_UNMARSHAL` after `PARAMETER_LAST_TYPE` and updating that constant).

See the existing ML-DSA / ML-KEM entries immediately before `#if CC_Vendor_TCG_Test`
as the concrete model.

#### 5. Implement the handler

Create `libtpms/src/tpm2/PqcMyCommands.c` (or add to an existing PQC file):

```c
#include "Tpm.h"
#include "MyCmd_fp.h"

#if CC_MyCmd
TPM_RC
TPM2_MyCmd(MyCmd_In *in, MyCmd_Out *out)
{
    OBJECT *obj = HandleToObject(in->keyHandle);

    if (!IsSigningObject(obj))
        return TPM_RCS_KEY + RC_MyCmd_keyHandle;

    return CryptMyOperation(&out->output, obj, &in->input);
}
#endif
```

---

## DevOps guide

### First-time setup

```bash
# Build the dev container (Ubuntu 24.04, OpenSSL 3.6.2 from source, cmake, tpm2-tools)
make docker-dev

# Verify the image
docker run --rm pqctoday-tpm-dev openssl version
# → OpenSSL 3.6.2 ...
```

### Compile verification

Always run inside Docker to ensure the OpenSSL 3.6.2 headers and libraries are available:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace pqctoday-tpm-dev bash -c \
  'cd libtpms && autoreconf -fi && \
   ./configure --with-tpm2 --with-openssl \
     PKG_CONFIG_PATH=/opt/openssl/lib64/pkgconfig \
     CFLAGS="-I/opt/openssl/include" \
     LDFLAGS="-L/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib64" && \
   make -j$(nproc) 2>&1 | tail -10'
```

A clean build produces no warnings. Any `implicit declaration` or `incompatible pointer` error
indicates a missing `_fp.h` include or type mismatch — fix before merging.

### Compliance gate

The compliance script is the canonical PR gate. It must exit **0 FAIL**:

```bash
make compliance
# → ... 83 PASS / 0 FAIL / 2 SKIP
```

The 2 SKIPs are Linux ELF binary checks auto-skipped on macOS (they run green in Docker / CI).

Run the full suite inside Docker to get a zero-SKIP result:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
  bash -c 'cd libtpms && make install -s && ldconfig && cd - && \
           bash tests/compliance/v185_compliance.sh'
# → 83 PASS / 0 FAIL / 0 SKIP
```

### Upstream libtpms unit tests

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace pqctoday-tpm-dev bash -c \
  'cd libtpms && make check'
# → PASS: 10
```

These tests exercise the upstream command dispatcher end-to-end. Any regression here
means a change broke a classical TPM operation — treat as a P0 blocker.

### Cross-validation harness

```bash
make crossval          # build + run in Docker (OpenSSL EVP round-trips + ACVP KATs)
make crossval-softhsm  # also loads softhsmv3 for C++ ↔ Go cross-verify
```

The softhsmv3 variant requires the sibling repo built at `../softhsmv3/build-pqctoday/`.
Override the path: `SOFTHSMV3_DIR=/path/to/softhsmv3 make crossval-softhsm`.

### OpenSSL version check (host)

The macOS system `openssl` is LibreSSL 3.3.6 and does **not** have ML-KEM or ML-DSA.
Use Homebrew OpenSSL 3.6 for any host-side manual checks:

```bash
/opt/homebrew/opt/openssl@3.6/bin/openssl version
# → OpenSSL 3.6.x ...
/opt/homebrew/opt/openssl@3.6/bin/openssl list -signature-algorithms | grep ML-DSA
```

### Patch workflow (upstream submission)

PQC changes are tracked as quilt patches in `patches/`. Before opening a PR against
upstream libtpms, regenerate the patch set:

```bash
cd libtpms
quilt refresh
quilt export patches/
```

---

## Project structure

```text
pqctoday-tpm/
├── libtpms/                          # libtpms v0.10.2 (squashed subtree)
│   └── src/tpm2/
│       ├── TpmTypes.h                # +TPM_ALG_MLKEM/MLDSA/HASH_MLDSA, PQC param sets,
│       │                             #  TPM2B_SIGNATURE_MLDSA, TPMS_SIGNATURE_HASH_MLDSA,
│       │                             #  TPM2B_KEM_CIPHERTEXT, TPM2B_SHARED_SECRET,
│       │                             #  TPM2B_SIGNATURE_CTX, TPM2B_SIGNATURE_HINT,
│       │                             #  TPMU_TK_VERIFIED_META, updated TPMT_TK_VERIFIED
│       ├── TpmAlgorithmDefines.h     # +FIPS 203/204 key/sig/ct size constants,
│       │                             #  MAX_SIGNATURE_HINT_SIZE, TPM_CC_* V1.85 codes
│       ├── TpmProfile_CommandList.h  # +CC_Encapsulate/Decapsulate/SignDigest/
│       │                             #  VerifyDigestSignature/Sequence* guards
│       ├── TpmProfile_Common.h       # ALG_MLKEM/MLDSA/HASH_MLDSA = ALG_YES
│       ├── RuntimeCommands.c         # +V1.85 COMMAND() entries
│       ├── CommandDispatchData.h     # +8 V1.85 command descriptors + dispatch types
│       ├── CryptUtil.c               # +ML-DSA/ML-KEM dispatch in Sign/Verify
│       ├── Marshal.c                 # +PQC TPMU marshal, V1.85 new types
│       ├── Unmarshal.c               # +PQC TPMU unmarshal, V1.85 new types
│       ├── NVMarshal.c               # +PQC NV sensitive marshal
│       ├── Object_spt.c              # +PQC scheme checks
│       │
│       ├── PqcKemCommands.c          # NEW — TPM2_Encapsulate, TPM2_Decapsulate
│       ├── PqcMlDsaCommands.c        # NEW — TPM2_SignDigest, TPM2_VerifyDigestSignature,
│       │                             #        Phase 4 sequence stubs
│       ├── Encapsulate_fp.h          # NEW — Encapsulate In/Out structs
│       ├── Decapsulate_fp.h          # NEW — Decapsulate In/Out structs
│       ├── SignDigest_fp.h           # NEW — SignDigest In/Out structs
│       ├── VerifyDigestSignature_fp.h# NEW — VerifyDigestSignature In/Out structs
│       ├── SignSequenceStart_fp.h    # NEW — Phase 4 stub
│       ├── SignSequenceComplete_fp.h # NEW — Phase 4 stub
│       ├── VerifySequenceStart_fp.h  # NEW — Phase 4 stub
│       ├── VerifySequenceComplete_fp.h# NEW — Phase 4 stub
│       │
│       └── crypto/openssl/
│           ├── CryptMlDsa.c          # ML-DSA via OpenSSL EVP; ctx/hint forwarding
│           ├── CryptMlKem.c          # ML-KEM via OpenSSL EVP
│           └── CryptMlDsa_fp.h       # Updated: CryptMlDsaSign/Validate accept ctx+hint
├── swtpm/                            # swtpm v0.10.1 (squashed subtree, minimal changes)
├── patches/                          # Quilt patches for upstream submission
├── tests/
│   ├── compliance/
│   │   └── v185_compliance.sh        # 83-check TCG V1.85 compliance suite
│   └── crossval/
│       ├── src/
│       │   ├── test_pqc_crossval.c   # OpenSSL EVP round-trips + NIST ACVP KAT driver
│       │   ├── test_tpm_roundtrip.c  # TPM2_CreatePrimary(MLDSA-65) end-to-end
│       │   ├── kat_loader.c          # NIST ACVP JSON parser
│       │   └── p11_helper.c          # PKCS#11 dlopen helper (softhsmv3)
│       └── vectors/
│           └── ML-DSA-keyGen-FIPS204/
│               └── internalProjection.json  # 75 NIST ACVP keyGen vectors
├── docker/
│   └── Dockerfile.dev                # Ubuntu 24.04 + OpenSSL 3.6.2 from source
├── docs/
│   ├── architecture.md               # System design, data flows, file map
│   ├── implementation-plan.md        # Phased roadmap with code-level detail
│   ├── v185-compliance.md            # Command compliance matrix
│   ├── wasm-integration.md           # Browser build + PQC Today API
│   └── standards/                    # TCG V1.85 RC4 Parts 0-3 (PDF)
└── Makefile                          # crossval / compliance / docker-dev targets
```

---

## Key implementation decisions

- **Crypto backend**: OpenSSL 3.6.2 EVP direct (`EVP_PKEY_fromdata`,
  `EVP_DigestSignInit_ex`, `EVP_PKEY_encapsulate`). TPMs don't use HSMs as
  crypto backends; no PKCS#11 in the runtime path.

- **Private keys stored as seeds**: per TCG V1.85 Part 2 Tables 206/210 —
  ML-DSA stores 32-byte seed ξ; ML-KEM stores 64-byte seed d‖z. OpenSSL
  expands both on-demand via `OSSL_PKEY_PARAM_ML_DSA_SEED` /
  `OSSL_PKEY_PARAM_ML_KEM_SEED`.

- **Algorithm IDs**: `TPM_ALG_MLKEM = 0x00A0`, `TPM_ALG_MLDSA = 0x00A1`,
  `TPM_ALG_HASH_MLDSA = 0x00A2` — from TCG Algorithm Registry 2.0 RC2,
  cross-checked against wolfTPM PR #445.

- **Buffer sizing**: `TPM_BUFFER_MAX` enlarged from 4096 → 8192 bytes
  (ML-DSA-87 signature alone is 4627 bytes). `s_actionIoBuffer` doubled
  from 768 → 1536 UINT64 elements.

- **FIPS 204 context string**: `TPM2_SignDigest` and `TPM2_VerifyDigestSignature`
  forward the optional `context` field to OpenSSL via
  `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` / `EVP_PKEY_CTX_set_params`. The `hint`
  field (FIPS 204 randomness override `rnd`) is accepted and silently ignored —
  OpenSSL 3.6 does not expose an external rnd injection API.

- **Streaming sequence commands**: `TPM2_SignSequenceStart/Complete` and
  `TPM2_VerifySequenceStart/Complete` return `TPM_RC_COMMAND_CODE` until Phase 4
  adds `MLDSA_SEQUENCE_OBJECT` (a handle-tracked struct holding a live
  `EVP_MD_CTX*` across command boundaries). wolfTPM PR #445 has the same
  architectural gap for identical reasons.

---

## Related projects

| Project | Relationship |
| --- | --- |
| [softhsmv3](https://github.com/pqctoday/softhsmv3) | PKCS#11 v3.2 PQC HSM — cross-validation partner (independent EVP path) |
| [pqc-timeline-app](https://github.com/pqctoday/pqc-timeline-app) | PQC educational SPA — WASM TPM integration target (Phase 5) |
| [wolfTPM PR #445](https://github.com/wolfSSL/wolfTPM/pull/445) | Alternative V1.85 impl (wolfCrypt backend) — algorithm ID reference |
| [libtpms issue #475](https://github.com/stefanberger/libtpms/issues/475) | Upstream PQC tracking issue |
| [libtpms](https://github.com/stefanberger/libtpms) | Upstream — v0.10.2 pinned |
| [swtpm](https://github.com/stefanberger/swtpm) | Upstream — v0.10.1 pinned |

---

## License

BSD-3-Clause — same as upstream libtpms and swtpm.
