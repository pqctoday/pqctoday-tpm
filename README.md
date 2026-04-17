# pqctoday-tpm

Post-quantum TPM 2.0 emulator implementing [TCG TPM 2.0 Library Specification V1.85](https://trustedcomputinggroup.org/resource/tpm-library-specification/) PQC extensions.

Fork of [libtpms v0.10.2](https://github.com/stefanberger/libtpms) + [swtpm v0.10.1](https://github.com/stefanberger/swtpm) with **ML-KEM** (FIPS 203) and **ML-DSA** (FIPS 204) support via OpenSSL 3.6+ EVP.

---

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| **1 — Foundation** | Algorithm IDs, crypto primitives (ML-DSA + ML-KEM), marshal/unmarshal, NIST ACVP KATs | ✅ Complete |
| 2 — V1.85 Commands | `TPM2_Encapsulate`, `TPM2_Decapsulate`, sign/verify sequence, `TPM2_SignDigest` | 🔲 Not started |
| 3 — Key Hierarchy | PQC EK/AK, hybrid EK certificates | 🔲 Not started |
| 4 — Attestation | `TPM2_Quote`, `TPM2_Certify`, PCR banks | 🔲 Not started |
| 5 — WASM | Emscripten build, browser API, PQC Today integration | 🔲 Not started |

**What works today (Phase 1):** The PQC-enabled libtpms builds and passes all
tests. `TPM2_CreatePrimary` with `TPM_ALG_MLDSA` succeeds end-to-end via direct
libtpms. Classical TPM operations (RSA, ECC) work unchanged via the swtpm socket.
Phase 2 adds the new V1.85 command surface that tpm2-tools will need to drive PQC
keys from the command line.

---

## What V1.85 adds

| Algorithm | TCG ID | FIPS standard | Key sizes |
| --- | --- | --- | --- |
| ML-KEM-512 / 768 / 1024 | `0x00A0` | FIPS 203 | pk 800/1184/1568 B, seed 64 B |
| ML-DSA-44 / 65 / 87 | `0x00A1` | FIPS 204 | pk 1312/1952/2592 B, seed 32 B |
| HashML-DSA | `0x00A2` | FIPS 204 §5.4 | pre-hash variant |

New V1.85 TPM commands (Phase 2+): `TPM2_Encapsulate`, `TPM2_Decapsulate`,
`TPM2_SignSequenceStart/Complete`, `TPM2_VerifySequenceStart/Complete`,
`TPM2_SignDigest`, `TPM2_VerifyDigestSignature`.

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

### Initialise and use (classical operations — work today)

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

### PQC keys today (Phase 1)

`tpm2-tools` v5.x does not yet recognise the `-G mldsa65` name, and does not
accept raw algorithm IDs via `-G 0xa1`. PQC key creation works through raw TPM
command bytes, as demonstrated in `tests/crossval/src/test_tpm_roundtrip.c`:

```bash
# Build and run the Phase 1 end-to-end test inside the container:
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

To create PQC keys programmatically in your own application today, use the
`TPMLIB_Process` API directly (same approach as `test_tpm_roundtrip.c`) or
any TPM 2.0 library that accepts raw TCTI commands — pass `TPM_ALG_MLDSA`
(`0x00A1`) as the object type in `TPM2_CreatePrimary`.

**Phase 2 will add** `tpm2-tools`-compatible PQC command ergonomics once the
new V1.85 commands (`TPM2_Encapsulate`, `TPM2_Decapsulate`, etc.) and the
corresponding `tpm2-tools` PQC template support are implemented.

### Connecting your application via TCTI

Any TPM 2.0 library that supports the `swtpm` TCTI can connect to the emulator
without modification. The PQC algorithm IDs are registered in the TPM's
algorithm capability table and will be returned by `TPM2_GetCapability` once
Phase 2 commands are implemented.

```c
// tpm2-tss example (any TCTI)
TSS2_TCTI_CONTEXT *tcti = NULL;
Tss2_TctiLdr_Initialize("swtpm:host=localhost,port=2321", &tcti);

// TPM_ALG_MLDSA = 0x00A1 (registered, usable from Phase 1)
// TPM_ALG_MLKEM = 0x00A0 (registered, usable from Phase 1)
// TPM2_Encapsulate CC = 0x01A2 (Phase 2)
// TPM2_Decapsulate CC = 0x01A3 (Phase 2)
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

### PQC Today app integration target

The WASM module will power the **TPM Workshop** module in the
[pqc-timeline-app](https://github.com/pqctoday/pqc-timeline-app), enabling
users to generate PQC TPM keys, attest to PCR state, and explore the V1.85
hierarchy entirely in-browser — no installation required.

---

## Build

### Docker dev environment (recommended)

```bash
# Build image — Ubuntu 24.04 + OpenSSL 3.6.2 (built from source) + tpm2-tools
docker build -f docker/Dockerfile.dev -t pqctoday-tpm-dev .

# Enter container with repo mounted
docker run --rm -it -v "$PWD:/workspace" -w /workspace pqctoday-tpm-dev bash
```

### Native (inside the container)

```bash
# libtpms
cd libtpms
./autogen.sh
./configure --with-tpm2 --with-openssl \
  PKG_CONFIG_PATH=/opt/openssl/lib64/pkgconfig \
  CFLAGS="-I/opt/openssl/include" \
  LDFLAGS="-L/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib64"
make -j$(nproc)
make check       # 10/10 tests green

# swtpm
cd ../swtpm
./autogen.sh --with-openssl
make -j$(nproc)
```

### Verify the PQC build

```bash
# Algorithm IDs registered (look for 0xa0, 0xa1, 0xa2)
openssl list -providers -kem-algorithms | grep ML-KEM
openssl list -providers -signature-algorithms | grep ML-DSA

# Cross-validation: OpenSSL EVP + NIST ACVP KATs (no extra deps)
make crossval

# Full compliance: 58 checks across §5, §9-§15 of TCG V1.85
make compliance
```

---

## Tests

| Target | What runs | Expected |
| --- | --- | --- |
| `make crossval` | OpenSSL EVP round-trips (ML-DSA-{44,65,87}, ML-KEM-{512,768,1024}), 75 NIST ACVP ML-DSA keyGen KATs, `TPM2_CreatePrimary(MLDSA-65)` end-to-end | 17/17 pass |
| `make crossval-softhsm` | All of above + softhsmv3 C++ cross-verify (sign↔verify, encap↔decap) | 17/17 pass |
| `make compliance` | 58-check TCG V1.85 compliance suite | 58/58 pass |
| `libtpms make check` | Upstream libtpms unit tests | 10/10 pass |

---

## Project structure

```text
pqctoday-tpm/
├── libtpms/                     # libtpms v0.10.2 (squashed subtree)
│   └── src/tpm2/
│       ├── TpmTypes.h           # +TPM_ALG_MLKEM/MLDSA/HASH_MLDSA, PQC param sets
│       ├── TpmAlgorithmDefines.h# +FIPS 203/204 key/sig/ct size constants
│       ├── TpmProfile_Common.h  # ALG_MLKEM/MLDSA/HASH_MLDSA = ALG_YES
│       ├── CryptUtil.c          # +ML-DSA/ML-KEM dispatch in CreateObject/Sign/Verify
│       ├── Marshal.c            # +PQC TPMU marshal
│       ├── Unmarshal.c          # +PQC TPMU unmarshal
│       ├── NVMarshal.c          # +PQC NV sensitive marshal
│       ├── Object_spt.c         # +PQC scheme checks
│       └── crypto/openssl/
│           ├── CryptMlDsa.c     # NEW — ML-DSA via OpenSSL EVP
│           └── CryptMlKem.c     # NEW — ML-KEM via OpenSSL EVP
├── swtpm/                       # swtpm v0.10.1 (squashed subtree, minimal changes)
├── patches/                     # Quilt patches for upstream submission
├── tests/
│   ├── compliance/
│   │   └── v185_compliance.sh   # 58-check TCG V1.85 compliance suite
│   └── crossval/
│       ├── src/
│       │   ├── test_pqc_crossval.c   # OpenSSL + NIST ACVP KAT driver
│       │   ├── test_tpm_roundtrip.c  # TPM2_CreatePrimary(MLDSA-65) end-to-end
│       │   ├── kat_loader.c          # NIST ACVP JSON parser
│       │   └── p11_helper.c          # PKCS#11 dlopen helper (softhsmv3)
│       └── vectors/
│           └── ML-DSA-keyGen-FIPS204/
│               └── internalProjection.json  # 75 NIST ACVP keyGen vectors
├── docker/
│   └── Dockerfile.dev           # Ubuntu 24.04 + OpenSSL 3.6.2 from source
├── docs/
│   ├── architecture.md          # System design, data flows, file map
│   ├── implementation-plan.md   # Phased roadmap with code-level detail
│   ├── v185-compliance.md       # Command compliance matrix
│   ├── wasm-integration.md      # Browser build + PQC Today API
│   └── standards/               # TCG V1.85 RC4 Parts 0-3 (PDF)
└── Makefile                     # crossval / compliance / docker-dev targets
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
  cross-checked against wolfTPM PR #445. The obvious 0x0040-0x0042 range
  was rejected because it collides with `TPM_ALG_CTR / OFB / CBC`.

- **Buffer sizing**: `TPM_BUFFER_MAX` enlarged from 4096 → 8192 bytes
  (ML-DSA-87 signature alone is 4627 bytes). `s_actionIoBuffer` doubled
  from 768 → 1536 UINT64 elements.

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
