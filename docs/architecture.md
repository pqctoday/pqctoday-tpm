# pqctoday-tpm Architecture

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Applications                              │
│  tpm2-tools │ PKCS#11 apps │ PQC Today (browser) │ custom tests │
├──────────────────────────────────────────────────────────────────┤
│                     Transport Layer                              │
│  TCP socket (Docker)  │  WASM direct call (browser)              │
├──────────────────────────────────────────────────────────────────┤
│                         swtpm                                    │
│  Wraps libtpms with socket/chardev interface                     │
│  Changes: buffer size only (~30K LOC, BSD-3)                     │
├──────────────────────────────────────────────────────────────────┤
│                        libtpms                                   │
│  Full TPM 2.0 state machine (~184K LOC, BSD-3)                   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Command Layer (tpm/src/command/)                           │  │
│  │                                                            │  │
│  │  Existing:                    NEW (V1.85):                 │  │
│  │  ├── TPM2_Create             ├── TPM2_Encapsulate          │  │
│  │  ├── TPM2_Sign               ├── TPM2_Decapsulate          │  │
│  │  ├── TPM2_VerifySignature    ├── TPM2_SignSequenceStart    │  │
│  │  ├── TPM2_Quote              ├── TPM2_SignSequenceComplete │  │
│  │  ├── TPM2_Certify            ├── TPM2_VerifySequenceStart  │  │
│  │  └── ...                     ├── TPM2_VerifySequenceComplete│ │
│  │                              ├── TPM2_SignDigest            │  │
│  │                              └── TPM2_VerifyDigestSignature│  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │ Crypto Abstraction (tpm/src/crypt/)                        │  │
│  │                                                            │  │
│  │  Existing:                    NEW:                         │  │
│  │  ├── CryptRsa.c              ├── CryptMlDsa.c             │  │
│  │  ├── CryptEccMain.c          ├── CryptMlKem.c             │  │
│  │  ├── CryptHash.c             └── (LMS/XMSS enable only)   │  │
│  │  ├── CryptSym.c                                           │  │
│  │  └── CryptUtil.c (dispatcher)                              │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │ OpenSSL Binding (tpm/cryptolibs/Ossl/)                     │  │
│  │                                                            │  │
│  │  EVP API calls — same API surface as softhsmv3:            │  │
│  │  ├── EVP_PKEY_CTX_new_from_name("ML-DSA-65")              │  │
│  │  ├── EVP_PKEY_keygen_init() / generate()                  │  │
│  │  ├── EVP_DigestSignInit_ex() / EVP_DigestSign()           │  │
│  │  ├── EVP_PKEY_encapsulate_init() / encapsulate()          │  │
│  │  └── EVP_PKEY_decapsulate_init() / decapsulate()          │  │
│  └────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│                      OpenSSL 3.6+                                │
│  Native PQC: ML-KEM, ML-DSA, SLH-DSA │ EVP provider model      │
└──────────────────────────────────────────────────────────────────┘
```

## Data Flow: ML-KEM Encapsulate

```
Application
  │
  ▼
tpm2_encapsulate -c mlkem.ctx -o ct.bin -o ss.bin
  │
  ▼ (marshal TPM2_Encapsulate command → raw bytes)
  │
TCP socket ──────────────────────────────► swtpm
                                            │
                                            ▼
                                    TPMLIB_Process()
                                            │
                                            ▼
                                    CommandDispatcher
                                    CC = 0x1A2 (Encapsulate)
                                            │
                                            ▼
                                    TPM2_Encapsulate()
                                    ├── Load key object from handle
                                    ├── Validate type == TPM_ALG_MLKEM
                                    ├── Check authorization
                                    │
                                    ▼
                                    CryptEncapsulate()
                                    ├── switch(TPM_ALG_MLKEM)
                                    │
                                    ▼
                                    CryptMlKemEncapsulate()
                                    ├── EVP_PKEY_CTX_new_from_name("ML-KEM-768")
                                    ├── EVP_PKEY_fromdata(pub_key_bytes)
                                    ├── EVP_PKEY_encapsulate_init(ctx)
                                    ├── EVP_PKEY_encapsulate(ctx, ct, ss)
                                    │
                                    ▼
                                    Return {ciphertext, shared_secret}
                                            │
                                            ▼ (marshal response)
                                            │
TCP socket ◄────────────────────────────────┘
  │
  ▼
Application receives ciphertext + shared_secret
```

## Data Flow: WASM (Browser)

```
PQC Today React App
  │
  ▼
pqctpm.ts TypeScript wrapper
  │
  ▼ (construct raw TPM command bytes in JS)
  │
ccall('TPMLIB_Process', ...) ──► pqctpm.wasm
                                    │
                                    ▼
                              (same libtpms path as above)
                                    │
                                    ▼
                              OpenSSL WASM (libcrypto.a)
                                    │
                                    ▼
                              Return to JS via ccall
  │
  ◄─────────────────────────────────┘
  │
  ▼
React component displays result
```

## Key Hierarchy (V1.85 Hybrid)

```
Platform Hierarchy (HT_PLATFORM)
├── RSA-2048 Platform EK          ← classical (existing)
├── ECC P-256 Platform EK         ← classical (existing)
├── ML-KEM-768 Platform EK        ← PQC (NEW)
└── ML-KEM-1024 Platform EK       ← PQC (NEW, CNSA 2.0)

Endorsement Hierarchy (HT_ENDORSEMENT)
├── RSA-2048 EK + EK Certificate  ← classical (existing)
├── ECC P-256 EK + EK Certificate ← classical (existing)
├── ML-KEM-768 EK + EK Cert       ← PQC (NEW, signed by ML-DSA CA)
└── ML-KEM-1024 EK + EK Cert      ← PQC (NEW, CNSA 2.0)

Owner Hierarchy (HT_OWNER)
├── RSA-2048 SRK                   ← classical (existing)
│   ├── RSA Signing Key
│   ├── RSA Storage Key
│   └── AES Wrapping Key
├── ECC P-256 SRK                  ← classical (existing)
│   └── ECDSA Signing Key
└── ML-KEM-768 SRK                 ← PQC (NEW)
    ├── ML-DSA-65 Attestation Key  ← PQC (restricted signing)
    ├── ML-DSA-65 Signing Key      ← PQC (unrestricted)
    ├── ML-KEM-768 Transport Key   ← PQC (key wrapping)
    └── AES-256 Storage Key        ← symmetric (wrapped by ML-KEM SRK)

Null Hierarchy (HT_NULL)
└── Ephemeral keys (any algorithm)
```

## Relationship to softhsmv3

```
┌─────────────────────┐          ┌─────────────────────┐
│    pqctoday-tpm      │          │     softhsmv3        │
│                     │          │                     │
│  Interface: TPM 2.0 │          │  Interface: PKCS#11 │
│  Protocol:  TCG     │          │  Protocol:  OASIS   │
│  Transport: Socket  │          │  Transport: C API   │
│                     │          │                     │
│  Crypto: OpenSSL EVP│ ◄──────► │  Crypto: OpenSSL EVP│
│  (same API calls)   │ cross-   │  (same API calls)   │
│                     │ validate │                     │
│  Key hierarchy: YES │          │  Key hierarchy: NO  │
│  PCR/Attest:    YES │          │  PCR/Attest:    NO  │
│  Seal/Unseal:   YES │          │  Seal/Unseal:   NO  │
│  Dict. Attack:  YES │          │  Dict. Attack:  NO  │
│                     │          │                     │
│  License: BSD-3     │          │  License: GPL-3     │
│  WASM:   Phase 5    │          │  WASM:   Production │
└─────────────────────┘          └─────────────────────┘
         │                                │
         └────────┬───────────────────────┘
                  │
                  ▼
         ┌─────────────────┐
         │  OpenSSL 3.6+    │
         │  ML-KEM, ML-DSA  │
         │  Apache-2.0      │
         └─────────────────┘
```

**softhsmv3 is NOT a code dependency.** Both projects independently call the
same OpenSSL EVP APIs. softhsmv3 serves as:

1. **Reference implementation** — proven EVP call patterns for ML-KEM/ML-DSA
2. **Cross-validation partner** — export key from TPM → import to PKCS#11 → verify
3. **WASM build reference** — Emscripten toolchain config already proven

## File Organization

```
pqctoday/pqctoday-tpm/
│
├── README.md                          # Project overview
├── LICENSE                            # BSD-3-Clause
├── CONTRIBUTING.md                    # Contribution guide + upstream policy
├── CMakeLists.txt                     # Top-level build (wraps autotools)
│
├── libtpms/                           # Forked from stefanberger/libtpms
│   ├── src/tpm2/TPMCmd/
│   │   ├── tpm/include/
│   │   │   ├── tpm_public/TpmTypes.h        # +PQC algorithm IDs
│   │   │   ├── TpmConfiguration/
│   │   │   │   └── TpmProfile_Common.h      # +ALG_MLDSA=YES, buffer sizes
│   │   │   └── Crypt/
│   │   │       ├── CryptMlDsa.h             # NEW
│   │   │       └── CryptMlKem.h             # NEW
│   │   ├── tpm/src/
│   │   │   ├── command/
│   │   │   │   ├── Object/
│   │   │   │   │   ├── Encapsulate.c        # NEW
│   │   │   │   │   └── Decapsulate.c        # NEW
│   │   │   │   └── Signature/
│   │   │   │       ├── SignSequenceStart.c   # NEW
│   │   │   │       ├── SignSequenceComplete.c# NEW
│   │   │   │       ├── VerifySequenceStart.c # NEW
│   │   │   │       ├── VerifySequenceComplete.c # NEW
│   │   │   │       ├── SignDigest.c          # NEW
│   │   │   │       └── VerifyDigestSignature.c  # NEW
│   │   │   └── crypt/
│   │   │       ├── CryptMlDsa.c             # NEW (~400 lines)
│   │   │       ├── CryptMlKem.c             # NEW (~350 lines)
│   │   │       └── CryptUtil.c              # MODIFIED (add PQC dispatch)
│   │   └── tpm/cryptolibs/Ossl/
│   │       └── Helpers.c                    # MODIFIED (PQC EVP helpers)
│   └── ...
│
├── swtpm/                             # Forked from stefanberger/swtpm
│   └── ...                            # Minimal changes (buffer sizes)
│
├── patches/                           # Quilt-style for upstream submission
│   ├── 0001-add-v185-algorithm-ids.patch
│   ├── 0002-enlarge-io-buffers.patch
│   ├── 0003-add-mldsa-crypto.patch
│   ├── 0004-add-mlkem-crypto.patch
│   ├── 0005-add-encapsulate-decapsulate.patch
│   ├── 0006-add-sign-verify-sequence.patch
│   ├── 0007-add-sign-verify-digest.patch
│   ├── 0008-pqc-key-hierarchy.patch
│   └── 0009-pqc-attestation.patch
│
├── wasm/                              # Emscripten WASM build
│   ├── CMakeLists.txt
│   ├── toolchain.cmake
│   ├── pqctpm.ts                      # TypeScript API wrapper
│   ├── pqctpm.test.ts                 # WASM unit tests
│   └── index.html                     # Standalone test harness
│
├── tests/
│   ├── v185_compliance/               # Shell-based compliance tests
│   ├── interop/                       # softhsmv3 cross-validation
│   ├── kat/                           # Known Answer Tests
│   └── fuzz/                          # Fuzzing harness (future)
│
├── docker/
│   ├── Dockerfile                     # Production image
│   ├── Dockerfile.dev                 # Development image
│   └── docker-compose.yml
│
├── .github/
│   └── workflows/
│       ├── ci.yml                     # Build + test
│       ├── compliance.yml             # V1.85 compliance check
│       └── release.yml                # Tagged releases
│
└── docs/
    ├── implementation-plan.md         # This plan
    ├── architecture.md                # This document
    ├── v185-compliance.md             # Command compliance matrix
    └── wasm-integration.md            # Browser integration guide
```

## Build Targets

| Target | Command | Output | Size |
|--------|---------|--------|------|
| libtpms (native) | `cd libtpms && ./autogen.sh && ./configure --with-tpm2 --with-openssl && make` | `libtpms.so` | ~2MB |
| swtpm (native) | `cd swtpm && ./autogen.sh && ./configure && make` | `swtpm` binary | ~500KB |
| Docker | `docker build -f docker/Dockerfile -t pqctoday-tpm .` | Container image | ~200MB |
| WASM | `cd wasm && emcmake cmake .. && make` | `pqctpm.wasm` + `pqctpm.js` | ~3-5MB |
| Tests | `./tests/v185_compliance/run_all.sh` | Pass/fail report | — |
