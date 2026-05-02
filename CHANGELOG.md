# Changelog

All notable changes to pqctoday-tpm are documented here.

---

## [Unreleased] — Phase 0 + Phase 2 + Phase 3

### Phase 3 — PQC Key Hierarchy

**Root cause fixes in `libtpms/src/tpm2/CryptUtil.c`**
- `CryptIsAsymAlgorithm`: added `TPM_ALG_MLDSA`, `TPM_ALG_HASH_MLDSA`, `TPM_ALG_MLKEM` cases — unblocks `MakeCredential`, `ActivateCredential`, and `CryptSelectSignScheme` for all PQC key types
- `CryptIsAsymSignScheme`: added ML-DSA / HashML-DSA cases — validates signature scheme against key type
- `CryptIsValidSignScheme`: added early-return cases for ML-DSA and HashML-DSA — skips hash-field validation that doesn't apply to pure ML-DSA
- `CryptSelectSignScheme`: excluded ML-DSA/HashML-DSA from the `asymDetail.scheme` branch (those keys use `TPMS_MLDSA_PARMS` not `TPMS_ASYM_PARMS`); synthesizes a `TPMT_SIG_SCHEME` from the key type directly
- `CryptSecretEncrypt`: added `TPM_ALG_MLKEM` case — encapsulates via `CryptMlKemEncapsulate`, derives seed via `KDFe(nameAlg, ss, label, ct, pk, bits)`
- `CryptSecretDecrypt`: added `TPM_ALG_MLKEM` case — decapsulates via `CryptMlKemDecapsulate`, derives same seed via `KDFe`

**Bug fix: Phase 2 command files missing from `libtpms/src/Makefile.am`**
- Added `tpm2/PqcMlDsaCommands.c` and `tpm2/PqcKemCommands.c` to the `libtpms_tpm2_la_SOURCES` list — previously these were compiled but not linked into `libtpms.so`, causing `TPM2_VerifyDigestSignature`, `TPM2_SignDigest`, `TPM2_Encapsulate`, `TPM2_Decapsulate` to be undefined at runtime
- Added corresponding `_fp.h` headers to the `EXTRA_DIST` list

**Bug fix: `PqcMlDsaCommands.c` — wrong arguments to `CryptMlDsaValidateSignature`**
- The call passed `(in->keyHandle, &in->digest, &in->signature, ctx)` but the function signature is `(sig, key, digest, ctx)` — corrected to `(&in->signature, signObject, &in->digest, ctx)`
- Added `#include "Attest_spt_fp.h"` to expose `IsSigningObject()` (follows the pattern in `SigningCommands.c`)

**V1.85 PQC EK/AK provisioning in `swtpm/src/swtpm_setup/swtpm.c`**
- Added `TPM2_ALG_MLKEM` (0x00A0), `TPM2_ALG_MLDSA` (0x00A1) and parameter-set constants
- Added provisional persistent handle and NV index constants for ML-KEM-768 EK (0x810100A0) and ML-DSA-65 AK (0x810100A1)
- Added `swtpm_tpm2_createprimary_pqc()` — generic PQC CreatePrimary builder using the simple `parameterSet`-only template (no symmetric or scheme sub-fields); 4096-byte response buffer to accommodate ML-DSA-65's 1952-byte public key
- Added `swtpm_tpm2_createprimary_ek_mlkem768()` — ML-KEM-768 EK in Endorsement hierarchy, attrs `0x000300f2` (restricted+decrypt), off=32
- Added `swtpm_tpm2_createprimary_ak_mldsa65()` — ML-DSA-65 AK in Owner hierarchy, attrs `0x000500f2` (restricted+sign), off=32
- Added `swtpm_tpm2_create_pqc_eks()` — creates both keys and evicts to persistent handles; NV template storage deferred pending TCG IWG PQC provisioning spec
- Registered `create_pqc_eks` in `swtpm2_ops` (swtpm.h + ops table)

**`swtpm/src/swtpm_setup/swtpm_setup.c`**
- `tpm2_create_eks_and_certs()`: calls `create_pqc_eks` after RSA+ECC EK creation; non-fatal (logs a note if the TPM lacks V1.85 support)

**`Makefile`**
- `compliance` target: install libtpms before running the test suite (fixes `libtpms.so.0: cannot open shared object file`)

### Compliance
- Score: **85 PASS / 0 FAIL / 0 SKIP** (up from 83; the previous 84→85 gain came from fixing the `test_tpm_roundtrip` undefined-symbol regression)
- `make crossval` and `make compliance` both clean

---

## [Unreleased] — Phase 0 + Phase 2

### Phase 0 — V1.85 Foundational Types, Constants, and Marshal

**`libtpms/src/tpm2/TpmTypes.h`**
- Added 8 new V1.85 type definitions:
  - `TPM2B_SIGNATURE_MLDSA` (§11.3.4 Table 216) — bare ML-DSA signature blob
  - `TPMS_SIGNATURE_HASH_MLDSA` (§11.2.7.2 Table 208) — HashML-DSA signature with hash binding
  - `TPMU_SIGNATURE_CTX` / `TPM2B_SIGNATURE_CTX` (§11.3.7-8 Tables 219-220) — domain-separation context
  - `TPM2B_SIGNATURE_HINT` (§11.3.9 Table 221) — hint buffer for signature operations
  - `TPM2B_SHARED_SECRET` (§10.3.12 Table 99) — ML-KEM encapsulation shared secret
  - `TPMU_KEM_CIPHERTEXT` / `TPM2B_KEM_CIPHERTEXT` (§10.3.13-14 Tables 100-101) — ML-KEM ciphertext
- Extended `TPMU_SIGNATURE` with `mldsa` (ML-DSA) and `hash_mldsa` (HashML-DSA) members
- Extended `TPMU_ENCRYPTED_SECRET` with `mlkem[MAX_MLKEM_CT_SIZE]` member (§11.4.2 Table 222)
- Added `TPMU_TK_VERIFIED_META` union (§10.6.4 Table 110) — tag-conditional ticket metadata
- Updated `TPMT_TK_VERIFIED` (§10.6.5 Table 112): added `metadata` field; renamed `digest` → `hmac`
- Added V1.85 ticket tag constants: `TPM_ST_MESSAGE_VERIFIED` (0x8026), `TPM_ST_DIGEST_VERIFIED` (0x8027)
- Added 8 V1.85 PQC command code constants (`TPM_CC_VerifySequenceComplete` through `TPM_CC_SignSequenceStart`)
- Updated `TPM_CC_LAST` from 0x19F → 0x1AA

**`libtpms/src/tpm2/TpmAlgorithmDefines.h`**
- Added `MAX_SIGNATURE_HINT_SIZE 256` (§11.3.9)
- Extended `LIBRARY_COMMAND_ARRAY_SIZE` to span 0x1A0–0x1AA with ADD_FILL sentinels; 0x1A2 marked RESERVED

**`libtpms/src/tpm2/Marshal.c` / `Marshal_fp.h`**
- Added `TPMU_TK_VERIFIED_META_Marshal` (tag-conditional, static)
- Updated `TPMT_TK_VERIFIED_Marshal` to serialize `metadata` then `hmac` (was `digest`)
- Added marshal functions: `TPM2B_SIGNATURE_MLDSA_Marshal`, `TPMS_SIGNATURE_HASH_MLDSA_Marshal`,
  `TPM2B_SIGNATURE_CTX_Marshal`, `TPM2B_SIGNATURE_HINT_Marshal`, `TPM2B_SHARED_SECRET_Marshal`,
  `TPM2B_KEM_CIPHERTEXT_Marshal`
- Extended `TPMU_SIGNATURE_Marshal` switch with `TPM_ALG_MLDSA` and `TPM_ALG_HASH_MLDSA` cases

**`libtpms/src/tpm2/Unmarshal.c` / `Unmarshal_fp.h`**
- Updated `TPMT_TK_VERIFIED_Unmarshal` to deserialize `metadata` then `hmac`
- Added unmarshal functions for all new V1.85 types (matching marshal)
- Extended `TPMU_SIGNATURE_Unmarshal` with ML-DSA and HashML-DSA cases

**Cascading `digest` → `hmac` rename** (TPMT_TK_VERIFIED field rename)
- `libtpms/src/tpm2/Ticket.c`: `TicketComputeVerified` updated
- `libtpms/src/tpm2/EACommands.c`: `TPM2_PolicyAuthorize` ticket comparison updated
- `libtpms/src/tpm2/SigningCommands.c`: `TPM2_VerifySignature` null-ticket zeroing updated

**`docs/implementation-plan.md`**
- Corrected all 8 V1.85 command codes (were wrong by multiple positions); removed "TBD" markers

---

### Phase 2 — V1.85 PQC Command Handlers

**New command handler files**
- `libtpms/src/tpm2/PqcKemCommands.c` — `TPM2_Encapsulate` (0x1A7) and `TPM2_Decapsulate` (0x1A8)
  - `TPM2_Encapsulate`: validates ML-KEM key type, calls `CryptMlKemEncapsulate`, returns ciphertext + shared secret
  - `TPM2_Decapsulate`: validates ML-KEM key type, calls `CryptMlKemDecapsulate`, returns shared secret
- `libtpms/src/tpm2/PqcMlDsaCommands.c` — `TPM2_SignDigest` (0x1A6), `TPM2_VerifyDigestSignature` (0x1A5), Phase 4 stubs
  - `TPM2_SignDigest`: validates signing key, scheme, calls `CryptMlDsaSign` with context and hint forwarding
  - `TPM2_VerifyDigestSignature`: validates sign attribute, calls `CryptMlDsaValidateSignature`, builds `TPM_ST_DIGEST_VERIFIED` ticket
  - Sequence command stubs (`TPM2_SignSequenceStart/Complete`, `TPM2_VerifySequenceStart/Complete`): return `TPM_RC_COMMAND_CODE` pending Phase 4 `MLDSA_SEQUENCE_OBJECT`

**New `_fp.h` parameter structure headers**
- `Encapsulate_fp.h`, `Decapsulate_fp.h` — KEM In/Out structs and RC handle constants
- `SignDigest_fp.h`, `VerifyDigestSignature_fp.h` — ML-DSA sign/verify In/Out structs
- `SignSequenceStart_fp.h`, `SignSequenceComplete_fp.h` — Phase 4 sequence start/complete
- `VerifySequenceStart_fp.h`, `VerifySequenceComplete_fp.h` — Phase 4 sequence start/complete

**`libtpms/src/tpm2/TpmProfile_CommandList.h`**
- `CC_Encapsulate` and `CC_Decapsulate`: `(CC_YES && ALG_MLKEM)`
- `CC_SignDigest` and `CC_VerifyDigestSignature`: `(CC_YES && (ALG_MLDSA || ALG_HASH_MLDSA))`
- Sequence commands remain `CC_NO` — Phase 4

**`libtpms/src/tpm2/RuntimeCommands.c`**
- Registered all 8 V1.85 commands via `COMMAND()` macro; 4 live (enabled=1), 4 Phase 4 stubs (enabled=0)

**`libtpms/src/tpm2/CommandDispatchData.h`**
- Added dispatch type codes: `TPM2B_KEM_CIPHERTEXT_P_UNMARSHAL`, `TPM2B_SIGNATURE_CTX_P_UNMARSHAL`,
  `TPM2B_SIGNATURE_HINT_P_UNMARSHAL`; updated `PARAMETER_LAST_TYPE`
- Added response type codes: `TPM2B_KEM_CIPHERTEXT_P_MARSHAL`, `TPM2B_SHARED_SECRET_P_MARSHAL`;
  updated `RESPONSE_PARAMETER_LAST_TYPE`
- Added full dispatch descriptors (paramOffsets + unmarshal/marshal type arrays) for all 8 commands

**`libtpms/src/tpm2/crypto/openssl/CryptMlDsa.c`**
- Removed Phase 1 TODO workaround that cast raw bytes into `&sig->signature`
- `CryptMlDsaSign`: extended signature to accept `ctx` and `hint`; wires FIPS 204 context string
  via `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` + `EVP_PKEY_CTX_set_params`; writes typed union members
  (`mldsa.t.buffer` / `hash_mldsa.signature.t.buffer`); `hint` accepted, not forwarded (OpenSSL 3.6
  does not expose external rnd injection)
- `CryptMlDsaValidateSignature`: extended to accept `ctx`; same context-string wiring on verify path;
  reads typed union members instead of raw cast; renamed internal `params[]` → `initParams[]`

**`libtpms/src/tpm2/crypto/CryptMlDsa_fp.h`**
- Updated `CryptMlDsaSign` and `CryptMlDsaValidateSignature` signatures to include `ctx` and (for sign) `hint`

**`libtpms/src/tpm2/crypto/CryptMlKem_fp.h`**
- Minor cleanup aligned with updated type names

**`libtpms/src/tpm2/CryptUtil.c`**
- Updated two call sites (`CryptMlDsaSign`, `CryptMlDsaValidateSignature`) to pass `NULL` for new `ctx`/`hint` parameters

---

### Compliance

**`tests/compliance/v185_compliance.sh`**
- Auto-detect Homebrew OpenSSL 3.6 at `/opt/homebrew/opt/openssl@3.6/bin/openssl` (and Intel paths);
  falls back to `openssl` — fixes LibreSSL false failures on macOS
- Added Darwin platform guard: Linux ELF cross-val binaries SKIP instead of FAIL when not executable
- Added 25 new checks covering all Phase 0 new types, Phase 2 command codes, FIPS 204 context string,
  `TPM_CC_LAST`, and `TPMU_ENCRYPTED_SECRET.mlkem`
- Score: **83 PASS / 0 FAIL / 2 SKIP** (up from 58)

---

### Documentation

**`README.md`** — full rewrite
- Phase 2 status: 4/8 commands live; table of all 8 commands with correct codes and live/Phase-4 status
- Corrected TCTI code comment (was `0x01A2`/`0x01A3`; now correct `0x1A7`/`0x1A8` etc.)
- New **Developer Guide**: 5-step pattern for adding a V1.85 command handler
- New **DevOps Guide**: Docker setup, compile verification, compliance gate, cross-val harness, upstream patch workflow
- Updated project structure tree with all new Phase 2 files

---

## Previous releases

### Phase 1 (b865b27) — Foundation complete

- Algorithm IDs `TPM_ALG_MLKEM` (0x00A0), `TPM_ALG_MLDSA` (0x00A1), `TPM_ALG_HASH_MLDSA` (0x00A2)
- ML-DSA and ML-KEM crypto primitives via OpenSSL 3.6.2 EVP (`CryptMlDsa.c`, `CryptMlKem.c`)
- `TPM_BUFFER_MAX` 4096 → 8192; `s_actionIoBuffer` 768 → 1536 UINT64 elements
- Marshal / Unmarshal / NVMarshal / Object_spt for all PQC types
- 75 NIST ACVP ML-DSA keyGen KATs — all pass
- `TPM2_CreatePrimary(MLDSA-65)` end-to-end via direct libtpms
- TCG V1.85 compliance suite: 58 checks green
- Docker dev environment: Ubuntu 24.04, OpenSSL 3.6.2 built from source
