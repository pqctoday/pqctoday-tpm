# Changelog

All notable changes to pqctoday-tpm are documented here.

---

## [Unreleased] — Phase 0 + Phase 2 + Phase 3 + Phase 3.5

### Phase 3.5 — V1.85 RC4 wire-format conformance for PQC parameter blocks

Surfaced by runtime cross-check with wolfTPM v4.0.0 (PR #445) over swtpm socket. CreatePrimary calls from wolfTPM client failed at `inPublic` parsing (parameter index 2):

- `mldsa_sign` → `TPM_RC_SIZE` (extra byte in `TPMS_MLDSA_PARMS`)
- `mlkem_encap` → `TPM_RC_VALUE` (unexpected symmetric-algorithm prefix)

Diagnosis vs `docs/standards/TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf` Tables 229 & 231:

- `TPMS_MLDSA_PARMS` spec layout = `{ parameterSet, allowExternalMu (TPMI_YES_NO) }`. libtpms had only `parameterSet`; the `allowExternalMu` byte selects whether the key is usable with `TPM2_SignDigest` / `TPM2_VerifyDigestSignature` (§12.2.3.6).
- `TPMS_MLKEM_PARMS` spec layout = `{ symmetric (TPMT_SYM_DEF_OBJECT+), parameterSet }`. libtpms had only `parameterSet`; the `symmetric` field is mandatory for restricted decryption keys per §12.2.3.8 (e.g. ML-KEM EK uses AES-128-CFB).

**`libtpms/src/tpm2/TpmTypes.h`**

- Added `TPMI_YES_NO allowExternalMu` to `TPMS_MLDSA_PARMS`.
- Added `TPMT_SYM_DEF_OBJECT symmetric` as the **first** field of `TPMS_MLKEM_PARMS`, then `parameterSet`.

**`libtpms/src/tpm2/Marshal.c` + `Unmarshal.c`**

- `TPMS_MLDSA_PARMS_Marshal` / `_Unmarshal`: emit/parse `parameterSet (UINT16)` then `allowExternalMu (BYTE)`. Unmarshaller validates `allowExternalMu ∈ {NO, YES}` per Part 2 Table 39.
- `TPMS_MLKEM_PARMS_Marshal` / `_Unmarshal`: emit/parse `symmetric (TPMT_SYM_DEF_OBJECT)` first (allowNull = YES so unrestricted keys can pass `TPM_ALG_NULL`), then `parameterSet`.

**Hand-built PQC templates updated to match new spec layout**

- `tests/crossval/src/test_pqc_phase3.c` — `do_create_primary` switches on `algid`; restricted ML-KEM-EK template now emits AES-128-CFB symmetric block; ML-DSA template emits `allowExternalMu=NO`. Response parsers updated for new parm-block sizes (ML-KEM-EK 8 B, ML-DSA-AK 3 B).
- `tests/crossval/src/test_tpm_roundtrip.c` — ML-DSA template adds `allowExternalMu=NO` byte; response parser advances 1 extra byte.
- `tests/crossval/src/tpm_bench.c` — ML-KEM EK/SRK gets restricted-decrypt symmetric (AES-128-CFB); ML-DSA gets `allowExternalMu=NO`.
- `swtpm/src/swtpm_setup/swtpm.c` — `swtpm_tpm2_createprimary_pqc` refactored to take `(parms, parms_len)` instead of just `parameterSet`. ML-KEM-768 EK builder emits 8-byte parms (AES-128-CFB + parameterSet); ML-DSA-65 AK builder emits 3-byte parms (parameterSet + allowExternalMu=NO).

**Verification (Docker dev container, `make compliance` + `make crossval`)**

- Compliance: **92 passed, 0 failed, 0 skipped** (no regression).
- Crossval: 10/10 Phase 3 subtests still green; FIPS-canonical sizes (ML-DSA-65 sig 3309 B, ML-KEM-768 ct 1088 B) preserved.

**End-to-end wolfTPM cross-check** (wolfSSL 5.9.1 `--enable-experimental --enable-dilithium --enable-mlkem` → wolfTPM PR #445 `--enable-pqc --enable-swtpm` → swtpm socket → our libtpms):

```
mldsa_sign  -mldsa=44 → Created ML-DSA primary: handle 0x80000000, pubkey 1312 bytes ✓
mldsa_sign  -mldsa=65 → Created ML-DSA primary: handle 0x80000000, pubkey 1952 bytes ✓
mldsa_sign  -mldsa=87 → Created ML-DSA primary: handle 0x80000000, pubkey 2592 bytes ✓
mlkem_encap -mlkem=512  → Created ML-KEM primary: pubkey 800 bytes  ✓
mlkem_encap -mlkem=768  → Created ML-KEM primary: pubkey 1184 bytes ✓
mlkem_encap -mlkem=1024 → Created ML-KEM primary: pubkey 1568 bytes ✓
```

All six PQC parameter sets succeed at `TPM2_CreatePrimary` cross-implementation. Bilateral wire-format conformance with wolfTPM (independent crypto stack: wolfCrypt vs OpenSSL 3.6.2) achieved on `TPMT_PUBLIC` for the full V1.85 PQC algorithm matrix.

Out-of-scope failures (deferred to Phase 4):

- `SignSequenceStart 0x143 = TPM_RC_COMMAND_CODE` — sequence commands not implemented in libtpms; `MLDSA_SEQUENCE_OBJECT` + dispatch handlers are Phase 4 work.
- wolfTPM client reports `Encapsulate: ciphertext 32 bytes, shared secret 64 bytes` (incorrect — should be 768/1088/1568 B and 32 B) → likely wolfTPM `TPM2_Encapsulate` response-parsing bug; needs upstream investigation.

### Phase 3 — Runtime Plumbing & PQC EK X.509 Certs (Steps 1–5)

Closes the gap between Phase 2 command handlers and end-to-end use. Compliance: **92 passed, 0 failed, 0 skipped**.

**`libtpms/src/tpm2/CommandAttributeData.h`** — generated table fix
- `s_ccAttr[]` and `s_commandAttributes[]` were missing entries for command-code slots `0x01A0`–`0x01AA`. Added 11 entries (3 reserved fill + 8 V1.85 PQC). Without these, `CommandCodeToCommandIndex(0x1A6)` returned `UNIMPLEMENTED_COMMAND_INDEX` and every PQC command rejected with `TPM_RC_COMMAND_CODE`.

**`libtpms/src/tpm2/CommandDispatchData.h`** — generated table fix
- `s_CommandDataArray[]` was missing the 3 fill entries for reserved slots `0x1A0`/`0x1A1`/`0x1A2` that `LIBRARY_COMMAND_ARRAY_SIZE` accounts for via `ADD_FILL`. The off-by-3 made `s_CommandDataArray[135]` point to the Phase-4 `VerifySequenceStart` stub (NULL) instead of `_SignDigestData`, tripping `pAssert(desc != NULL)` in `ParseHandleBuffer` and entering FATAL_ERROR_INTERNAL.

**`libtpms/src/tpm2/RuntimeProfile.c`** — `defaultCommandsProfile`
- Added `0x1a5-0x1a8` to the `default-v1` profile so `VerifyDigestSignature` / `SignDigest` / `Encapsulate` / `Decapsulate` are runtime-enabled. The frozen `null` profile (libtpms v0.9 compat) intentionally remains unchanged.

**`libtpms/src/tpm2/NVDynamic.c`** — `NvObjectToBuffer`
- Added `TPM_ALG_MLDSA`, `TPM_ALG_HASH_MLDSA`, `TPM_ALG_MLKEM` cases. PQC objects always require `ANY_OBJECT_Marshal` (StateFormatLevel ≥ 7). Without these cases, `TPM2_EvictControl` for PQC EKs hit the `default:` arm and called `FAIL(FATAL_ERROR_INTERNAL)`, putting the TPM into failure mode mid-provisioning.

**`tests/crossval/src/test_pqc_phase3.c`**
- Added `TPMLIB_SetProfile("{\"Name\":\"default-v1\"}")` before `TPMLIB_MainInit()` so PQC commands are enabled in the per-test TPM. The default null profile would otherwise gate them out.

**`swtpm/src/swtpm_setup/swtpm.c`** — Phase 3 Step 5: self-signed PQC EK certificates
- New `swtpm_tpm2_pqc_write_ek_certs()` op: writes self-signed X.509 certs (DER) for ML-KEM-768 EK and ML-DSA-65 AK to the user certs directory.
- Cert structure: ephemeral ML-DSA-65 issuer key (per call), subject SPKI = TPM-resident PQC pubkey via `EVP_PKEY_fromdata` + `OSSL_PKEY_PARAM_PUB_KEY`, NIST CSOR OIDs auto-emitted by OpenSSL 3.5+, signed via `EVP_DigestSignInit_ex(..., NULL md, ..., mldsa_pkey, NULL)` per FIPS 204 §5.4 (ML-DSA is hash-and-sign internally; no external hash).
- Cert filenames: `mlkem_ek.cert` (≈ 4.7 KB) and `mldsa_ak.cert` (≈ 5.5 KB). Validity 10 years. Issuer CN = "pqctoday-tpm PQC EK CA (ephemeral)" — these are development artefacts, not production trust anchors. The TCG IWG PQC EK Credential Profile will eventually replace this scheme.
- Guarded by `#if OPENSSL_VERSION_NUMBER >= 0x30500000L`; older OpenSSL silently skips with a log note.
- `swtpm_tpm2_create_pqc_eks()`: `EvictControl` failure for PQC handles is now a `logit` note, not fatal — the TCG IWG hasn't finalised PQC EK persistent handle ranges yet, and the pubkey is captured before persistence anyway.

**`swtpm/src/swtpm_setup/swtpm.h`**
- Added `pqc_write_ek_certs` op to the TPM 2 vtable.

**`swtpm/src/swtpm_setup/swtpm_setup.c`**
- `tpm2_create_eks_and_certs()`: when `--create-ek-cert` is set, after PQC EK provisioning, calls `pqc_write_ek_certs` with the user certs directory (falls back to staging dir when `--write-ek-cert-files` is absent).

**Smoke test (Docker dev container, OpenSSL 3.6.2):**
```
$ swtpm_setup --tpm2 --create-ek-cert --profile-name default-v1 \
              --write-ek-cert-files <dir> --tpm-state <dir>
$ ls <dir>
ek-rsa2048.crt  ek-secp384r1.crt  mldsa_ak.cert  mlkem_ek.cert
$ openssl x509 -in <dir>/mlkem_ek.cert -inform DER -text -noout | grep -E "Algorithm|Subject"
        Signature Algorithm: ML-DSA-65
        Subject: CN=TPM EK (ML-KEM-768), O=pqctoday-tpm
            Public Key Algorithm: ML-KEM-768
```

### Phase 3 — PQC Key Hierarchy (Tests)

**`libtpms/src/tpm2/PqcMlDsaCommands.c` — restriction enforcement fix**

- `TPM2_SignDigest`: added check `IS_ATTRIBUTE(…, TPMA_OBJECT, restricted)` before `CryptSelectSignScheme` — restricted signing keys must be rejected with `TPM_RC_ATTRIBUTES` because `TPM2_SignDigest` accepts arbitrary pre-hashed data without a hashcheck ticket (V1.85 §29.2.1; Part 1 §22.1.2)

**`tests/crossval/src/test_pqc_phase3.c`** (new)

- **Test 1**: `TPM2_CreatePrimary(ML-KEM-768)` in Endorsement hierarchy — verifies pk = 1184 B (FIPS 203)
- **Test 2**: `TPM2_CreatePrimary(ML-DSA-65 restricted+sign)` in Owner hierarchy — verifies pk = 1952 B (FIPS 204)
- **Test 3**: `TPM2_ReadPublic` → `TPM2_MakeCredential` → `TPM2_ActivateCredential` roundtrip via ML-KEM-768 EK — verifies CryptSecretEncrypt/Decrypt ML-KEM path; encryptedSecret.size = 1088 B (ML-KEM-768 ciphertext); recovered certInfo matches original credential
- **Test 4**: `TPM2_SignDigest` with restricted ML-DSA AK → asserts `TPM_RC_ATTRIBUTES` (restriction enforced)
- **Test 5**: `TPM2_CreatePrimary(ML-DSA-65 unrestricted)` + `TPM2_SignDigest` → verifies sigAlg = MLDSA, sig = 3309 B (FIPS 204); confirms `CryptSelectSignScheme` synthetic mldsaScheme path

**`tests/crossval/CMakeLists.txt`**

- Added `test_pqc_phase3` executable linking against `tpms`

**`Makefile`**

- Added `tests/crossval/build/test_pqc_phase3` to the `crossval` target run sequence

**`tests/compliance/v185_compliance.sh`**

- Added `Phase 3 — Key Hierarchy Dispatch` section: 6 source-level grep checks (CryptIsAsymAlgorithm ML-DSA/KEM, CryptSecretEncrypt/Decrypt, CryptSelectSignScheme synthetic scheme, SignDigest restriction guard)
- Added `Phase 3 — Runtime Roundtrip` section: runs `test_pqc_phase3` with same SKIP logic as existing runtime sections

**`docs/TPMdocextract.md`**

- Added Section 13 with spec-authoritative wire formats for `TPM2_ReadPublic` (§12.4.2), `TPM2_MakeCredential` (§12.5.2), `TPM2_ActivateCredential` (§12.6.2), `TPM2_SignDigest` (§29.2.1) — including the restriction rule and TPMT_SIG_SCHEME NULL encoding notes

### Phase 3 — PQC Key Hierarchy (Implementation)

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
