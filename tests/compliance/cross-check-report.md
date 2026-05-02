# PQC Compliance Cross-Check: pqctoday-tpm vs wolfTPM v4.0.0

**Generated:** 2026-05-02 (corrected 2026-05-02)  
**Spec:** TCG TPM 2.0 Library Specification V1.85 RC4 (December 11, 2025) — **authoritative reference**  
**Reference:** wolfSSL/wolfTPM PR #445, merged 2026-04-29, v4.0.0  
**wolfTPM CI:** https://github.com/wolfSSL/wolfTPM/actions/runs/25124489138  
**Spec extract:** `docs/TPMdocextract.md`

---

## Score Summary

| Implementation | PASS | FAIL | SKIP | Notes |
|---|---|---|---|---|
| **pqctoday-tpm** | 51 | 16 | 0 | 8 Phase 2 + 6 OpenSSL version + 2 Linux binaries |
| **wolfTPM v4.0.0** | 37 | 0 | 7 | 7 runtime skips (wolfCrypt build required) |

Source-level checks only (no Docker build): pqctoday-tpm **51/51** on applicable checks.

---

## §6.3 Algorithm Identifiers (TCG Algorithm Registry)

| Constant | pqctoday-tpm | wolfTPM | V1.85 Spec | Status |
|---|---|---|---|---|
| TPM_ALG_MLKEM | 0x00A0 | 0x00A0 | 0x00A0 | ✅ |
| TPM_ALG_MLDSA | 0x00A1 | 0x00A1 | 0x00A1 | ✅ |
| TPM_ALG_HASH_MLDSA | 0x00A2 | 0x00A2 | 0x00A2 | ✅ |

---

## §11 Parameter Set Identifiers (Part 2 Tables 204, 207)

| Constant | pqctoday-tpm | wolfTPM | Spec value | Status |
|---|---|---|---|---|
| TPM_MLDSA_NONE | 0x0000 | 0x0000 | 0x0000 | ✅ |
| TPM_MLDSA_44 | 0x0001 | 0x0001 | 0x0001 | ✅ |
| TPM_MLDSA_65 | 0x0002 | 0x0002 | 0x0002 | ✅ |
| TPM_MLDSA_87 | 0x0003 | 0x0003 | 0x0003 | ✅ |
| TPM_MLKEM_NONE | 0x0000 | 0x0000 | 0x0000 | ✅ |
| TPM_MLKEM_512 | 0x0001 | 0x0001 | 0x0001 | ✅ |
| TPM_MLKEM_768 | 0x0002 | 0x0002 | 0x0002 | ✅ |
| TPM_MLKEM_1024 | 0x0003 | 0x0003 | 0x0003 | ✅ |

---

## §11.2.6 / §11.2.7 ML-KEM and ML-DSA Sizes (Part 2 Tables 204–210)

### ML-KEM per-variant sizes (Table 204, p.182)

| Parameter set | Spec pub key | Spec ciphertext | Spec shared secret | pqctoday-tpm | wolfTPM |
|---|---|---|---|---|---|
| ML-KEM-512 | 800 | 768 | 32 | ✅ defined | — (MAX_* only) |
| ML-KEM-768 | 1184 | 1088 | 32 | ✅ defined | — (MAX_* only) |
| ML-KEM-1024 | 1568 | 1568 | 32 | ✅ defined | — (MAX_* only) |

### ML-DSA per-variant sizes (Table 207, p.183)

| Parameter set | Spec pub key | Spec signature | pqctoday-tpm | wolfTPM |
|---|---|---|---|---|
| ML-DSA-44 | 1312 | 2420 | ✅ defined | — (MAX_* only) |
| ML-DSA-65 | 1952 | 3309 | ✅ defined | — (MAX_* only) |
| ML-DSA-87 | 2592 | 4627 | ✅ defined | — (MAX_* only) |

> **Advantage:** pqctoday-tpm exposes all per-variant sizes — useful for strict size validation. wolfTPM defines MAX_* bounds only.

### Buffer size constants (MAX_*)

| Constant | pqctoday-tpm | wolfTPM | Spec (Tables 204-210) | Status |
|---|---|---|---|---|
| MAX_MLKEM_PUB_SIZE | 1568 | 1568 | 1568 (ML-KEM-1024 pub) | ✅ |
| MAX_MLKEM_PRIV_SEED_SIZE | 64 | 64 | 64 (Table 206: d‖z seed) | ✅ |
| MAX_MLDSA_PUB_SIZE | 2592 | 2592 | 2592 (ML-DSA-87 pub) | ✅ |
| MAX_MLDSA_SIG_SIZE | 4627 | 4627 | 4627 (ML-DSA-87 sig) | ✅ |
| MAX_MLDSA_PRIV_SEED_SIZE | 32 | 32 | 32 (Table 210: ξ seed) | ✅ |
| MAX_SIGNATURE_CTX_SIZE | 255 | 255 | ≥ 255 for ML-DSA (Table 219) | ✅ |

---

## §10.3 KEM/Shared Secret Sizes — Implementation-Dependent Constants

These are **implementation-dependent** per spec. Both our choice and wolfTPM's choice are spec-compliant.

| Constant | pqctoday-tpm | wolfTPM | Spec requirement | Notes |
|---|---|---|---|---|
| MAX_MLKEM_CT_SIZE | 1568 | 2048 | max ciphertext of supported param sets | Both valid; wolfTPM oversized for margin |
| MAX_SHARED_SECRET_SIZE | 32 | 64 | TPM-dependent (Table 99 note) | Both valid; wolfTPM reserves for future Part 4 salted sessions |
| MAX_SIGNATURE_HINT_SIZE | — | 256 | impl-dependent (Table 221 note) | Not a fixed spec value; 256 is wolfTPM's impl choice. We need to define ≥ required hint size |

---

## §13 V1.85 PQC Command Codes — PLAN DIVERGENCE (CRITICAL)

wolfTPM's values and our compliance script expected values **both match the spec** (Table 11, Part 2 p.52). Our `docs/implementation-plan.md` Phase 2 plan had every code wrong.

| Command | pqctoday-tpm plan | wolfTPM (correct) | V1.85 Spec (Table 11, p.52) | Delta from plan |
|---|---|---|---|---|
| TPM_CC_VerifySequenceComplete | 0x000001A7 | **0x000001A3** | **0x000001A3** | off by 4 |
| TPM_CC_SignSequenceComplete | 0x000001A5 | **0x000001A4** | **0x000001A4** | off by 1 |
| TPM_CC_VerifyDigestSignature | 0x000001A9 | **0x000001A5** | **0x000001A5** | off by 4 |
| TPM_CC_SignDigest | 0x000001A8 | **0x000001A6** | **0x000001A6** | off by 2 |
| TPM_CC_Encapsulate | 0x000001A2 | **0x000001A7** | **0x000001A7** | off by 5 (our value is RESERVED) |
| TPM_CC_Decapsulate | 0x000001A3 | **0x000001A8** | **0x000001A8** | off by 5 |
| TPM_CC_VerifySequenceStart | 0x000001A6 | **0x000001A9** | **0x000001A9** | off by 3 |
| TPM_CC_SignSequenceStart | 0x000001A4 | **0x000001AA** | **0x000001AA** | off by 6 |

> **0x000001A2 is RESERVED in the spec** — our plan assigned it to Encapsulate, which is wrong.  
> **Action required:** Update `docs/implementation-plan.md` before Phase 2 begins.

---

## Structural Gaps — Types We Are Missing

wolfTPM defines several V1.85 structures we don't have yet. All are Phase 2 prerequisites.

| Type | Spec section | wolfTPM (tpm2.h) | pqctoday-tpm | Priority |
|---|---|---|---|---|
| `TPM2B_SIGNATURE_MLDSA` | §11.3.4 Table 216 | ✅ (as `TPM2B_MLDSA_SIGNATURE`*) | ❌ TODO in CryptMlDsa.c:338 | **P0 — blocks Phase 2 signing** |
| `TPMS_SIGNATURE_HASH_MLDSA` | §11.2.7.2 Table 208 | ✅ `{hashAlg, sig}` | ❌ missing | P1 — HashML-DSA marshal |
| `TPMU_SIGNATURE.mldsa` | §11.3.5 Table 217 | ✅ as `TPM2B_MLDSA_SIGNATURE` | ❌ workaround | **P0 — blocks Phase 2 marshal** |
| `TPMU_SIGNATURE.hash_mldsa` | §11.3.5 Table 217 | ✅ as `TPMS_SIGNATURE_HASH_MLDSA` | ❌ missing | P1 |
| `TPM2B_SHARED_SECRET` | §10.3.12 Table 99 | ✅ 64B buf | ❌ missing | P1 — Encapsulate/Decapsulate |
| `TPM2B_SIGNATURE_HINT` | §11.3.9 Table 221 | ✅ 256B buf | ❌ missing | P1 — VerifySequenceStart |
| `TPMU_SIGNATURE_CTX` | §11.3.7 Table 219 | ❌ not reported | ❌ missing | P1 — SignSequenceStart/VerifySequenceStart |
| `TPM2B_SIGNATURE_CTX` | §11.3.8 Table 220 | ❌ not reported | ❌ missing | P1 — SignSequenceComplete/VerifySequenceComplete |
| `TPM2B_KEM_CIPHERTEXT` | §10.3.14 Table 101 | ✅ via `TPMU_KEM_CIPHERTEXT` | ❌ missing | P1 — Encapsulate/Decapsulate output |

> **Naming note (*):** wolfTPM uses `TPM2B_MLDSA_SIGNATURE` — this **diverges from the spec-canonical name `TPM2B_SIGNATURE_MLDSA`** (§11.3.4). Adopt the spec name, not wolfTPM's name.

---

## Scope Comparison

| Dimension | pqctoday-tpm | wolfTPM v4.0.0 |
|---|---|---|
| TPM backend | libtpms v0.10.2 + swtpm (fork) | fwTPM server (in-tree) |
| Crypto backend | OpenSSL 3.6.2 EVP | wolfCrypt |
| Algorithm IDs | ✅ all 3 | ✅ all 3 |
| Parameter set IDs | ✅ all 7 | ✅ all 7 |
| Per-variant sizes | ✅ all 10 | ❌ MAX_* only |
| V1.85 command codes | ❌ Phase 2 | ✅ all 8 |
| TPM2B_SIGNATURE_MLDSA (spec name) | ❌ TODO | ✅ (as TPM2B_MLDSA_SIGNATURE) |
| TPMS_SIGNATURE_HASH_MLDSA | ❌ | ✅ |
| TPM2B_SIGNATURE_HINT | ❌ | ✅ |
| TPM2B_SHARED_SECRET | ❌ | ✅ |
| TPMU_SIGNATURE_CTX | ❌ | ❌ |
| TPM2B_SIGNATURE_CTX | ❌ | ❌ |
| TPM2B_KEM_CIPHERTEXT | ❌ | ✅ (via TPMU_KEM_CIPHERTEXT) |
| WASM build target | ✅ Phase 5 plan | ❌ |
| Hardware TPM HAL | ❌ | ✅ |
| Source files (C/H) | 628 | 170 |
| Test count | 58-check + KATs + round-trip | 119 unit + 18-way matrix |
| NIST ACVP vectors | ML-DSA keyGen (75) | ML-DSA + ML-KEM full suite |

---

## Verdict — Phase 2 Prerequisite Fixes

Before starting Phase 2 command implementation, fix in `TpmTypes.h` / `TpmAlgorithmDefines.h`:

1. **Rename TODO → `TPM2B_SIGNATURE_MLDSA`** — use spec-canonical name (§11.3.4 Table 216), NOT wolfTPM's `TPM2B_MLDSA_SIGNATURE`
2. **Add `TPMS_SIGNATURE_HASH_MLDSA`** struct `{TPMI_ALG_HASH hashAlg; TPM2B_SIGNATURE_MLDSA signature;}` (§11.2.7.2 Table 208)
3. **Add `TPMU_SIGNATURE.mldsa`** (TPM2B_SIGNATURE_MLDSA) and `.hash_mldsa` (TPMS_SIGNATURE_HASH_MLDSA) (§11.3.5 Table 217)
4. **Add `TPM2B_SHARED_SECRET`** (buf `{:MAX_SHARED_SECRET_SIZE}`) (§10.3.12 Table 99) — size 32 or 64 are both spec-valid
5. **Add `TPM2B_SIGNATURE_HINT`** with `MAX_SIGNATURE_HINT_SIZE` (§11.3.9 Table 221) — 256 matches wolfTPM
6. **Add `TPMU_SIGNATURE_CTX`** and **`TPM2B_SIGNATURE_CTX`** (§11.3.7-8 Tables 219-220) — `MAX_SIG_CTX_BYTES ≥ 255`
7. **Add `TPMU_KEM_CIPHERTEXT`** and **`TPM2B_KEM_CIPHERTEXT`** (§10.3.13-14 Tables 100-101)
8. **Correct `docs/implementation-plan.md` command codes** using spec Table 11 values (which wolfTPM also uses)
9. **Keep `MAX_MLKEM_CT_SIZE = 1568`** — spec-exact for ML-KEM-1024; wolfTPM's 2048 is a conservative impl choice
10. **Keep `MLKEM_SHARED_SECRET_SIZE = 32`** — spec says impl-dependent; 32 is correct for ML-KEM all param sets
