# TCG TPM 2.0 V1.85 PQC Compliance Matrix

## Status Key

- [ ] Not started
- [~] In progress
- [x] Implemented and tested
- [N/A] Not applicable

---

## 1. Algorithm Support

| Algorithm | TPM_ALG_ID | Parameter Sets | Status | Phase |
|-----------|-----------|----------------|--------|-------|
| ML-DSA | TBD | ML-DSA-44, ML-DSA-65, ML-DSA-87 | [ ] | 1 |
| HashML-DSA | TBD | ML-DSA-44/65/87 + SHA-256/384/512 | [ ] | 1 |
| ML-KEM | TBD | ML-KEM-768, ML-KEM-1024 | [ ] | 1 |
| LMS | 0x0070 | (enable existing) | [ ] | 1 |
| XMSS | 0x0071 | (enable existing) | [ ] | 1 |

## 2. New TPM Commands

| Command | TPM_CC | Auth | Status | Phase |
|---------|--------|------|--------|-------|
| TPM2_Encapsulate | TBD | None (pub key op) | [ ] | 2 |
| TPM2_Decapsulate | TBD | USER auth | [ ] | 2 |
| TPM2_SignSequenceStart | TBD | USER auth | [ ] | 2 |
| TPM2_SignSequenceComplete | TBD | (sequence handle) | [ ] | 2 |
| TPM2_VerifySequenceStart | TBD | None (pub key op) | [ ] | 2 |
| TPM2_VerifySequenceComplete | TBD | (sequence handle) | [ ] | 2 |
| TPM2_SignDigest | TBD | USER auth | [ ] | 2 |
| TPM2_VerifyDigestSignature | TBD | None (pub key op) | [ ] | 2 |

## 3. Data Structures

| Structure | Purpose | Status | Phase |
|-----------|---------|--------|-------|
| TPM2B_KEM_CIPHERTEXT | KEM ciphertext container | [ ] | 2 |
| TPM2B_SHARED_SECRET | KEM shared secret (32 bytes) | [ ] | 2 |
| TPM2B_SIGNATURE_CTX | Sign/verify sequence context | [ ] | 2 |
| TPM2B_PUBLIC_KEY_MLDSA | ML-DSA public key | [ ] | 1 |
| TPM2B_PRIVATE_KEY_MLDSA | ML-DSA private key | [ ] | 1 |
| TPM2B_PUBLIC_KEY_MLKEM | ML-KEM public key | [ ] | 1 |
| TPM2B_PRIVATE_KEY_MLKEM | ML-KEM private key | [ ] | 1 |
| TPMS_MLDSA_PARMS | ML-DSA parameters | [ ] | 1 |
| TPMS_HASH_MLDSA_PARMS | HashML-DSA parameters | [ ] | 1 |
| TPMS_MLKEM_PARMS | ML-KEM parameters | [ ] | 1 |

## 4. Error Codes

| Error | Value | Condition | Status | Phase |
|-------|-------|-----------|--------|-------|
| TPM_RC_EXT_MU | RC_FMT1 + 0x02B | External MU error | [ ] | 2 |
| TPM_ST_MESSAGE_VERIFIED | TBD | Verify sequence success | [ ] | 2 |
| TPM_ST_DIGEST_VERIFIED | TBD | Digest verify success | [ ] | 2 |

## 5. Key Hierarchy

| Feature | Status | Phase |
|---------|--------|-------|
| ML-KEM Endorsement Key (EK) | [ ] | 3 |
| ML-KEM Storage Root Key (SRK) | [ ] | 3 |
| ML-DSA Attestation Key (AK) | [ ] | 3 |
| ML-DSA Signing Key (unrestricted) | [ ] | 1 |
| Hybrid classical+PQC hierarchy coexistence | [ ] | 3 |
| EK certificate (X.509, signed by ML-DSA CA) | [ ] | 3 |
| swtpm_setup PQC provisioning | [ ] | 3 |

## 6. Attestation

| Feature | Status | Phase |
|---------|--------|-------|
| TPM2_Quote with ML-DSA AK | [ ] | 4 |
| TPM2_Certify with ML-DSA AK | [ ] | 4 |
| TPM2_CertifyCreation with PQC | [ ] | 4 |
| PCR extension (hash-based, no PQC change) | [ ] | 4 |
| NV storage for PQC certificates | [ ] | 4 |

## 7. Buffer & Storage

| Feature | Current | V1.85 Required | Status | Phase |
|---------|---------|---------------|--------|-------|
| MAX_COMMAND_SIZE | 4096 | 8192 | [ ] | 1 |
| MAX_RESPONSE_SIZE | 4096 | 8192 | [ ] | 1 |
| MAX_NV_INDEX_SIZE | 2048 | 8192 | [ ] | 1 |
| ML-DSA-87 signature fits in response | No | Yes | [ ] | 1 |
| ML-KEM-1024 ciphertext fits in command | No | Yes | [ ] | 1 |

## 8. Interoperability

| Test | Description | Status | Phase |
|------|-------------|--------|-------|
| softhsmv3 ML-DSA cross-sign | TPM signs → PKCS#11 verifies | [ ] | 4 |
| softhsmv3 ML-DSA cross-verify | PKCS#11 signs → TPM verifies | [ ] | 4 |
| softhsmv3 ML-KEM cross-encap | TPM encaps → PKCS#11 decaps | [ ] | 4 |
| softhsmv3 ML-KEM cross-decap | PKCS#11 encaps → TPM decaps | [ ] | 4 |
| wolfTPM cross-validation | Compare outputs with wolfTPM V1.85 | [ ] | 4 |
| SEALSQ QVault TPM 185 interop | Test against real hardware | [ ] | External |

## 9. WASM Build

| Feature | Status | Phase |
|---------|--------|-------|
| Emscripten build of libtpms | [ ] | 5 |
| TPMLIB_Process() callable from JS | [ ] | 5 |
| TypeScript API wrapper | [ ] | 5 |
| PQC Today SecureBootPQC integration | [ ] | 5 |
| WASM KAT tests | [ ] | 5 |
| WASM size < 5MB | [ ] | 5 |

---

## References

- TCG TPM 2.0 Library Specification V1.85 RC4 (Dec 2025)
- TCG Algorithm Registry Version 2.0 RC2 (April 2025)
- NIST FIPS 203 — ML-KEM
- NIST FIPS 204 — ML-DSA
- NIST SP 800-208 — LMS/HSS
- wolfTPM PR #445 — V1.85 PQC implementation reference
- libtpms issue #475 — PQC support tracking
- softhsmv3 gap-analysis-pkcs11-v3.2.md — PQC crypto reference
