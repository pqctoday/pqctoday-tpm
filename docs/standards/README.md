# TCG TPM 2.0 Library Specification — V1.85 RC4

This directory archives the **TCG TPM 2.0 Library Specification Version 185
RC4** (12 Dec 2025), the normative reference for this project's PQC work.
Every algorithm ID, command code, structure tag, and error value committed
to `libtpms/src/tpm2/` traces back to a table in one of these four parts.

Starting with V1.85, TCG merged the "Supporting Routines" material (legacy
Part 4) into the inline reference code in Part 3. V1.85 therefore ships as
four parts rather than the five parts of earlier revisions.

## Archived documents

| File | Part | Source |
|------|------|--------|
| [TPM-2.0-Library-Part-0_Introduction-V185-RC4.pdf](TPM-2.0-Library-Part-0_Introduction-V185-RC4.pdf)    | Part 0: Introduction                 | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-0_Introduction-V185-RC4_12Dec2025.pdf) |
| [TPM-2.0-Library-Part-1_Architecture-V185-RC4.pdf](TPM-2.0-Library-Part-1_Architecture-V185-RC4.pdf)    | Part 1: Architecture                 | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1_Architecture-V185-RC4_12Dec2025.pdf) |
| [TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf](TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf)        | Part 2: Structures                   | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2_Structures-V185-RC4_12Dec2025.pdf) |
| [TPM-2.0-Library-Part-3_Commands-V185-RC4.pdf](TPM-2.0-Library-Part-3_Commands-V185-RC4.pdf)            | Part 3: Commands + Supporting Routines | [trustedcomputinggroup.org](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3_Commands-V185-RC4_12Dec2025.pdf) |

## Compliance anchors — where each pqctoday-tpm change is derived

| pqctoday-tpm artifact | V1.85 citation |
|---|---|
| `ALG_MLKEM_VALUE = 0x00A0` (TpmTypes.h)       | Part 2 §6.3 "TPM_ALG_ID" table, row TPM_ALG_MLKEM           |
| `ALG_MLDSA_VALUE = 0x00A1` (TpmTypes.h)       | Part 2 §6.3 "TPM_ALG_ID" table, row TPM_ALG_MLDSA           |
| `ALG_HASH_MLDSA_VALUE = 0x00A2` (TpmTypes.h)  | Part 2 §6.3 "TPM_ALG_ID" table, row TPM_ALG_HASH_MLDSA      |
| `MLDSA_{44,65,87}_*_SIZE` (TpmAlgorithmDefines.h)    | Part 2 §15 "ML-DSA" + FIPS 204 §7.6 Table 3          |
| `MLKEM_{512,768,1024}_*_SIZE` (TpmAlgorithmDefines.h) | Part 2 §14 "ML-KEM" + FIPS 203 §8 Table 3           |
| `MLDSA_PRIVATE_SEED_SIZE = 32`                | Part 2 "TPM2B_PRIVATE_KEY_MLDSA" — size shall be 32 (seed ξ)|
| `MLKEM_PRIVATE_SEED_SIZE = 64`                | Part 2 "TPM2B_PRIVATE_KEY_MLKEM" — size shall be 64 (d‖z)  |
| `MAX_SIGNATURE_CTX_SIZE = 255`                | Part 2 "TPM2B_SIGNATURE_CTX" definition (domain separation) |
| `TPM_BUFFER_MAX = 8192`                       | Required so ML-DSA-87 signatures (4627 B) + TPM header + auth sessions fit a single command/response. |
| `TPM_CC_Encapsulate = 0x1A7`                  | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_Decapsulate = 0x1A8`                  | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_SignDigest = 0x1A6`                   | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_SignSequenceStart = 0x1AA`            | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_SignSequenceComplete = 0x1A4`         | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_VerifySequenceStart = 0x1A9`          | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_VerifySequenceComplete = 0x1A3`       | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_CC_VerifyDigestSignature = 0x1A5`        | Part 2 §6.5 "TPM_CC" table                                  |
| `TPM_ST_MESSAGE_VERIFIED = 0x8026`            | Part 2 §6.9 "TPM_ST" table                                  |
| `TPM_ST_DIGEST_VERIFIED = 0x8027`             | Part 2 §6.9 "TPM_ST" table                                  |
| `TPM_RC_EXT_MU = RC_FMT1 + 0x02B`             | Part 2 §6.6 "TPM_RC" table                                  |

## Cross-reference sources (non-normative)

- [wolfTPM PR #445](https://github.com/wolfSSL/wolfTPM/pull/445) —
  reference implementation by wolfSSL tracking V1.85 RC4. Used to
  sanity-check our numeric values.
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice
  KEM (ML-KEM). Normative for ML-KEM behavior.
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice
  Digital Signature (ML-DSA). Normative for ML-DSA behavior.

## License

TCG specifications are published under a royalty-free reproduction
license (see Part 0 §1 "Copyright Licenses"). We keep local copies here
so every contributor can verify the implementation against the spec
without an external download.

## Refreshing

```bash
cd docs/standards
for PART in "Part-0_Introduction" "Part-1_Architecture" \
            "Part-2_Structures" "Part-3_Commands"; do
  curl -sfL -O \
    "https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-${PART}-V185-RC4_12Dec2025.pdf"
done
```
