# pqctoday-tpm — Patches

This directory holds quilt-style patches we intend to submit upstream
to [libtpms](https://github.com/stefanberger/libtpms) and
[swtpm](https://github.com/stefanberger/swtpm) once stable.

## Path reality vs. design doc

[docs/implementation-plan.md](../docs/implementation-plan.md) was drafted
against the Microsoft TPM 2.0 reference implementation layout
(`TPMCmd/tpm/include/tpm_public/…`). The actual libtpms tree flattens
that hierarchy. Paths in play:

| Design doc (reference tree)                                           | Actual libtpms v0.10.2                                 |
|-----------------------------------------------------------------------|--------------------------------------------------------|
| `TPMCmd/tpm/include/tpm_public/TpmTypes.h`                            | `libtpms/src/tpm2/TpmTypes.h`                          |
| `TPMCmd/tpm/include/TpmConfiguration/TpmProfile_Common.h`             | `libtpms/src/tpm2/TpmProfile_Common.h`                 |
| `TPMCmd/tpm/include/tpm_public/TpmAlgorithmDefines.h`                 | `libtpms/src/tpm2/TpmAlgorithmDefines.h`               |
| `TPMCmd/tpm/src/crypt/CryptRsa.c`                                     | `libtpms/src/tpm2/crypto/openssl/CryptRsa.c`           |
| `TPMCmd/tpm/src/crypt/CryptUtil.c`                                    | `libtpms/src/tpm2/CryptUtil.c`                         |
| `TPMCmd/tpm/src/subsystem/Object_spt.c`                               | `libtpms/src/tpm2/Object_spt.c`                        |
| `TPMCmd/tpm/src/crypt/CryptMlDsa.c` (new)                             | `libtpms/src/tpm2/crypto/openssl/CryptMlDsa.c`         |
| `TPMCmd/tpm/src/crypt/CryptMlKem.c` (new)                             | `libtpms/src/tpm2/crypto/openssl/CryptMlKem.c`         |

## Patch series (in order)

| # | File | Phase | Status |
|---|------|-------|--------|
| 0001 | `0001-v185-algorithm-ids.patch`       | 1.2 | pending |
| 0002 | `0002-v185-size-constants.patch`       | 1.2 | pending |
| 0003 | `0003-enlarge-io-buffers.patch`        | 1.3 | pending |
| 0004 | `0004-cryptmldsa-openssl-evp.patch`    | 1.4 | pending |
| 0005 | `0005-cryptmlkem-openssl-evp.patch`    | 1.5 | pending |
| 0006 | `0006-cryptutil-pqc-dispatch.patch`    | 1.6 | pending |

Patches are generated post-hoc from commits landing in the subtree
(`git format-patch --relative=libtpms <base>..<tip>`). Until Phase 1
lands we work directly in the subtree tree; the patch files are created
as a deliverable when the phase is verified green.
