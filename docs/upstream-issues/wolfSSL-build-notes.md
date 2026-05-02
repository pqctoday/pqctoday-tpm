# wolfSSL build incantation for wolfTPM PQC cross-check

**Purpose:** capture the exact wolfSSL `configure` flags that produce a libwolfssl suitable for the wolfTPM `--enable-pqc` cross-check, and explain non-obvious flag interactions. **Not** an upstream bug — wolfSSL itself behaves correctly; the flags below are required by the downstream wolfTPM consumer.

## Verified-good incantation

```bash
git clone --depth=1 https://github.com/wolfSSL/wolfssl
cd wolfssl
./autogen.sh
./configure \
    --prefix=/opt/wolfssl \
    --enable-experimental \
    --enable-dilithium \
    --enable-mlkem \
    --enable-aescfb \
    --enable-cmac \
    --enable-keygen \
    --enable-rsapss \
    --disable-shared --enable-static \
    CFLAGS="-fPIC -DWC_RSA_NO_PADDING"
make -j"$(nproc)" && make install
```

Verified at wolfSSL commit `7b53303` (2026-04). Pinned identically in [`docker/Dockerfile.xcheck`](../../docker/Dockerfile.xcheck).

## Why each flag is needed

| Flag | Reason |
|---|---|
| `--enable-experimental` | Required gate for ML-DSA + ML-KEM in wolfSSL 5.9.x (NIST FIPS 203/204 are still marked experimental in wolfSSL upstream). |
| `--enable-dilithium` | Exposes `wc_dilithium_*` ML-DSA APIs that wolfTPM v1.85 PQC support requires. |
| `--enable-mlkem` | Exposes `wc_MlKemKey_*` ML-KEM APIs (FIPS 203). Note: wolfSSL still calls these "MlKem" not "Kyber" in the API but the algorithm IS NIST-standardised ML-KEM. |
| `--enable-aescfb`, `--enable-cmac`, `--enable-keygen`, `--enable-rsapss` | Required by wolfTPM for classic TPM operations; not PQC-specific but the build fails without them. |
| `--disable-shared --enable-static` | wolfTPM links wolfSSL statically; otherwise two linkers fight over the same symbols at runtime. |
| `CFLAGS="-fPIC ..."` | Required because wolfTPM's libwolftpm.la (built as a libtool archive) needs to be relocatable when the static wolfSSL is linked into it. Without `-fPIC`, the link step fails: `relocation R_AARCH64_ADR_PREL_PG_HI21 against symbol 'wc_Sha512Final' which may bind externally can not be used when making a shared object`. |
| `CFLAGS="... -DWC_RSA_NO_PADDING"` | wolfTPM's `configure` script explicitly checks for this and emits `WARNING: fwTPM: wolfSSL lacks WC_RSA_NO_PADDING — raw RSA operations will return TPM_RC_SCHEME` if missing. The TPM 2.0 spec V1.85 requires raw RSA support for `TPM2_RSA_Encrypt`/`Decrypt` with `TPM_ALG_NULL` scheme. |

## Common misdiagnoses

### "wolfSSL `--enable-mlkem` doesn't expose `wc_MlKemKey_Init`"

The `configure` summary line `ML-KEM standalone: no` is misleading — it refers to `--enable-tls-mlkem-standalone` (a TLS-specific feature for IETF-style standalone key exchange), **not** the wc_MlKem* C API.

The wc_MlKem* API is exposed whenever `--enable-mlkem` is active. Verify with:

```bash
$ grep -E "WOLFSSL_HAVE_MLKEM|HAVE_MLKEM\b" /opt/wolfssl/include/wolfssl/options.h
#define WOLFSSL_HAVE_MLKEM
$ grep -c "wc_MlKemKey_Init" /opt/wolfssl/include/wolfssl/wolfcrypt/wc_mlkem.h
6   # ← function declarations present
```

The actual symptom that triggered this misdiagnosis was wolfTPM's `configure.ac` including the wrong header name (`mlkem.h` vs `wc_mlkem.h`). See [`wolfTPM-001-mlkem-header-rename.md`](wolfTPM-001-mlkem-header-rename.md) for the upstream fix.

### "wolfSSL ML-KEM ciphertext sizes don't match FIPS 203"

Verified false. wolfSSL's ML-KEM-512/768/1024 ciphertext sizes are 768/1088/1568 bytes, byte-exact with FIPS 203 Table 3.

The earlier symptom (wolfTPM client reporting `Encapsulate: ciphertext 32 bytes, shared secret 64 bytes` for ML-KEM-512 — clearly wrong) was caused by **libtpms's** divergence from V1.85 RC4 Part 3 §14.10 Table 61: our `Encapsulate_Out` had `{ciphertext, sharedSecret}` instead of the spec-mandated `{sharedSecret, ciphertext}`. **wolfTPM was correct against the spec; we were not.** Fixed in commit `23a718f6`.

This is the canonical cross-check workflow: when implementations diverge, **read the V1.85 RC4 spec PDF in `docs/standards/`**. wolfTPM is a peer reference, not a spec source.

## Pinning policy

`Dockerfile.xcheck` defaults to:
- `WOLFSSL_REF=7b53303`
- `WOLFTPM_REF=fbbf6fe` (PR #445 merge into v4.0.0)

Override on bump:
```bash
make docker-xcheck WOLFSSL_REF=<new-sha> WOLFTPM_REF=<new-sha>
```

Run `make wolftpm-xcheck` after every bump. Any new failures are V1.85 RC4 spec violations on either side — investigate against the spec, file upstream where appropriate, and update [`tests/compliance/cross-check-report.md`](../../tests/compliance/cross-check-report.md).
