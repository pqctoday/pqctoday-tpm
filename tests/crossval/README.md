# pqctoday-tpm — Cross-Validation Harness

Developer-run `make crossval` target that independently validates our
post-quantum crypto against **two** algorithmically distinct
implementations: **OpenSSL 3.6.2 EVP** (native providers) and **softhsmv3
PKCS#11** (both C++ engine over OpenSSL and Rust engine using the `fips204`
/ `ml-kem` Rust crates).

## Why

A TPM would never use an HSM as its crypto backend in production — libtpms
talks to OpenSSL EVP directly and always will. The cross-val harness exists
only to ensure our implementation is correct by cross-checking it against
independent implementations under canonical NIST ACVP test vectors.

Not tied to CI. Run locally with `make crossval` when PQC crypto changes.

## Strategy

1. **OpenSSL canonical KATs** — for each NIST ACVP vector, feed the seed
   directly into `EVP_PKEY_fromdata` with `OSSL_PKEY_PARAM_ML_DSA_SEED` /
   `OSSL_PKEY_PARAM_ML_KEM_SEED`, extract the derived public key, and
   assert it matches the canonical expected value bit-for-bit.

2. **softhsmv3 ↔ OpenSSL round-trip** — each impl generates its own
   keypair; we cross-sign and cross-verify to validate wire-format
   compatibility and crypto protocol correctness.

3. **softhsmv3 Rust seed parity** — via softhsmv3's `C_Initialize` +
   `CK_ACVP_TEST_ARGS` + `ACVP_RNG` ChaCha20 hook (see
   `~/antigravity/softhsmv3/rust/src/ffi.rs:46-70`), softhsmv3 Rust
   produces deterministic output for a given ACVP seed. The C++ engine
   matches via `EVP_chacha20`.

## Files

| Path | Purpose |
|---|---|
| `src/test_pqc_crossval.c` | Driver — runs all three strategies above |
| `src/kat_loader.c` | Parses NIST ACVP JSON into test-case structs |
| `src/p11_helper.c` | Thin `dlopen` + `CK_FUNCTION_LIST` wrapper for softhsmv3 |
| `vectors/` | NIST ACVP JSON (bundled — ML-DSA and ML-KEM keyGen / sigGen / encapDecap) |
| `CMakeLists.txt` | Build targets linked against libcrypto + libdl |
| `run.sh` | Docker wrapper — `./run.sh` from repo root |

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `PQCTODAY_TPM_PKCS11_MODULE` | (empty) | dlopen target. Set to `/usr/local/lib/libsofthsmv3.so` for C++ engine, `/usr/local/lib/libsofthsmrustv3.so` for Rust. If empty, softhsmv3 tests are skipped and only OpenSSL-side KATs run. |
| `PQCTODAY_TPM_ACVP_SEED` | (empty) | 32-byte hex seed passed to softhsmv3 via `CK_ACVP_TEST_ARGS`. Required for deterministic softhsmv3 output. |

## Running

From repo root, inside the dev container:

```bash
cd /workspace
make crossval
```

Or without make:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
    bash -c 'cmake -S tests/crossval -B tests/crossval/build \
                   -DCMAKE_PREFIX_PATH=/opt/openssl && \
             cmake --build tests/crossval/build && \
             tests/crossval/build/test_pqc_crossval'
```

## Current status (Phase 1.7 partial)

- `test_pqc_crossval.c` — scaffolding committed, OpenSSL-side KATs
  implemented for ML-DSA-65 keygen and sign/verify round-trip.
- ML-KEM-768 encap/decap round-trip in OpenSSL — in progress.
- softhsmv3 PKCS#11 integration (p11_helper.c) — scaffolded, real
  invocations pending. dlopen + `C_GetFunctionList` handshake works.
- NIST ACVP vectors — small bundled subset under `vectors/` pulled
  from softhsmv3's `rust/fips204-patched/tests/nist_vectors/`.
- Full harness completion is tracked as remaining Phase 1.7 work.
