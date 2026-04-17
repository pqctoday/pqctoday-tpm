# pqctoday-tpm

Post-quantum TPM 2.0 emulator implementing [TCG TPM 2.0 Library Specification V1.85](https://trustedcomputinggroup.org/resource/tpm-library-specification/) PQC extensions.

Fork of [libtpms](https://github.com/stefanberger/libtpms) + [swtpm](https://github.com/stefanberger/swtpm) with ML-KEM (FIPS 203) and ML-DSA (FIPS 204) support via OpenSSL 3.6+ EVP.

## Status

**Pre-development** -- implementation plan complete, code not started.

## What V1.85 Adds

| Feature | Description |
|---------|-------------|
| ML-KEM (FIPS 203) | Key encapsulation for Endorsement Keys |
| ML-DSA (FIPS 204) | Digital signatures for Attestation Keys |
| HashML-DSA | Pre-hash ML-DSA variant |
| TPM2_Encapsulate | New command: public-key encapsulation |
| TPM2_Decapsulate | New command: private-key decapsulation |
| Sign/Verify Sequence | Streaming sign/verify for large messages |
| TPM2_SignDigest | Direct digest-based signing |
| Hybrid hierarchy | Classical + PQC keys coexist |

## Build Targets

| Target | Use Case |
|--------|----------|
| Native (Linux) | Docker-based TPM emulation for development and testing |
| WASM (browser) | In-browser TPM for [PQC Today](https://pqctoday.github.io/pqc-timeline-app/) educational demos |

## Project Structure

```
pqctoday-tpm/
├── libtpms/           # Forked libtpms with PQC patches
├── swtpm/             # Forked swtpm (minimal changes)
├── patches/           # Quilt-style patches for upstream submission
├── wasm/              # Emscripten WASM build + TypeScript API
├── tests/             # V1.85 compliance + interop tests
├── docker/            # Container images
└── docs/              # Implementation plan, architecture, compliance matrix
```

## Documentation

- [Implementation Plan](docs/implementation-plan.md) -- phased roadmap with code-level detail
- [Architecture](docs/architecture.md) -- system design, data flows, file organization
- [V1.85 Compliance Matrix](docs/v185-compliance.md) -- command-by-command tracking
- [WASM Integration](docs/wasm-integration.md) -- browser build and PQC Today integration

## Related Projects

| Project | Relationship |
|---------|-------------|
| [softhsmv3](https://github.com/pqctoday/softhsmv3) | PKCS#11 PQC HSM -- cross-validation partner (same OpenSSL EVP backend) |
| [pqc-timeline-app](https://github.com/pqctoday/pqc-timeline-app) | PQC educational SPA -- WASM TPM integration target |
| [wolfTPM PR #445](https://github.com/wolfSSL/wolfTPM/pull/445) | Alternative V1.85 implementation (wolfCrypt backend) |
| [libtpms #475](https://github.com/stefanberger/libtpms/issues/475) | Upstream PQC tracking issue |

## License

BSD-3-Clause (same as upstream libtpms and swtpm)
