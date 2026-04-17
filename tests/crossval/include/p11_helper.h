/*
 * p11_helper.h — minimal PKCS#11 v3.2 client for cross-validation
 *
 * Wraps dlopen + C_GetFunctionList, token init, session mgmt, and
 * keygen/sign/verify/encap/decap for ML-DSA and ML-KEM. Sized for the
 * cross-val harness only, not a general-purpose PKCS#11 client.
 *
 * Copyright 2026 PQC Today. BSD-3-Clause.
 */

#ifndef P11_HELPER_H
#define P11_HELPER_H

#include <stddef.h>
#include <stdint.h>

/* Opaque context. */
typedef struct p11_ctx p11_ctx;

/* Open the PKCS#11 module via dlopen and initialize it. Returns NULL on
 * failure (diagnostic printed to stderr). `so_pin` and `user_pin` are
 * used to provision a fresh token in the first available slot. */
p11_ctx *p11_open(const char *module_path,
                  const char *so_pin,
                  const char *user_pin);

void p11_close(p11_ctx *ctx);

/* ML-DSA operations. param_set ∈ {1,2,3} → CKP_ML_DSA_{44,65,87}. */
int p11_mldsa_generate(p11_ctx *ctx, uint32_t param_set,
                       uint8_t *pk_out, size_t *pk_len,
                       uint64_t *priv_handle_out);

int p11_mldsa_sign(p11_ctx *ctx,
                   uint64_t priv_handle,
                   const uint8_t *msg, size_t msg_len,
                   uint8_t *sig_out, size_t *sig_len);

/* ML-KEM operations. param_set ∈ {1,2,3} → CKP_ML_KEM_{512,768,1024}. */
int p11_mlkem_generate(p11_ctx *ctx, uint32_t param_set,
                       uint8_t *pk_out, size_t *pk_len,
                       uint64_t *priv_handle_out);

int p11_mlkem_decapsulate(p11_ctx *ctx,
                          uint64_t priv_handle,
                          const uint8_t *ct, size_t ct_len,
                          uint8_t *ss_out, size_t *ss_len);

/* Introspection for diagnostics. */
const char *p11_module_description(p11_ctx *ctx);

#endif  /* P11_HELPER_H */
