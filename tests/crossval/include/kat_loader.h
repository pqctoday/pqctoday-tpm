/*
 * kat_loader.h — NIST ACVP known-answer vector loader
 *
 * Parses NIST ACVP internalProjection.json files into struct arrays our
 * harness can iterate. Copyright 2026 PQC Today. BSD-3-Clause.
 */

#ifndef KAT_LOADER_H
#define KAT_LOADER_H

#include <stddef.h>
#include <stdint.h>

#define KAT_SEED_MAX    32      /* ML-DSA ξ, ML-KEM d, or ML-KEM z */
#define KAT_PK_MAX      2600    /* ML-DSA-87 pk = 2592 */

typedef struct {
    char      param_set[16];    /* "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" */
    int       tc_id;
    uint8_t   seed[KAT_SEED_MAX];
    size_t    seed_len;         /* should be 32 for ML-DSA */
    uint8_t   pk[KAT_PK_MAX];
    size_t    pk_len;
} kat_mldsa_keygen_t;

/* Iterator callback — return non-zero to stop early. udata is opaque. */
typedef int (*kat_mldsa_keygen_cb)(const kat_mldsa_keygen_t *vec, void *udata);

/* Walk all ML-DSA keyGen test cases in the JSON file at `path`.
 * Returns total test cases processed, or -1 on parse error. */
int kat_walk_mldsa_keygen(const char *path,
                          kat_mldsa_keygen_cb cb,
                          void *udata);

#endif /* KAT_LOADER_H */
