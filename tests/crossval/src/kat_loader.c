/*
 * kat_loader.c — NIST ACVP internalProjection.json parser (json-c based).
 *
 * Copyright 2026 PQC Today. BSD-3-Clause.
 */

#include "kat_loader.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int
hex_decode(const char *hex, uint8_t *out, size_t out_max, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t n = hex_len / 2;
    if (n > out_max) return -1;
    for (size_t i = 0; i < n; ++i) {
        char h = hex[2*i], l = hex[2*i+1];
        int hv = (h >= '0' && h <= '9') ? h - '0'
               : (h >= 'a' && h <= 'f') ? h - 'a' + 10
               : (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
        int lv = (l >= '0' && l <= '9') ? l - '0'
               : (l >= 'a' && l <= 'f') ? l - 'a' + 10
               : (l >= 'A' && l <= 'F') ? l - 'A' + 10 : -1;
        if (hv < 0 || lv < 0) return -1;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    *out_len = n;
    return 0;
}

int
kat_walk_mldsa_keygen(const char *path,
                      kat_mldsa_keygen_cb cb,
                      void *udata)
{
    json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "kat: failed to parse %s\n", path);
        return -1;
    }

    int total = 0;
    int stop = 0;

    json_object *groups;
    if (!json_object_object_get_ex(root, "testGroups", &groups)) {
        fprintf(stderr, "kat: no testGroups in %s\n", path);
        json_object_put(root);
        return -1;
    }

    size_t n_groups = json_object_array_length(groups);
    for (size_t g = 0; g < n_groups && !stop; ++g) {
        json_object *grp = json_object_array_get_idx(groups, g);
        json_object *ps_obj, *tests_obj;
        if (!json_object_object_get_ex(grp, "parameterSet", &ps_obj)) continue;
        if (!json_object_object_get_ex(grp, "tests", &tests_obj)) continue;

        const char *param_set = json_object_get_string(ps_obj);
        size_t n_tests = json_object_array_length(tests_obj);
        for (size_t t = 0; t < n_tests && !stop; ++t) {
            json_object *tc = json_object_array_get_idx(tests_obj, t);
            json_object *id_obj, *seed_obj, *pk_obj;
            if (!json_object_object_get_ex(tc, "tcId", &id_obj)) continue;
            if (!json_object_object_get_ex(tc, "seed", &seed_obj)) continue;
            if (!json_object_object_get_ex(tc, "pk",   &pk_obj))   continue;

            kat_mldsa_keygen_t v;
            memset(&v, 0, sizeof(v));
            strncpy(v.param_set, param_set, sizeof(v.param_set) - 1);
            v.tc_id = json_object_get_int(id_obj);
            if (hex_decode(json_object_get_string(seed_obj),
                           v.seed, sizeof(v.seed), &v.seed_len) != 0) {
                fprintf(stderr, "kat: bad seed hex at tcId=%d\n", v.tc_id);
                continue;
            }
            if (hex_decode(json_object_get_string(pk_obj),
                           v.pk, sizeof(v.pk), &v.pk_len) != 0) {
                fprintf(stderr, "kat: bad pk hex at tcId=%d\n", v.tc_id);
                continue;
            }
            stop = cb(&v, udata);
            total++;
        }
    }

    json_object_put(root);
    return total;
}
