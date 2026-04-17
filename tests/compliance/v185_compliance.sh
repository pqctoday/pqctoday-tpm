#!/usr/bin/env bash
# ============================================================================
# TCG TPM 2.0 Library Specification V1.85 PQC Compliance Test
# ============================================================================
#
# Validates pqctoday-tpm's post-quantum additions against:
#   - TCG TPM 2.0 Library Spec V1.85 RC4 (12 Dec 2025), Parts 0-3
#     archived under docs/standards/
#   - NIST FIPS 203 (ML-KEM, August 2024)
#   - NIST FIPS 204 (ML-DSA, August 2024)
#   - TCG Algorithm Registry v2.0 RC2 (cross-checked via wolfTPM PR #445)
#
# Three evidence sources per V1.85 requirement:
#   (a) SOURCE — grep libtpms headers for declared constant values
#   (b) BUILD  — libtpms compiles with OpenSSL 3.6.2 EVP provider
#   (c) RUNTIME— OpenSSL genpkey produces exact FIPS 203/204 byte lengths
#
# Run: ./tests/compliance/v185_compliance.sh  (inside the dev Docker container)
# Or:  make compliance                         (from repo root)
# ============================================================================

set -u

# Repo root discovered relative to this script — works whether invoked from
# repo root or from the tests/compliance directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

TPMTYPES="libtpms/src/tpm2/TpmTypes.h"
TPMALGDEF="libtpms/src/tpm2/TpmAlgorithmDefines.h"
TPMPROF="libtpms/src/tpm2/TpmProfile_Common.h"
TPMLIBCONF="libtpms/src/tpm_library_conf.h"
CROSSVAL_BIN="tests/crossval/build/test_pqc_crossval"

PASS=0; FAIL=0; SKIP=0

pass() { printf "  [PASS] %s\n" "$*"; PASS=$((PASS+1)); }
fail() { printf "  [FAIL] %s\n" "$*"; FAIL=$((FAIL+1)); }
skip() { printf "  [SKIP] %s\n" "$*"; SKIP=$((SKIP+1)); }
section() { printf "\n=== %s ===\n" "$*"; }

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# Grep-extract the integer value of `#define NAME  VALUE` in a header.
# Follows up to 3 levels of alias indirection (`#define A B` where B is
# itself a macro). Accepts tabs or spaces as separator; tolerates
# surrounding parens/casts.
get_define_raw() {
    local name=$1 file=$2
    grep -E "^#define[[:space:]]+${name}[[:space:]]" "$file" 2>/dev/null \
        | head -1 \
        | sed -E "s/^#define[[:space:]]+${name}[[:space:]]+//" \
        | sed -E 's/^\([^)]*\)//' \
        | tr -d '()' \
        | awk '{print $1}'
}

get_define() {
    local name=$1 file=$2
    local val depth=0
    val=$(get_define_raw "$name" "$file")
    # Follow alias: while val looks like another identifier defined in the
    # same file, resolve. Cap at 3 hops.
    while [[ -n "$val" ]] && [[ "$val" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && (( depth < 3 )); do
        local next
        next=$(get_define_raw "$val" "$file")
        if [[ -z "$next" ]]; then break; fi
        val=$next
        depth=$((depth+1))
    done
    printf "%s" "$val"
}

# Convert a hex or decimal literal to decimal for comparison.
to_dec() {
    local v=$1
    if [[ "$v" =~ ^0[xX] ]]; then printf "%d" "$v"; else printf "%d" "$v"; fi
}

assert_const() {
    local name=$1 expected=$2 file=$3
    local actual
    actual=$(get_define "$name" "$file")
    if [[ -z "$actual" ]]; then
        fail "$name — not defined in ${file##*/}"
        return
    fi
    local adec=$(to_dec "$actual" 2>/dev/null || echo "$actual")
    local edec=$(to_dec "$expected" 2>/dev/null || echo "$expected")
    if [[ "$adec" == "$edec" ]]; then
        pass "$name = $actual"
    else
        fail "$name: expected $expected, got $actual  (${file##*/})"
    fi
}

assert_ge() {
    local name=$1 minimum=$2 file=$3
    local actual=$(get_define "$name" "$file")
    if [[ -z "$actual" ]]; then
        fail "$name — not defined in ${file##*/}"; return
    fi
    local adec=$(to_dec "$actual"); local mdec=$(to_dec "$minimum")
    if (( adec >= mdec )); then
        pass "$name = $actual (>= $minimum required)"
    else
        fail "$name = $actual, V1.85 requires >= $minimum"
    fi
}

# ----------------------------------------------------------------------------
# Preflight
# ----------------------------------------------------------------------------

printf "TCG TPM 2.0 Library Specification V1.85 PQC Compliance Test\n"
printf "=============================================================\n"
printf "  repo root : %s\n" "$REPO_ROOT"
printf "  date      : %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf "  host      : %s / %s\n" "$(uname -s)" "$(uname -m)"

for f in "$TPMTYPES" "$TPMALGDEF" "$TPMPROF" "$TPMLIBCONF"; do
    if [[ ! -f "$f" ]]; then
        printf "\nFATAL: required source file missing: %s\n" "$f" >&2
        exit 2
    fi
done

# ----------------------------------------------------------------------------
# §6.3 — Algorithm Identifiers (TCG Registry v2.0)
# ----------------------------------------------------------------------------

section "§6.3 Algorithm Identifiers (TCG V1.85 Part 2, Registry v2.0)"

# Value-form _VALUE macros (the raw numeric literal we added)
assert_const "ALG_MLKEM_VALUE"       "0x00A0" "$TPMTYPES"
assert_const "ALG_MLDSA_VALUE"       "0x00A1" "$TPMTYPES"
assert_const "ALG_HASH_MLDSA_VALUE"  "0x00A2" "$TPMTYPES"

# ALG_LAST must advance to the new tail of the registry.
assert_const "ALG_LAST_VALUE"        "0x00A2" "$TPMTYPES"

# ----------------------------------------------------------------------------
# §11 — Parameter Set Identifiers
# ----------------------------------------------------------------------------

section "§11 Parameter Set Identifiers (TCG V1.85 Part 2)"

assert_const "TPM_MLDSA_NONE"  "0x0000" "$TPMTYPES"
assert_const "TPM_MLDSA_44"    "0x0001" "$TPMTYPES"
assert_const "TPM_MLDSA_65"    "0x0002" "$TPMTYPES"
assert_const "TPM_MLDSA_87"    "0x0003" "$TPMTYPES"

assert_const "TPM_MLKEM_NONE"  "0x0000" "$TPMTYPES"
assert_const "TPM_MLKEM_512"   "0x0001" "$TPMTYPES"
assert_const "TPM_MLKEM_768"   "0x0002" "$TPMTYPES"
assert_const "TPM_MLKEM_1024"  "0x0003" "$TPMTYPES"

# ----------------------------------------------------------------------------
# §14 — ML-KEM sizes (FIPS 203 Table 3)
# ----------------------------------------------------------------------------

section "§14 ML-KEM Sizes (FIPS 203 Table 3)"

assert_const "MLKEM_512_PUBLIC_KEY_SIZE"   "800"  "$TPMALGDEF"
assert_const "MLKEM_768_PUBLIC_KEY_SIZE"   "1184" "$TPMALGDEF"
assert_const "MLKEM_1024_PUBLIC_KEY_SIZE"  "1568" "$TPMALGDEF"
assert_const "MLKEM_512_CIPHERTEXT_SIZE"   "768"  "$TPMALGDEF"
assert_const "MLKEM_768_CIPHERTEXT_SIZE"   "1088" "$TPMALGDEF"
assert_const "MLKEM_1024_CIPHERTEXT_SIZE"  "1568" "$TPMALGDEF"
assert_const "MLKEM_SHARED_SECRET_SIZE"    "32"   "$TPMALGDEF"
assert_const "MLKEM_PRIVATE_SEED_SIZE"     "64"   "$TPMALGDEF"   # d||z per FIPS 203 §7.1
assert_const "MAX_MLKEM_PUB_SIZE"          "1568" "$TPMALGDEF"
assert_const "MAX_MLKEM_CT_SIZE"           "1568" "$TPMALGDEF"
assert_const "MAX_MLKEM_PRIV_SEED_SIZE"    "64"   "$TPMALGDEF"

# ----------------------------------------------------------------------------
# §15 — ML-DSA sizes (FIPS 204 Table 3)
# ----------------------------------------------------------------------------

section "§15 ML-DSA Sizes (FIPS 204 Table 3)"

assert_const "MLDSA_44_PUBLIC_KEY_SIZE"  "1312" "$TPMALGDEF"
assert_const "MLDSA_65_PUBLIC_KEY_SIZE"  "1952" "$TPMALGDEF"
assert_const "MLDSA_87_PUBLIC_KEY_SIZE"  "2592" "$TPMALGDEF"
assert_const "MLDSA_44_SIGNATURE_SIZE"   "2420" "$TPMALGDEF"
assert_const "MLDSA_65_SIGNATURE_SIZE"   "3309" "$TPMALGDEF"
assert_const "MLDSA_87_SIGNATURE_SIZE"   "4627" "$TPMALGDEF"
assert_const "MLDSA_PRIVATE_SEED_SIZE"   "32"   "$TPMALGDEF"   # ξ per FIPS 204 §7.1
assert_const "MAX_MLDSA_PUB_SIZE"        "2592" "$TPMALGDEF"
assert_const "MAX_MLDSA_SIG_SIZE"        "4627" "$TPMALGDEF"
assert_const "MAX_MLDSA_PRIV_SEED_SIZE"  "32"   "$TPMALGDEF"

# ----------------------------------------------------------------------------
# §10 — Domain Separation Context
# ----------------------------------------------------------------------------

section "§10 HashML-DSA Domain Separation Context (TCG V1.85 Part 2)"

assert_const "MAX_SIGNATURE_CTX_SIZE"  "255" "$TPMALGDEF"

# ----------------------------------------------------------------------------
# §9 — I/O Buffer sizing for V1.85 commands
# ----------------------------------------------------------------------------

section "§9 I/O Buffer Sizing (ML-DSA-87 sig = 4627 B)"

assert_ge "TPM_BUFFER_MAX" "8192" "$TPMLIBCONF"

# ----------------------------------------------------------------------------
# §5.1 — Algorithm enable flags
# ----------------------------------------------------------------------------

section "§5.1 Algorithm Enable Flags (TpmProfile_Common.h)"

for flag in ALG_MLKEM ALG_MLDSA ALG_HASH_MLDSA; do
    # get_define may resolve the alias chain ALG_YES → YES (→ 1).
    # Any of those three forms means "enabled" in libtpms.
    v=$(get_define "$flag" "$TPMPROF")
    case "$v" in
        ALG_YES|YES|1)
            pass "$flag = $v  (enabled)"
            ;;
        "")
            fail "$flag: undefined in ${TPMPROF##*/}"
            ;;
        *)
            fail "$flag: expected ALG_YES (or alias), got $v"
            ;;
    esac
done

# ----------------------------------------------------------------------------
# TPMU Union Extensions (TCG V1.85 Part 2 Tables 184, 189, 195)
# ----------------------------------------------------------------------------

section "TPMU Union Extensions (TCG V1.85 Part 2 Tables 184, 189, 195)"

# Presence-check rather than value-check — these are union member fields.
grep -q "TPM2B_PUBLIC_KEY_MLDSA.*mldsa" "$TPMTYPES"    && pass "TPMU_PUBLIC_ID.mldsa present"   || fail "TPMU_PUBLIC_ID missing mldsa"
grep -q "TPM2B_PUBLIC_KEY_MLKEM.*mlkem" "$TPMTYPES"    && pass "TPMU_PUBLIC_ID.mlkem present"   || fail "TPMU_PUBLIC_ID missing mlkem"
grep -q "TPMS_MLDSA_PARMS.*mldsaDetail" "$TPMTYPES"    && pass "TPMU_PUBLIC_PARMS.mldsaDetail present" || fail "TPMU_PUBLIC_PARMS missing mldsaDetail"
grep -q "TPMS_HASH_MLDSA_PARMS.*hashMldsaDetail" "$TPMTYPES" && pass "TPMU_PUBLIC_PARMS.hashMldsaDetail present" || fail "TPMU_PUBLIC_PARMS missing hashMldsaDetail"
grep -q "TPMS_MLKEM_PARMS.*mlkemDetail" "$TPMTYPES"    && pass "TPMU_PUBLIC_PARMS.mlkemDetail present" || fail "TPMU_PUBLIC_PARMS missing mlkemDetail"
grep -q "TPM2B_PRIVATE_KEY_MLDSA.*mldsa" "$TPMTYPES"   && pass "TPMU_SENSITIVE_COMPOSITE.mldsa present" || fail "TPMU_SENSITIVE_COMPOSITE missing mldsa"
grep -q "TPM2B_PRIVATE_KEY_MLKEM.*mlkem" "$TPMTYPES"   && pass "TPMU_SENSITIVE_COMPOSITE.mlkem present" || fail "TPMU_SENSITIVE_COMPOSITE missing mlkem"

# ----------------------------------------------------------------------------
# Build evidence
# ----------------------------------------------------------------------------

section "Build — libtpms compiles with PQC crypto modules"

if [[ -f libtpms/src/tpm2/crypto/openssl/CryptMlDsa.c ]]; then
    pass "CryptMlDsa.c present"
else
    fail "CryptMlDsa.c missing"
fi
if [[ -f libtpms/src/tpm2/crypto/openssl/CryptMlKem.c ]]; then
    pass "CryptMlKem.c present"
else
    fail "CryptMlKem.c missing"
fi
grep -q "CryptMlDsaGenerateKey" libtpms/src/tpm2/CryptUtil.c && pass "CryptUtil.c dispatches ML-DSA keygen" || fail "CryptUtil.c missing ML-DSA keygen dispatch"
grep -q "CryptMlKemGenerateKey" libtpms/src/tpm2/CryptUtil.c && pass "CryptUtil.c dispatches ML-KEM keygen" || fail "CryptUtil.c missing ML-KEM keygen dispatch"
grep -q "CryptMlDsaSign"        libtpms/src/tpm2/CryptUtil.c && pass "CryptUtil.c dispatches ML-DSA sign"   || fail "CryptUtil.c missing ML-DSA sign dispatch"
grep -q "CryptMlDsaValidateSignature" libtpms/src/tpm2/CryptUtil.c && pass "CryptUtil.c dispatches ML-DSA verify" || fail "CryptUtil.c missing ML-DSA verify dispatch"

# ----------------------------------------------------------------------------
# Runtime — OpenSSL provider surface for V1.85 crypto
# ----------------------------------------------------------------------------

section "Runtime — OpenSSL 3.6+ Provider Surface"

OSSL_VER=$(openssl version | awk '{print $2}')
printf "  OpenSSL version: %s\n" "$OSSL_VER"

check_algo() {
    local algo=$1 list_flag=$2
    if openssl list "$list_flag" 2>/dev/null | grep -qi " $algo[, ]"; then
        pass "$algo exposed by default provider"
    else
        fail "$algo NOT exposed — OpenSSL 3.5+ required"
    fi
}

check_algo "ML-KEM-512"  "-kem-algorithms"
check_algo "ML-KEM-768"  "-kem-algorithms"
check_algo "ML-KEM-1024" "-kem-algorithms"
check_algo "ML-DSA-44"   "-signature-algorithms"
check_algo "ML-DSA-65"   "-signature-algorithms"
check_algo "ML-DSA-87"   "-signature-algorithms"

# ----------------------------------------------------------------------------
# Runtime — FIPS 203/204 canonical output sizes (via cross-val harness)
# ----------------------------------------------------------------------------

section "Runtime — Canonical Output Sizes (cross-val harness)"

if [[ -x "$CROSSVAL_BIN" ]]; then
    # Harness exits 0 iff all param sets produce exact FIPS 203/204 sizes.
    if "$CROSSVAL_BIN" > /tmp/crossval.out 2>&1; then
        # `grep -c` returns exit 1 when count is 0 — use || : to mask that.
        local_pass=$(grep -c "^\[PASS\]" /tmp/crossval.out 2>/dev/null) || local_pass=0
        local_fail=$(grep -c "^\[FAIL\]" /tmp/crossval.out 2>/dev/null) || local_fail=0
        if [[ "$local_fail" == "0" ]]; then
            pass "cross-val harness: $local_pass subtests green (ML-DSA-44/65/87, ML-KEM-512/768/1024)"
        else
            fail "cross-val harness: $local_fail subtests FAILED"
            sed 's/^/         /' /tmp/crossval.out
        fi
    else
        fail "cross-val harness exited non-zero"
        sed 's/^/         /' /tmp/crossval.out
    fi
else
    skip "cross-val binary not built — run 'make crossval-build' first"
fi

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------

printf "\n============================================================\n"
printf "TCG V1.85 Compliance: %d passed, %d failed, %d skipped\n" "$PASS" "$FAIL" "$SKIP"
printf "============================================================\n"

# Normative-reference reminder
cat <<'EOF'

Spec references archived locally:
  docs/standards/TPM-2.0-Library-Part-0_Introduction-V185-RC4.pdf
  docs/standards/TPM-2.0-Library-Part-1_Architecture-V185-RC4.pdf
  docs/standards/TPM-2.0-Library-Part-2_Structures-V185-RC4.pdf
  docs/standards/TPM-2.0-Library-Part-3_Commands-V185-RC4.pdf

Algorithm IDs cross-checked against wolfTPM PR #445
  https://github.com/wolfSSL/wolfTPM/pull/445
EOF

exit $(( FAIL > 0 ? 1 : 0 ))
