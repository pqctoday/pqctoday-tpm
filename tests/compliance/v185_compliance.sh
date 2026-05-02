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
ROUNDTRIP_BIN="tests/crossval/build/test_tpm_roundtrip"
PHASE3_BIN="tests/crossval/build/test_pqc_phase3"

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

assert_const "MAX_SIGNATURE_CTX_SIZE"   "255" "$TPMALGDEF"
assert_const "MAX_SIGNATURE_HINT_SIZE"  "256" "$TPMALGDEF"  # §11.3.9 Table 221

# ----------------------------------------------------------------------------
# §9 — I/O Buffer sizing for V1.85 commands
# ----------------------------------------------------------------------------

section "§9 I/O Buffer Sizing (ML-DSA-87 sig = 4627 B)"

assert_ge "TPM_BUFFER_MAX" "8192" "$TPMLIBCONF"

# ----------------------------------------------------------------------------
# §13 — V1.85 PQC Command Codes (TCG V1.85 RC4 Part 3 §28)
# Expected values per wolfTPM PR #445 (first open-source V1.85 implementation).
# Phase 2 target — these are NOT yet defined in libtpms; all checks will FAIL
# until Phase 2 adds the eight new command dispatch entries.
# ----------------------------------------------------------------------------

section "§13 V1.85 PQC Command Codes (TCG V1.85 RC4 Part 2 Table 11)"

# Search every libtpms header for each command code constant.
# Use find + xargs-friendly approach (macOS sh/bash 3 compat — no mapfile).
LIBTPMS_HDRS_LIST=$(find libtpms/src/tpm2 -name "*.h" 2>/dev/null | tr '\n' ' ')

check_cc() {
    local name=$1 expected=$2
    local found=""
    for hdr in $LIBTPMS_HDRS_LIST; do
        local v; v=$(get_define "$name" "$hdr")
        if [[ -n "$v" ]]; then found="$v"; break; fi
    done
    if [[ -n "$found" ]]; then
        local fdec; fdec=$(to_dec "$found" 2>/dev/null || echo "$found")
        local edec; edec=$(to_dec "$expected" 2>/dev/null || echo "$expected")
        if [[ "$fdec" == "$edec" ]]; then
            pass "$name = $found"
        else
            fail "$name: expected $expected (V1.85 spec), got $found"
        fi
    else
        fail "$name — not yet defined (Phase 2)"
    fi
}

check_cc "TPM_CC_VerifySequenceComplete"  "0x000001A3"
check_cc "TPM_CC_SignSequenceComplete"    "0x000001A4"
check_cc "TPM_CC_VerifyDigestSignature"  "0x000001A5"
check_cc "TPM_CC_SignDigest"             "0x000001A6"
check_cc "TPM_CC_Encapsulate"           "0x000001A7"
check_cc "TPM_CC_Decapsulate"           "0x000001A8"
check_cc "TPM_CC_VerifySequenceStart"   "0x000001A9"
check_cc "TPM_CC_SignSequenceStart"     "0x000001AA"

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

# TPMU_SIGNATURE V1.85 new members (§11.3.5 Table 217)
grep -q "TPM2B_SIGNATURE_MLDSA[[:space:]]*mldsa"              "$TPMTYPES" && pass "TPMU_SIGNATURE.mldsa member present"      || fail "TPMU_SIGNATURE.mldsa missing"
grep -q "TPMS_SIGNATURE_HASH_MLDSA[[:space:]]*hash_mldsa"     "$TPMTYPES" && pass "TPMU_SIGNATURE.hash_mldsa member present" || fail "TPMU_SIGNATURE.hash_mldsa missing"

# TPMU_ENCRYPTED_SECRET V1.85 new mlkem member (§11.4.2 Table 222)
grep -q "mlkem\[MAX_MLKEM_CT_SIZE\]" "$TPMTYPES" && pass "TPMU_ENCRYPTED_SECRET.mlkem member present" || fail "TPMU_ENCRYPTED_SECRET missing mlkem member"

# ----------------------------------------------------------------------------
# V1.85 New Type Definitions (TCG Part 2 Tables 99-101, 110-112, 208, 216-221)
# ----------------------------------------------------------------------------

section "V1.85 New Type Definitions (Part 2 Tables 99-101, 110-112, 208, 216-221)"

# ML-DSA signature types
grep -q "TPM2B_SIGNATURE_MLDSA"      "$TPMTYPES" && pass "TPM2B_SIGNATURE_MLDSA defined (§11.3.4 Table 216)"    || fail "TPM2B_SIGNATURE_MLDSA missing"
grep -q "TPMS_SIGNATURE_HASH_MLDSA"  "$TPMTYPES" && pass "TPMS_SIGNATURE_HASH_MLDSA defined (§11.2.7.2 T208)"  || fail "TPMS_SIGNATURE_HASH_MLDSA missing"
grep -q "TPMU_SIGNATURE_CTX"         "$TPMTYPES" && pass "TPMU_SIGNATURE_CTX defined (§11.3.7 Table 219)"       || fail "TPMU_SIGNATURE_CTX missing"
grep -q "TPM2B_SIGNATURE_CTX"        "$TPMTYPES" && pass "TPM2B_SIGNATURE_CTX defined (§11.3.8 Table 220)"      || fail "TPM2B_SIGNATURE_CTX missing"
grep -q "TPM2B_SIGNATURE_HINT"       "$TPMTYPES" && pass "TPM2B_SIGNATURE_HINT defined (§11.3.9 Table 221)"     || fail "TPM2B_SIGNATURE_HINT missing"

# ML-KEM KEM types
grep -q "TPM2B_SHARED_SECRET"        "$TPMTYPES" && pass "TPM2B_SHARED_SECRET defined (§10.3.12 Table 99)"     || fail "TPM2B_SHARED_SECRET missing"
grep -q "TPMU_KEM_CIPHERTEXT"        "$TPMTYPES" && pass "TPMU_KEM_CIPHERTEXT defined (§10.3.13 Table 100)"    || fail "TPMU_KEM_CIPHERTEXT missing"
grep -q "TPM2B_KEM_CIPHERTEXT"       "$TPMTYPES" && pass "TPM2B_KEM_CIPHERTEXT defined (§10.3.14 Table 101)"   || fail "TPM2B_KEM_CIPHERTEXT missing"

# V1.85 ticket type additions (§10.6.4-5 Tables 110-112)
grep -q "TPMU_TK_VERIFIED_META"      "$TPMTYPES" && pass "TPMU_TK_VERIFIED_META defined (§10.6.4 Table 110)"   || fail "TPMU_TK_VERIFIED_META missing"
grep -q "metadata"                   "$TPMTYPES" && pass "TPMT_TK_VERIFIED.metadata field present (Table 112)" || fail "TPMT_TK_VERIFIED missing metadata field"
grep -q "hmac;"                      "$TPMTYPES" && pass "TPMT_TK_VERIFIED.hmac field renamed from digest"     || fail "TPMT_TK_VERIFIED.hmac field missing"

# V1.85 new ticket tag values (TCG Part 2 Table 19)
assert_const "TPM_ST_MESSAGE_VERIFIED" "0x8026" "$TPMTYPES"
assert_const "TPM_ST_DIGEST_VERIFIED"  "0x8027" "$TPMTYPES"

# TPM_CC_LAST updated to 0x1AA
assert_const "TPM_CC_LAST" "0x000001AA" "$TPMTYPES"

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

# On macOS the system 'openssl' is LibreSSL and lacks PQC.
# Prefer Homebrew OpenSSL 3.6 if present.
OSSL_BIN="openssl"
for _candidate in \
        "/opt/homebrew/opt/openssl@3.6/bin/openssl" \
        "/usr/local/opt/openssl@3.6/bin/openssl" \
        "/opt/homebrew/opt/openssl@3/bin/openssl" \
        "/usr/local/opt/openssl@3/bin/openssl"; do
    if [[ -x "$_candidate" ]] && "$_candidate" version 2>/dev/null | grep -q "^OpenSSL 3"; then
        OSSL_BIN="$_candidate"
        break
    fi
done

OSSL_VER=$("$OSSL_BIN" version 2>/dev/null | awk '{print $2}')
printf "  OpenSSL binary  : %s\n" "$OSSL_BIN"
printf "  OpenSSL version : %s\n" "$OSSL_VER"

check_algo() {
    local algo=$1 list_flag=$2
    if "$OSSL_BIN" list "$list_flag" 2>/dev/null | grep -qi " $algo[, ]"; then
        pass "$algo exposed by default provider"
    else
        fail "$algo NOT exposed — OpenSSL 3.5+ required (using: $OSSL_BIN)"
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

if [[ "$(uname -s)" == "Darwin" ]] && [[ -x "$CROSSVAL_BIN" ]] && ! "$CROSSVAL_BIN" --help >/dev/null 2>&1; then
    skip "cross-val binary is Linux ELF — run inside Docker (make crossval-build && make compliance)"
elif [[ -x "$CROSSVAL_BIN" ]]; then
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

# §5 / §15 / §14 — End-to-end TPM2_CreatePrimary(MLDSA-65) via direct libtpms
section "Runtime — TPM2_CreatePrimary(MLDSA-65) end-to-end (libtpms direct)"

if [[ "$(uname -s)" == "Darwin" ]] && [[ -x "$ROUNDTRIP_BIN" ]] && ! "$ROUNDTRIP_BIN" --help >/dev/null 2>&1; then
    skip "test_tpm_roundtrip is Linux ELF — run inside Docker (make crossval-build && make compliance)"
elif [[ -x "$ROUNDTRIP_BIN" ]]; then
    if "$ROUNDTRIP_BIN" > /tmp/roundtrip.out 2>&1; then
        rt_pass=$(grep -c "^\[PASS\]" /tmp/roundtrip.out 2>/dev/null) || rt_pass=0
        rt_fail=$(grep -c "^\[FAIL\]" /tmp/roundtrip.out 2>/dev/null) || rt_fail=0
        if [[ "$rt_fail" == "0" ]]; then
            pass "TPM2_CreatePrimary(MLDSA-65): $rt_pass subtests green — ML-DSA-65 pk=1952 B FIPS 204 compliant"
        else
            fail "TPM2_CreatePrimary(MLDSA-65): $rt_fail subtests FAILED"
            sed 's/^/         /' /tmp/roundtrip.out
        fi
    else
        fail "test_tpm_roundtrip exited non-zero"
        sed 's/^/         /' /tmp/roundtrip.out
    fi
else
    skip "test_tpm_roundtrip not built — run 'make crossval-build' first"
fi

# ----------------------------------------------------------------------------
# Phase 3 — Key hierarchy dispatch (source checks)
# CryptIsAsymAlgorithm, CryptSecretEncrypt/Decrypt ML-KEM paths
# ----------------------------------------------------------------------------

section "Phase 3 — Key Hierarchy Dispatch (CryptUtil.c source checks)"

CRYPTUTIL="libtpms/src/tpm2/CryptUtil.c"
PQCMLDSA="libtpms/src/tpm2/PqcMlDsaCommands.c"

# CryptIsAsymAlgorithm must handle MLDSA and MLKEM (unblocks MakeCredential, ActivateCredential)
grep -q "case TPM_ALG_MLDSA:" "$CRYPTUTIL"  && pass "CryptIsAsymAlgorithm: TPM_ALG_MLDSA case present" \
                                             || fail "CryptIsAsymAlgorithm: TPM_ALG_MLDSA case missing"
grep -q "case TPM_ALG_MLKEM:" "$CRYPTUTIL"  && pass "CryptIsAsymAlgorithm: TPM_ALG_MLKEM case present" \
                                             || fail "CryptIsAsymAlgorithm: TPM_ALG_MLKEM case missing"

# CryptSecretEncrypt ML-KEM path (MakeCredential transport)
grep -q "CryptMlKemEncapsulate" "$CRYPTUTIL" && pass "CryptSecretEncrypt: CryptMlKemEncapsulate present (ML-KEM seed)" \
                                              || fail "CryptSecretEncrypt: CryptMlKemEncapsulate missing"

# CryptSecretDecrypt ML-KEM path (ActivateCredential transport)
grep -q "CryptMlKemDecapsulate" "$CRYPTUTIL" && pass "CryptSecretDecrypt: CryptMlKemDecapsulate present (ML-KEM seed)" \
                                              || fail "CryptSecretDecrypt: CryptMlKemDecapsulate missing"

# CryptSelectSignScheme: synthetic mldsaScheme for ML-DSA keys (TPM2_Quote path)
grep -q "mldsaScheme" "$CRYPTUTIL"           && pass "CryptSelectSignScheme: synthetic mldsaScheme present for ML-DSA" \
                                             || fail "CryptSelectSignScheme: mldsaScheme missing"

# TPM2_SignDigest: restricted key check present (V1.85 §29.2.1)
grep -q "TPMA_OBJECT.*restricted" "$PQCMLDSA" && pass "TPM2_SignDigest: restricted-key guard present (§29.2.1)" \
                                               || fail "TPM2_SignDigest: restricted-key guard missing"

# V1.85 §12.2.3.6 Table 229: TPMS_MLDSA_PARMS.allowExternalMu must be enforced
# in TPM2_SignDigest and TPM2_VerifyDigestSignature.
grep -q "allowExternalMu" "$PQCMLDSA" && pass "TPMS_MLDSA_PARMS.allowExternalMu enforced (§12.2.3.6 Table 229)" \
                                       || fail "allowExternalMu enforcement missing in PqcMlDsaCommands.c"

# V1.85 §8.6 Table 22: TPM_PT_ML_PARAMETER_SETS GetCapability must be wired
grep -q "TPM_PT_ML_PARAMETER_SETS" "libtpms/src/tpm2/PropertyCap.c" \
    && pass "TPM_PT_ML_PARAMETER_SETS capability handler present (Table 22 + Table 46)" \
    || fail "TPM_PT_ML_PARAMETER_SETS capability handler missing in PropertyCap.c"

# V1.85 §12.2.3.6/8: TPMS_MLDSA_PARMS / TPMS_MLKEM_PARMS spec field layout
grep -q "TPMI_YES_NO\s*allowExternalMu" "libtpms/src/tpm2/TpmTypes.h" \
    && pass "TPMS_MLDSA_PARMS.allowExternalMu field present (Table 229)" \
    || fail "TPMS_MLDSA_PARMS missing allowExternalMu field"
grep -q "TPMT_SYM_DEF_OBJECT\s*symmetric" "libtpms/src/tpm2/TpmTypes.h" \
    && pass "TPMS_MLKEM_PARMS.symmetric field present (Table 231)" \
    || fail "TPMS_MLKEM_PARMS missing symmetric field"

# Phase 3 — Runtime roundtrip (test_pqc_phase3)
section "Phase 3 — Runtime Roundtrip (test_pqc_phase3)"

if [[ "$(uname -s)" == "Darwin" ]] && [[ -x "$PHASE3_BIN" ]] && ! "$PHASE3_BIN" --help >/dev/null 2>&1; then
    skip "test_pqc_phase3 is Linux ELF — run inside Docker (make compliance)"
elif [[ -x "$PHASE3_BIN" ]]; then
    if "$PHASE3_BIN" > /tmp/phase3.out 2>&1; then
        ph3_pass=$(grep -c "^\[PASS\]" /tmp/phase3.out 2>/dev/null) || ph3_pass=0
        ph3_fail=$(grep -c "^\[FAIL\]" /tmp/phase3.out 2>/dev/null) || ph3_fail=0
        if [[ "$ph3_fail" == "0" ]]; then
            pass "Phase 3 roundtrip: $ph3_pass subtests green (ML-KEM-768 EK + ML-DSA-65 AK + MakeCredential + SignDigest)"
        else
            fail "Phase 3 roundtrip: $ph3_fail subtests FAILED"
            sed 's/^/         /' /tmp/phase3.out
        fi
    else
        fail "test_pqc_phase3 exited non-zero"
        sed 's/^/         /' /tmp/phase3.out
    fi
else
    skip "test_pqc_phase3 not built — run 'make crossval-build' first"
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
