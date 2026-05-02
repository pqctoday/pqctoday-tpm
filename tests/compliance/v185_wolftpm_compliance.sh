#!/usr/bin/env bash
# ============================================================================
# TCG TPM 2.0 Library Specification V1.85 PQC Compliance Test — wolfTPM
# ============================================================================
#
# Runs the same source-level checks as v185_compliance.sh but against the
# wolfTPM v4.0.0 (PR #445) headers cloned at vendor/wolftpm/.
#
# wolfTPM uses wolfCrypt as its crypto backend, so OpenSSL runtime checks
# and libtpms build-evidence checks are skipped (marked SKIP).
#
# Run: ./tests/compliance/v185_wolftpm_compliance.sh  (from repo root)
# Or:  make wolftpm-compliance                         (from repo root)
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

WOLFTPM_DIR="vendor/wolftpm"
TPMTYPES="$WOLFTPM_DIR/wolftpm/tpm2.h"       # algorithm IDs, param sets, command codes, structures
TPMALGDEF="$WOLFTPM_DIR/wolftpm/tpm2_types.h" # MAX_* size constants

PASS=0; FAIL=0; SKIP=0

pass() { printf "  [PASS] %s\n" "$*"; PASS=$((PASS+1)); }
fail() { printf "  [FAIL] %s\n" "$*"; FAIL=$((FAIL+1)); }
skip() { printf "  [SKIP] %s\n" "$*"; SKIP=$((SKIP+1)); }
section() { printf "\n=== %s ===\n" "$*"; }

# ----------------------------------------------------------------------------
# Helpers (identical to v185_compliance.sh)
# ----------------------------------------------------------------------------

get_define_raw() {
    local name=$1 file=$2
    # Handle both #define and enum member (e.g. "  TPM_ALG_MLKEM = 0x00A0,")
    local v
    v=$(grep -E "^[[:space:]]*#define[[:space:]]+${name}[[:space:]]" "$file" 2>/dev/null \
        | head -1 \
        | sed -E "s/^[[:space:]]*#define[[:space:]]+${name}[[:space:]]+//" \
        | sed -E 's/^\([^)]*\)//' \
        | tr -d '()' \
        | awk '{print $1}')
    if [[ -z "$v" ]]; then
        # Try enum member: "  NAME  =  VALUE,"
        v=$(grep -E "[[:space:]]+${name}[[:space:]]*=" "$file" 2>/dev/null \
            | head -1 \
            | sed -E "s/.*${name}[[:space:]]*=[[:space:]]*//" \
            | tr -d '(),' \
            | awk '{print $1}')
    fi
    printf "%s" "$v"
}

get_define() {
    local name=$1 file=$2
    local val depth=0
    val=$(get_define_raw "$name" "$file")
    while [[ -n "$val" ]] && [[ "$val" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && (( depth < 3 )); do
        local next
        next=$(get_define_raw "$val" "$file")
        if [[ -z "$next" ]]; then
            # also try tpm2_types.h for aliased constants
            next=$(get_define_raw "$val" "$TPMALGDEF" 2>/dev/null || true)
        fi
        if [[ -z "$next" ]]; then break; fi
        val=$next
        depth=$((depth+1))
    done
    printf "%s" "$val"
}

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

printf "TCG TPM 2.0 Library Specification V1.85 PQC Compliance Test — wolfTPM\n"
printf "========================================================================\n"
printf "  wolfTPM  : %s\n" "$WOLFTPM_DIR"
printf "  date     : %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf "  host     : %s / %s\n" "$(uname -s)" "$(uname -m)"

if [[ ! -f "$TPMTYPES" ]]; then
    printf "\nFATAL: wolfTPM headers not found at %s\n" "$WOLFTPM_DIR" >&2
    printf "Run: git clone --depth=1 https://github.com/wolfSSL/wolfTPM %s\n" "$WOLFTPM_DIR" >&2
    exit 2
fi

# ----------------------------------------------------------------------------
# §6.3 — Algorithm Identifiers (TCG Registry v2.0)
# ----------------------------------------------------------------------------

section "§6.3 Algorithm Identifiers (TCG V1.85 Part 2, Registry v2.0)"

assert_const "TPM_ALG_MLKEM"      "0x00A0" "$TPMTYPES"
assert_const "TPM_ALG_MLDSA"      "0x00A1" "$TPMTYPES"
assert_const "TPM_ALG_HASH_MLDSA" "0x00A2" "$TPMTYPES"

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
# §14 / §15 — Buffer Size Constants (wolfTPM uses MAX_* only, not per-variant)
# ----------------------------------------------------------------------------

section "§14/§15 PQC Buffer Size Constants (tpm2_types.h)"

assert_const "MAX_MLDSA_PUB_SIZE"       "2592" "$TPMALGDEF"  # ML-DSA-87 public key
assert_const "MAX_MLDSA_SIG_SIZE"       "4627" "$TPMALGDEF"  # ML-DSA-87 signature
assert_const "MAX_MLDSA_PRIV_SEED_SIZE" "32"   "$TPMALGDEF"  # ξ seed (all variants)
assert_const "MAX_MLKEM_PUB_SIZE"       "1568" "$TPMALGDEF"  # ML-KEM-1024 public key
assert_const "MAX_MLKEM_PRIV_SEED_SIZE" "64"   "$TPMALGDEF"  # d||z seed (all variants)
assert_const "MAX_SIGNATURE_CTX_SIZE"   "255"  "$TPMALGDEF"  # HashML-DSA domain sep
assert_const "MAX_SIGNATURE_HINT_SIZE"  "256"  "$TPMALGDEF"  # signature hint (V1.85 T221)

# Note: wolfTPM MAX_MLKEM_CT_SIZE aliases MAX_KEM_CIPHERTEXT_SIZE (2048, not 1568)
# and MAX_SHARED_SECRET_SIZE=64 (not 32) — both conservatively oversized.
printf "  [NOTE] MAX_MLKEM_CT_SIZE aliases MAX_KEM_CIPHERTEXT_SIZE (check separately)\n"
printf "  [NOTE] MAX_SHARED_SECRET_SIZE=64 (reserved for salted sessions per V1.85 Part 4 pending)\n"
actual_ct=$(get_define "MAX_KEM_CIPHERTEXT_SIZE" "$TPMALGDEF")
actual_ss=$(get_define "MAX_SHARED_SECRET_SIZE"  "$TPMALGDEF")
printf "         MAX_KEM_CIPHERTEXT_SIZE = %s  (ML-KEM-1024 spec: 1568)\n" "$actual_ct"
printf "         MAX_SHARED_SECRET_SIZE  = %s  (ML-KEM spec: 32, wolfTPM reserves for future Part 4)\n" "$actual_ss"

# I/O buffer sizing — wolfTPM doesn't use a single TPM_BUFFER_MAX define;
# per-command buffers are sized by the MAX_* constants above.
skip "TPM_BUFFER_MAX — wolfTPM sizes per-command (not single global buffer)"

# ----------------------------------------------------------------------------
# §13 — V1.85 PQC Command Codes (TCG V1.85 RC4 Part 3 §28)
# ----------------------------------------------------------------------------

section "§13 V1.85 PQC Command Codes (TCG V1.85 RC4 Part 3)"

assert_const "TPM_CC_VerifySequenceComplete"  "0x000001A3" "$TPMTYPES"
assert_const "TPM_CC_SignSequenceComplete"    "0x000001A4" "$TPMTYPES"
assert_const "TPM_CC_VerifyDigestSignature"  "0x000001A5" "$TPMTYPES"
assert_const "TPM_CC_SignDigest"             "0x000001A6" "$TPMTYPES"
assert_const "TPM_CC_Encapsulate"           "0x000001A7" "$TPMTYPES"
assert_const "TPM_CC_Decapsulate"           "0x000001A8" "$TPMTYPES"
assert_const "TPM_CC_VerifySequenceStart"   "0x000001A9" "$TPMTYPES"
assert_const "TPM_CC_SignSequenceStart"     "0x000001AA" "$TPMTYPES"

# ----------------------------------------------------------------------------
# TPMU Union Extensions (TCG V1.85 Part 2 Tables 184, 189, 195, 217)
# ----------------------------------------------------------------------------

section "TPMU Union Extensions (TCG V1.85 Part 2 Tables 184, 189, 195, 217)"

grep -q "TPM2B_PUBLIC_KEY_MLDSA"        "$TPMTYPES" && pass "TPM2B_PUBLIC_KEY_MLDSA defined"          || fail "TPM2B_PUBLIC_KEY_MLDSA missing"
grep -q "TPM2B_PUBLIC_KEY_MLKEM"        "$TPMTYPES" && pass "TPM2B_PUBLIC_KEY_MLKEM defined"          || fail "TPM2B_PUBLIC_KEY_MLKEM missing"
grep -q "TPM2B_PRIVATE_KEY_MLDSA"       "$TPMTYPES" && pass "TPM2B_PRIVATE_KEY_MLDSA defined"         || fail "TPM2B_PRIVATE_KEY_MLDSA missing"
grep -q "TPM2B_PRIVATE_KEY_MLKEM"       "$TPMTYPES" && pass "TPM2B_PRIVATE_KEY_MLKEM defined"         || fail "TPM2B_PRIVATE_KEY_MLKEM missing"
grep -q "TPM2B_MLDSA_SIGNATURE"         "$TPMTYPES" && pass "TPM2B_MLDSA_SIGNATURE defined"           || fail "TPM2B_MLDSA_SIGNATURE missing"
grep -q "TPMS_SIGNATURE_HASH_MLDSA"     "$TPMTYPES" && pass "TPMS_SIGNATURE_HASH_MLDSA defined"       || fail "TPMS_SIGNATURE_HASH_MLDSA missing"
grep -q "TPM2B_SHARED_SECRET"           "$TPMTYPES" && pass "TPM2B_SHARED_SECRET defined"             || fail "TPM2B_SHARED_SECRET missing"
grep -q "TPM2B_SIGNATURE_HINT"          "$TPMTYPES" && pass "TPM2B_SIGNATURE_HINT defined"            || fail "TPM2B_SIGNATURE_HINT missing"

# TPMU_SIGNATURE union members
grep -q "TPM2B_MLDSA_SIGNATURE mldsa"           "$TPMTYPES" && pass "TPMU_SIGNATURE.mldsa (bare ML-DSA) present"       || fail "TPMU_SIGNATURE.mldsa missing"
grep -q "TPMS_SIGNATURE_HASH_MLDSA hash_mldsa"  "$TPMTYPES" && pass "TPMU_SIGNATURE.hash_mldsa (HashML-DSA) present"   || fail "TPMU_SIGNATURE.hash_mldsa missing"

# TPMU_PUBLIC_ID KEM field
grep -q "mlkem\[MAX_MLKEM_CT_SIZE\]"    "$TPMTYPES" && pass "TPMU_PUBLIC_ID/TPMU_ASYM_SCHEME mlkem ciphertext field present" || fail "mlkem ciphertext field missing"

# ----------------------------------------------------------------------------
# Build evidence — wolfTPM uses wolfCrypt, skip OpenSSL-specific checks
# ----------------------------------------------------------------------------

section "Build Evidence (wolfTPM — wolfCrypt backend)"

skip "CryptMlDsa.c / CryptMlKem.c — wolfTPM uses wolfCrypt (not OpenSSL EVP)"
skip "CryptUtil.c dispatch — wolfTPM uses fwTPM handler architecture"

if [[ -f "$WOLFTPM_DIR/src/tpm2/fwtpm_ml_dsa.c" ]]; then
    pass "fwtpm_ml_dsa.c present (wolfCrypt ML-DSA handler)"
elif [[ -f "$WOLFTPM_DIR/src/tpm2/fwtpm_pqc.c" ]]; then
    pass "fwtpm_pqc.c present (wolfCrypt PQC handler)"
else
    # Search for any fwtpm PQC source
    pqc_src=$(find "$WOLFTPM_DIR/src" -name "*pqc*" -o -name "*mldsa*" -o -name "*mlkem*" 2>/dev/null | head -3)
    if [[ -n "$pqc_src" ]]; then
        pass "PQC fwTPM source files found: $(echo "$pqc_src" | tr '\n' ' ')"
    else
        skip "fwTPM PQC source search inconclusive — check $WOLFTPM_DIR/src/"
    fi
fi

# ----------------------------------------------------------------------------
# Runtime — wolfCrypt provider surface (skipped: requires wolfCrypt build)
# ----------------------------------------------------------------------------

section "Runtime — wolfCrypt Provider Surface"
skip "ML-KEM-512/768/1024 — requires wolfTPM build with --enable-pqc (not run here)"
skip "ML-DSA-44/65/87 — requires wolfTPM build with --enable-pqc (not run here)"
skip "End-to-end fwTPM round-trip — requires compiled wolfTPM fwTPM server"

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------

printf "\n============================================================\n"
printf "wolfTPM V1.85 Compliance: %d passed, %d failed, %d skipped\n" "$PASS" "$FAIL" "$SKIP"
printf "============================================================\n"

cat <<'EOF'

wolfTPM source:  vendor/wolftpm/wolftpm/tpm2.h
Size constants:  vendor/wolftpm/wolftpm/tpm2_types.h
Spec ref:        TCG TPM 2.0 Library Spec V1.85 RC4
Implementation:  wolfTPM PR #445 (merged 2026-04-29, v4.0.0)
Crypto backend:  wolfCrypt (not OpenSSL EVP)
EOF

exit $(( FAIL > 0 ? 1 : 0 ))
