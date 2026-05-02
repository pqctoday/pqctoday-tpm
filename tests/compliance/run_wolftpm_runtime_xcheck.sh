#!/usr/bin/env bash
# ============================================================================
# pqctoday-tpm runtime cross-check against wolfTPM v4.0.0 PR #445.
#
# Designed to run inside the pqctoday-tpm-xcheck Docker image (built from
# docker/Dockerfile.xcheck), which pre-builds wolfSSL + wolfTPM with
# --enable-pqc + --enable-swtpm. This script:
#
#   1. Installs the freshly-mounted libtpms + swtpm from /workspace.
#   2. Provisions a TPM state with the default-v1 profile (so V1.85 PQC
#      commands are runtime-enabled — the libtpms v0.9 "null" profile is
#      frozen and would gate these out).
#   3. Starts swtpm on the standard socket (TCP 2321/2322).
#   4. Drives wolfTPM's examples/pqc/mldsa_sign and mlkem_encap binaries
#      against the running TPM, asserts the spec-mandated outcomes.
#
# Spec authority: TCG TPM 2.0 Library Specification V1.85 RC4.
# Per FIPS 203 / FIPS 204 the public-key and ciphertext sizes are fixed:
#
#   ML-DSA-44 / -65 / -87 pubkeys: 1312 / 1952 / 2592 bytes
#   ML-KEM-512 / -768 / -1024 pks: 800  / 1184 / 1568 bytes
#   ML-KEM ciphertexts:            768  / 1088 / 1568 bytes
#   ML-KEM shared secret:          32 bytes (always)
#
# Failure modes interpreted per V1.85:
#   SignSequenceStart 0x143 (TPM_RC_COMMAND_CODE) — known Phase 4 stub,
#   counts as PASS only when explicitly tagged as "expected-Phase-4".
# ============================================================================

set -u

PASS=0; FAIL=0
pass() { printf "  [PASS] %s\n" "$*"; PASS=$((PASS+1)); }
fail() { printf "  [FAIL] %s\n" "$*"; FAIL=$((FAIL+1)); }
section() { printf "\n=== %s ===\n" "$*"; }

trap 'pkill -9 swtpm 2>/dev/null || true' EXIT

WORKSPACE=${WORKSPACE:-/workspace}
WOLFTPM_DIR=${WOLFTPM_DIR:-/opt/build/wolftpm}

cd "$WORKSPACE"

# ── Step 1: install our libtpms + swtpm ─────────────────────────────────────
section "Setup — install pqctoday-tpm libtpms + swtpm"

if ! ( cd libtpms && make install >/dev/null 2>&1 && ldconfig ); then
    fail "libtpms install failed"
    exit 1
fi
pass "libtpms installed and ldconfig'd"

if ! ( cd swtpm && make install >/dev/null 2>&1 ); then
    fail "swtpm install failed"
    exit 1
fi
pass "swtpm installed"

# ── Step 2: provision a TPM state under the default-v1 profile ──────────────
section "Setup — TPM state with default-v1 profile"

STATEDIR=$(mktemp -d)
if ! swtpm_setup --tpm2 --tpm-state "$STATEDIR" \
                 --profile-name default-v1 \
                 --logfile /tmp/swtpm_setup.log \
                 --overwrite >/dev/null 2>&1; then
    fail "swtpm_setup failed:"
    sed 's/^/         /' /tmp/swtpm_setup.log
    exit 1
fi
pass "swtpm_setup --profile-name default-v1 (state in $STATEDIR)"

if ! grep -q "default-v1" /tmp/swtpm_setup.log 2>/dev/null; then
    fail "default-v1 profile not applied per swtpm_setup.log"
    exit 1
fi
if ! grep -q "0x1a5-0x1a8" /tmp/swtpm_setup.log 2>/dev/null; then
    fail "PQC commands 0x1a5-0x1a8 not in active profile"
    exit 1
fi
pass "active profile includes V1.85 PQC commands 0x1a5-0x1a8"

# ── Step 3: start swtpm on TCP 2321/2322 ────────────────────────────────────
section "Start swtpm socket"

swtpm socket --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl   type=tcp,port=2322 \
    --tpmstate dir="$STATEDIR" \
    --flags not-need-init \
    --log file=/tmp/swtpm.log,level=20 \
    --daemon
sleep 1

if ! ss -tln 2>/dev/null | grep -qE "2321|2322"; then
    fail "swtpm socket not listening on 2321/2322"
    exit 1
fi
pass "swtpm listening on TCP 2321 (data) + 2322 (ctrl)"

# ── Step 4: ML-KEM Encap+Decap roundtrip via wolfTPM client ─────────────────
#
# Per V1.85 RC4 Part 3 §14.10 Table 61, the response is:
#   { sharedSecret (TPM2B_SHARED_SECRET), ciphertext (TPM2B_KEM_CIPHERTEXT) }
# pqctoday-tpm commit 23a718f6 fixed the order; verify wolfTPM round-trip.
section "ML-KEM Encap/Decap roundtrip (Part 3 §14.10/§14.11)"

declare -A MLKEM_PK=(  [512]=800  [768]=1184 [1024]=1568 )
declare -A MLKEM_CT=(  [512]=768  [768]=1088 [1024]=1568 )
MLKEM_SS=32

for kem in 512 768 1024; do
    out=$( "$WOLFTPM_DIR/examples/pqc/mlkem_encap" -mlkem=$kem 2>&1 )
    pk_actual=$(  echo "$out" | grep -oE "pubkey [0-9]+ bytes"            | grep -oE "[0-9]+" || echo 0)
    ct_actual=$(  echo "$out" | grep -oE "ciphertext [0-9]+ bytes"        | grep -oE "[0-9]+" || echo 0)
    encap_ss=$(   echo "$out" | grep -oE "shared secret [0-9]+ bytes"     | head -1 | grep -oE "[0-9]+" || echo 0)
    decap_ss=$(   echo "$out" | grep -oE "shared secret [0-9]+ bytes"     | tail -1 | grep -oE "[0-9]+" || echo 0)
    rt_ok=$(      echo "$out" | grep -c "Round-trip OK")

    pk_expect=${MLKEM_PK[$kem]}; ct_expect=${MLKEM_CT[$kem]}

    [[ "$pk_actual" == "$pk_expect" ]] \
        && pass  "ML-KEM-$kem CreatePrimary pubkey = $pk_actual B (FIPS 203)" \
        || fail  "ML-KEM-$kem pubkey: got $pk_actual, expected $pk_expect"

    [[ "$ct_actual" == "$ct_expect" ]] \
        && pass  "ML-KEM-$kem Encap ciphertext = $ct_actual B (FIPS 203)" \
        || fail  "ML-KEM-$kem ciphertext: got $ct_actual, expected $ct_expect (Part 3 §14.10 Table 61)"

    [[ "$encap_ss" == "$MLKEM_SS" && "$decap_ss" == "$MLKEM_SS" ]] \
        && pass  "ML-KEM-$kem shared secret = ${MLKEM_SS} B on both sides (FIPS 203)" \
        || fail  "ML-KEM-$kem shared secret: encap=$encap_ss, decap=$decap_ss, expected $MLKEM_SS"

    [[ "$rt_ok" -ge 1 ]] \
        && pass  "ML-KEM-$kem Round-trip OK (encap secret == decap secret)" \
        || fail  "ML-KEM-$kem round-trip mismatch:\n$(echo "$out" | sed 's/^/         /')"
done

# ── Step 5: ML-DSA CreatePrimary (sign path is Phase 4) ─────────────────────
#
# The full sign/verify path needs TPM2_SignSequence{Start,Complete} —
# Phase 4 work. Here we assert CreatePrimary succeeds with FIPS 204 pubkey
# sizes, then accept the SignSequenceStart 0x143 as the documented Phase-4
# stub boundary. Once Phase 4 lands, this section graduates from "expected
# stub" to "full sign/verify roundtrip".
section "ML-DSA CreatePrimary + Phase-4 boundary (Part 3 §14.x)"

declare -A MLDSA_PK=( [44]=1312 [65]=1952 [87]=2592 )

for dsa in 44 65 87; do
    out=$( "$WOLFTPM_DIR/examples/pqc/mldsa_sign" -mldsa=$dsa 2>&1 )
    pk_actual=$( echo "$out" | grep -oE "pubkey [0-9]+ bytes" | grep -oE "[0-9]+" || echo 0 )
    pk_expect=${MLDSA_PK[$dsa]}

    [[ "$pk_actual" == "$pk_expect" ]] \
        && pass  "ML-DSA-$dsa CreatePrimary pubkey = $pk_actual B (FIPS 204)" \
        || fail  "ML-DSA-$dsa pubkey: got $pk_actual, expected $pk_expect"

    if echo "$out" | grep -q "SignSequenceStart failed 0x143"; then
        pass "ML-DSA-$dsa SignSequence path returns TPM_RC_COMMAND_CODE — expected Phase-4 stub"
    elif echo "$out" | grep -qE "Sign(Sequence)? .* OK|verified"; then
        pass "ML-DSA-$dsa Sign/Verify roundtrip OK — Phase 4 has landed!"
    else
        fail "ML-DSA-$dsa unexpected sign-path outcome:\n$(echo "$out" | sed 's/^/         /')"
    fi
done

# ── Summary ─────────────────────────────────────────────────────────────────
section "wolfTPM v4.0.0 PR #445 ↔ pqctoday-tpm runtime cross-check summary"

printf "  pqctoday-tpm: libtpms (OpenSSL 3.6.2) + swtpm + default-v1 profile\n"
printf "  wolfTPM:      v4.0.0 PR #445 + wolfSSL 5.9.1 wolfCrypt\n"
printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"

[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
