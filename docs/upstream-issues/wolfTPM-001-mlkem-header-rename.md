# wolfTPM — `configure.ac` includes wrong wolfSSL header (`mlkem.h` → `wc_mlkem.h`)

**Target:** [wolfSSL/wolfTPM](https://github.com/wolfSSL/wolfTPM)
**Severity:** build break with current wolfSSL master
**Affects:** wolfTPM v4.0.0 (PR #445 merge commit `fbbf6fe`); presumably HEAD too unless already fixed
**Status (pqctoday-tpm):** worked around in `docker/Dockerfile.xcheck` with a symlink

---

## Summary

`wolfTPM/configure.ac` AC_CHECK_DECL probes for `wc_MlKemKey_Init` by including `<wolfssl/wolfcrypt/mlkem.h>`, but wolfSSL HEAD installs the header under `wc_mlkem.h` (with the `wc_` prefix). The probe fails, and `--enable-pqc` configure aborts with:

```
checking whether wc_MlKemKey_Init is declared... no
configure: error: --enable-v185/--enable-pqc requires wolfSSL built with --enable-mlkem --enable-experimental
```

— even though wolfSSL was correctly built with `--enable-mlkem --enable-experimental`.

## Reproducer

```bash
# wolfSSL HEAD (commit 7b53303 at time of report)
git clone --depth=1 https://github.com/wolfSSL/wolfssl
cd wolfssl
./autogen.sh
./configure --prefix=/opt/wolfssl --enable-experimental \
            --enable-dilithium --enable-mlkem \
            --disable-shared --enable-static \
            CFLAGS="-fPIC -DWC_RSA_NO_PADDING"
make -j"$(nproc)" && make install
cd ..

# Confirm wolfSSL DOES expose wc_MlKemKey_Init in wc_mlkem.h
grep -c "wc_MlKemKey_Init" /opt/wolfssl/include/wolfssl/wolfcrypt/wc_mlkem.h
# → 6 (declarations present)

# Confirm wolfSSL does NOT ship mlkem.h (no wc_ prefix)
ls /opt/wolfssl/include/wolfssl/wolfcrypt/mlkem.h 2>&1
# → No such file or directory

# wolfTPM v4.0.0 (PR #445 merge fbbf6fe)
git clone --depth=200 https://github.com/wolfSSL/wolfTPM
cd wolfTPM
git checkout fbbf6fe   # PR #445 merge
./autogen.sh
./configure --prefix=/opt/wolftpm --with-wolfcrypt=/opt/wolfssl \
            --enable-pqc --enable-swtpm
# → checking whether wc_MlKemKey_Init is declared... no
# → configure: error: --enable-v185/--enable-pqc requires wolfSSL built with --enable-mlkem --enable-experimental
```

## Root cause

`configure.ac` lines 727–731 and 756–759:

```m4
AC_CHECK_DECL([wc_MlKemKey_Init],
    [WOLFTPM_HAVE_MLKEM_FN=yes],
    [WOLFTPM_HAVE_MLKEM_FN=no],
    [[#include <wolfssl/options.h>
      #include <wolfssl/wolfcrypt/mlkem.h>]])     ← wrong header name

# ...later...

AC_CHECK_DECL([wc_MlKemKey_Init], [],
    [AC_MSG_ERROR([--enable-v185/--enable-pqc requires wolfSSL built with --enable-mlkem --enable-experimental])],
    [[#include <wolfssl/options.h>
      #include <wolfssl/wolfcrypt/mlkem.h>]])     ← wrong header name
```

wolfSSL's actual header is `wolfssl/wolfcrypt/wc_mlkem.h` (note the `wc_` prefix matches `wc_dilithium.h` / `wc_pkcs7.h` / etc.). The dilithium probe right above uses the correctly-prefixed `<wolfssl/wolfcrypt/dilithium.h>` (which is dilithium-specific — `dilithium.h` itself, no `wc_` prefix), so the asymmetry is a typo, not a deliberate design choice.

## Suggested fix (one-line × 2)

```diff
--- a/configure.ac
+++ b/configure.ac
@@ -727,7 +727,7 @@ then
     AC_CHECK_DECL([wc_MlKemKey_Init],
         [WOLFTPM_HAVE_MLKEM_FN=yes],
         [WOLFTPM_HAVE_MLKEM_FN=no],
         [[#include <wolfssl/options.h>
-          #include <wolfssl/wolfcrypt/mlkem.h>]])
+          #include <wolfssl/wolfcrypt/wc_mlkem.h>]])
     if test "x$WOLFTPM_HAVE_DILITHIUM_FN" = "xyes" && \
@@ -756,7 +756,7 @@ then
     AC_CHECK_DECL([wc_MlKemKey_Init], [],
         [AC_MSG_ERROR([--enable-v185/--enable-pqc requires wolfSSL built with --enable-mlkem --enable-experimental])],
         [[#include <wolfssl/options.h>
-          #include <wolfssl/wolfcrypt/mlkem.h>]])
+          #include <wolfssl/wolfcrypt/wc_mlkem.h>]])
     AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_V185"
 fi
```

## Compatibility

If wolfSSL still ships `mlkem.h` (without prefix) on some branches, `AC_CHECK_HEADERS` could detect either:

```m4
AC_CHECK_HEADERS([wolfssl/wolfcrypt/wc_mlkem.h wolfssl/wolfcrypt/mlkem.h])
```

But the simpler one-line fix to `wc_mlkem.h` matches what wolfSSL master + the recent stable releases ship.

## Workaround in pqctoday-tpm

`docker/Dockerfile.xcheck` symlinks the missing header so the AC_CHECK_DECL probe finds it:

```dockerfile
RUN ln -sf wc_mlkem.h /opt/wolfssl/include/wolfssl/wolfcrypt/mlkem.h
```

This is an obvious smell; remove once the upstream PR lands.

## TPM 2.0 spec angle

This is a wolfSSL/wolfTPM build-system issue — no V1.85 spec implications. Reported here because pqctoday-tpm's `make wolftpm-xcheck` cross-implementation harness depends on a correctly-built wolfTPM PQC client, and the symlink workaround is fragile (e.g. if wolfSSL ever ships `mlkem.h` again as a different file, the symlink would shadow it).

## How to file

Open at https://github.com/wolfSSL/wolfTPM/issues/new with this content. Title suggestion:

> `configure.ac: --enable-pqc fails with current wolfSSL master because mlkem.h was renamed wc_mlkem.h`
