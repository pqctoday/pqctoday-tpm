cmake_minimum_required(VERSION 3.16)
project(pqctoday_tpm_crossval C)

# Require OpenSSL 3.5+ for ML-DSA / ML-KEM in default provider.
set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL 3.5 REQUIRED)

add_executable(test_pqc_crossval
    src/test_pqc_crossval.c
    src/p11_helper.c
)

target_include_directories(test_pqc_crossval PRIVATE
    include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(test_pqc_crossval PRIVATE
    OpenSSL::Crypto
    ${CMAKE_DL_LIBS}   # for future p11_helper.c dlopen
)

target_compile_options(test_pqc_crossval PRIVATE -Wall -Wextra -Wno-unused-function)

# Direct-libtpms TPM command-layer roundtrip test — requires libtpms installed
# via `make install` inside the container (header + .so in /usr/local).
#
# NOTE: EXCLUDE_FROM_ALL because in-process libtpms init with in-memory NV
# callbacks still fails at NvPowerOn (NV header magic mismatch from zeroed
# state blob). Full bootstrapping requires invoking TPMLIB_SetState with a
# valid PERMANENT state blob before TPMLIB_MainInit, or routing NV through
# a file backend that libtpms pre-initializes. Deferred to next session.
# Build explicitly with `cmake --build build --target test_tpm_roundtrip`.
add_executable(test_tpm_roundtrip EXCLUDE_FROM_ALL
    src/test_tpm_roundtrip.c
)
target_compile_options(test_tpm_roundtrip PRIVATE -Wall -Wextra)
target_link_libraries(test_tpm_roundtrip PRIVATE
    tpms  # libtpms.so exports TPMLIB_MainInit / TPMLIB_Process / TPMLIB_Terminate
)

# install into build dir; `make crossval` in the top-level Makefile runs the binary
