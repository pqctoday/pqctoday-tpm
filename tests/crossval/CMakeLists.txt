cmake_minimum_required(VERSION 3.16)
project(pqctoday_tpm_crossval C)

# Require OpenSSL 3.5+ for ML-DSA / ML-KEM in default provider.
set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL 3.5 REQUIRED)

# json-c for NIST ACVP JSON vector parsing.
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONC REQUIRED json-c)

add_executable(test_pqc_crossval
    src/test_pqc_crossval.c
    src/p11_helper.c
    src/kat_loader.c
)

target_include_directories(test_pqc_crossval PRIVATE
    include
    ${OPENSSL_INCLUDE_DIR}
    ${JSONC_INCLUDE_DIRS}
)

target_link_libraries(test_pqc_crossval PRIVATE
    OpenSSL::Crypto
    ${CMAKE_DL_LIBS}   # for p11_helper.c dlopen
    ${JSONC_LIBRARIES} # for kat_loader.c
)

target_compile_options(test_pqc_crossval PRIVATE -Wall -Wextra -Wno-unused-function)

# Direct-libtpms TPM command-layer roundtrip test.
# Requires libtpms installed via `make install` inside the container.
#
# Uses file-backed NV in a mkdtemp() directory: no custom callbacks.
# libtpms manufacture writes NVChip; second _plat__NVEnable_NVChipFile()
# call short-circuits (s_NvFile != NULL) so manufactured state is preserved.
add_executable(test_tpm_roundtrip
    src/test_tpm_roundtrip.c
)
target_compile_options(test_tpm_roundtrip PRIVATE -Wall -Wextra)
target_link_libraries(test_tpm_roundtrip PRIVATE
    tpms  # libtpms.so exports TPMLIB_MainInit / TPMLIB_Process / TPMLIB_Terminate
)

# tpm_bench — parameterized TPM2_CreatePrimary harness used by the
# pqctoday-sandbox scenario 36 to drive the EK/SRK/AIK/IDevID migration
# matrix against the real libtpms engine (no swtpm socket needed).
add_executable(tpm_bench
    src/tpm_bench.c
)
target_compile_options(tpm_bench PRIVATE -Wall -Wextra)
target_link_libraries(tpm_bench PRIVATE tpms)

# install into build dir; `make crossval` in the top-level Makefile runs the binary
