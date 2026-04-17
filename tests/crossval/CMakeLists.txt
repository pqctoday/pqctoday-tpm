cmake_minimum_required(VERSION 3.16)
project(pqctoday_tpm_crossval C)

# Require OpenSSL 3.5+ for ML-DSA / ML-KEM in default provider.
set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL 3.5 REQUIRED)

add_executable(test_pqc_crossval
    src/test_pqc_crossval.c
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

# install into build dir; `make crossval` in the top-level Makefile runs the binary
