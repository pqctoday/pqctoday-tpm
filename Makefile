# pqctoday-tpm — top-level convenience targets
#
# The real build systems are autotools (libtpms, swtpm) and CMake (cross-val
# harness, future WASM). This Makefile wraps common developer-facing targets.

.PHONY: help crossval crossval-build crossval-run crossval-softhsm compliance compliance-softhsm docker-dev clean

help:
	@echo "pqctoday-tpm — developer targets"
	@echo
	@echo "  make docker-dev     Build the pqctoday-tpm-dev Docker image"
	@echo "  make compliance     Run the TCG V1.85 PQC compliance test suite"
	@echo "  make crossval       Run the PQC cross-validation harness in Docker"
	@echo "  make crossval-build Build the harness without running it"
	@echo "  make clean          Clean build artifacts under tests/crossval/build"
	@echo

docker-dev:
	docker build -f docker/Dockerfile.dev -t pqctoday-tpm-dev .

crossval-build:
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make clean > /dev/null 2>&1 && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             cmake -S tests/crossval -B tests/crossval/build \
	                 -DCMAKE_PREFIX_PATH=/opt/openssl \
	                 -DOPENSSL_ROOT_DIR=/opt/openssl && \
	             cmake --build tests/crossval/build -j$$(nproc)'

# Location of the softhsmv3 sibling repo (built dylibs live under build-pqctoday/).
# Override with SOFTHSMV3_DIR=... make crossval-softhsm.
SOFTHSMV3_DIR ?= $(abspath $(PWD)/../softhsmv3)

crossval: crossval-build
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             tests/crossval/build/test_pqc_crossval && \
	             tests/crossval/build/test_tpm_roundtrip && \
	             tests/crossval/build/test_pqc_phase3'

crossval-softhsm: crossval-build
	@echo "Running cross-val with softhsmv3 C++ engine at $(SOFTHSMV3_DIR)"
	@test -f $(SOFTHSMV3_DIR)/build-pqctoday/src/lib/libsofthsmv3.so \
	    || (echo "libsofthsmv3.so not found — run: cd $(SOFTHSMV3_DIR) && \
	                 cmake -S . -B build-pqctoday -DBUILD_TESTS=OFF && \
	                 cmake --build build-pqctoday -j"; exit 1)
	docker run --rm \
	    -v "$$PWD:/workspace" \
	    -v "$(SOFTHSMV3_DIR):/softhsmv3" \
	    -e SOFTHSM2_CONF=/tmp/softhsm2.conf \
	    -e PQCTODAY_TPM_PKCS11_MODULE=/softhsmv3/build-pqctoday/src/lib/libsofthsmv3.so \
	    -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             mkdir -p /tmp/tokens && \
	             printf "directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" > /tmp/softhsm2.conf && \
	             tests/crossval/build/test_pqc_crossval && \
	             tests/crossval/build/test_tpm_roundtrip'

compliance: crossval-build
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    bash -c 'cd libtpms && make install > /dev/null 2>&1 && ldconfig && cd - && \
	             bash tests/compliance/v185_compliance.sh'

compliance-softhsm: crossval-build
	@echo "Running full compliance (includes softhsmv3) with $(SOFTHSMV3_DIR)"
	@test -f $(SOFTHSMV3_DIR)/build-pqctoday/src/lib/libsofthsmv3.so \
	    || (echo "libsofthsmv3.so not found — build softhsmv3 first"; exit 1)
	docker run --rm \
	    -v "$$PWD:/workspace" \
	    -v "$(SOFTHSMV3_DIR):/softhsmv3" \
	    -e SOFTHSM2_CONF=/tmp/softhsm2.conf \
	    -e PQCTODAY_TPM_PKCS11_MODULE=/softhsmv3/build-pqctoday/src/lib/libsofthsmv3.so \
	    -w /workspace pqctoday-tpm-dev \
	    bash -c 'mkdir -p /tmp/tokens && \
	             printf "directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" > /tmp/softhsm2.conf && \
	             bash tests/compliance/v185_compliance.sh'

clean:
	rm -rf tests/crossval/build
