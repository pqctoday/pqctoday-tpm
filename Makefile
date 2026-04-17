# pqctoday-tpm — top-level convenience targets
#
# The real build systems are autotools (libtpms, swtpm) and CMake (cross-val
# harness, future WASM). This Makefile wraps common developer-facing targets.

.PHONY: help crossval crossval-build crossval-run docker-dev clean

help:
	@echo "pqctoday-tpm — developer targets"
	@echo
	@echo "  make docker-dev     Build the pqctoday-tpm-dev Docker image"
	@echo "  make crossval       Run the PQC cross-validation harness in Docker"
	@echo "  make crossval-build Build the harness without running it"
	@echo "  make clean          Clean build artifacts under tests/crossval/build"
	@echo

docker-dev:
	docker build -f docker/Dockerfile.dev -t pqctoday-tpm-dev .

crossval-build:
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    bash -c 'cmake -S tests/crossval -B tests/crossval/build \
	                 -DCMAKE_PREFIX_PATH=/opt/openssl \
	                 -DOPENSSL_ROOT_DIR=/opt/openssl && \
	             cmake --build tests/crossval/build -j$$(nproc)'

crossval: crossval-build
	docker run --rm -v "$$PWD:/workspace" -w /workspace pqctoday-tpm-dev \
	    tests/crossval/build/test_pqc_crossval

clean:
	rm -rf tests/crossval/build
