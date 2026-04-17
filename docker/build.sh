#!/usr/bin/env bash
# pqctoday-tpm — build + enter dev container
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=${IMAGE:-pqctoday-tpm-dev}

cd "$REPO_ROOT"
docker build -f docker/Dockerfile.dev -t "$IMAGE" .

if [[ "${1-}" == "--shell" ]]; then
    exec docker run --rm -it \
        -v "$REPO_ROOT:/workspace" \
        -w /workspace \
        "$IMAGE" /bin/bash
fi

echo "Image built: $IMAGE"
echo "Enter the container with:"
echo "  docker run --rm -it -v \"\$PWD:/workspace\" $IMAGE"
