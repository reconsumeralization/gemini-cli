#!/bin/bash
set -euo pipefail

# Minimal OSS-Fuzz build script wrapper for local testing.
echo "Building fuzzers for gemini_cli"
export GOPATH=$(go env GOPATH)
mkdir -p $OUT || true
GOCMD=$(command -v go)
cd "$(dirname "$0")"
if [ -z "$GOCMD" ]; then
  echo "go toolchain not found"
  exit 1
fi

# Ensure modules are fetched
${GOCMD} mod tidy

# Build a test binary to validate package compiles
${GOCMD} test -c -o $OUT/gemini_cli_fuzz.test
echo "Built test binary: $OUT/gemini_cli_fuzz.test"
