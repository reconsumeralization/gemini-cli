#!/usr/bin/env bash
set -euo pipefail

echo "CIFuzz build wrapper: building JS and Go fuzz targets"

if command -v node >/dev/null 2>&1 && [ -f package.json ]; then
  echo "Installing Node dependencies"
  npm ci
  if npm run -s build >/dev/null 2>&1; then
    echo "Repository build succeeded"
  else
    echo "Repository build failed (npm run build)"
    exit 1
  fi
else
  echo "Node not found or package.json missing — skipping JS build"
fi

# Build the Go/OSS-Fuzz fuzzers if the folder exists
if [ -d "oss-fuzz/gemini_cli" ]; then
  if command -v go >/dev/null 2>&1; then
    echo "Building Go fuzzers (oss-fuzz/gemini_cli)"
    pushd oss-fuzz/gemini_cli >/dev/null
    ./build.sh
    popd >/dev/null
  else
    echo "Go not found — skipping Go fuzzers build"
  fi
else
  echo "oss-fuzz/gemini_cli not found — skipping Go fuzzers build"
fi

echo "CIFuzz build wrapper completed"
