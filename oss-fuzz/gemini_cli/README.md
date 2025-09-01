OSS-Fuzz integration for Gemini CLI.

This folder contains Go-based mirrored parsers and fuzz targets suitable for
submission to OSS-Fuzz. The fuzzers avoid I/O and external dependencies.

Local build (requires Go):

  OUT=out ./build.sh

The project includes seed corpora for each target under `corpora/`.
