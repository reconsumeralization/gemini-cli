## Proposed change

Please include a summary of the change and which issue is fixed. Provide
context for maintainers and reviewers.

## Checklist for reviewers
- [ ] Confirm OSS-Fuzz files are under `oss-fuzz/gemini_cli` and follow OSS-Fuzz best practices
- [ ] Corpora look appropriate and contain no secrets
- [ ] No network or durable-storage I/O in fuzz targets
- [ ] CI validates build
- [ ] Licensing is compatible

## How to test locally
1. Build the repo: `npm run build`
2. Validate OSS-Fuzz build: `OUT=out ./oss-fuzz/gemini_cli/build.sh`
