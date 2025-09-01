OSS-Fuzz integration for Gemini CLI

## Summary

Adds an `oss-fuzz/gemini_cli` directory containing Go-based mirrored parsers and five fuzz targets:
Adds an `oss-fuzz/gemini_cli` directory containing Go-based mirrored parsers and five fuzz targets:

- FuzzConfigParser
- FuzzMCPDecoder
- FuzzCLIParser
- FuzzOAuthTokenResponse
- FuzzOAuthTokenRequest

## What changed

- New OSS-Fuzz project: `oss-fuzz/gemini_cli` with `go.mod`, `fuzz_targets.go`, corpora, `build.sh`, and `project.yaml`.
- VS Code workspace additions: `.vscode/*` and `DEVELOPER_SETUP.md`.
- CI (suggested) and PR template added to make review easier.

## Security considerations

- Fuzz targets contain no network I/O or file writes.
- Corpora are small and do not include secrets.
- Input size bounds and UTF-8 checks are applied to avoid resource exhaustion.

## How to test

Run the following locally:

```bash
npm run build
chmod +x oss-fuzz/gemini_cli/build.sh
OUT=out ./oss-fuzz/gemini_cli/build.sh
```

## Next steps for maintainers

1. Review the fuzz targets and corpora.
2. Approve adding to OSS-Fuzz and assist with submission to `google/oss-fuzz` if desired.

Contact: `David Weatherspoon <reconsumeralization@gmail.com>` — demo and assistance available.
