# Gemini CLI Security Research and Enhancements

## Scope
- Sandbox proxy execution hardening
- Environment variable filtering and validation
- Input tokenization and size limits
- Secrets and credential isolation for child processes

## Current Enhancements
- Require JSON array or tokenized string for `GEMINI_SANDBOX_PROXY_COMMAND`.
- No-shell spawning (`shell: false`) to avoid metacharacter interpretation.
- Strict env filtering for dangerous variables (LD_PRELOAD, DYLD_INSERT_LIBRARIES, BASH_ENV, ENV, IFS, NODE_OPTIONS, language/tooling paths).
- Credentials pruning (GEMINI_API_KEY, GOOGLE_API_KEY, GOOGLE_APPLICATION_CREDENTIALS, AWS keys, SSH agent).
- Conservative env whitelist (PATH, LANG, HOME, TERM, COLORTERM, TZ) + validated proxy vars.
- Limits on SANDBOX_ENV pairs, key/value lengths, and aggregate size.
- Command token count and token length limits to avoid resource abuse.

## Future Work
- Add allowlist for mount paths with canonicalization and symlink resolution.
- Enforce numeric port ranges for published ports; block 0.0.0.0 binds unless explicitly allowed.
- Harden Windows support (COMSPEC/PATHEXT) and macOS DYLD variants.
- Telemetry for rejected SANDBOX_ENV keys/values and proxy spawn failures (privacy-preserving).
- Profile-based policy (Beginner/Standard/Advanced/Developer) to tune limits.

## Test Plan
- Unit tests for env parsing, tokenization, and env building.
- Integration tests for proxy spawn with JSON array and token string forms.
- Negative tests for metacharacters, oversize tokens, dangerous envs, and secrets leakage.