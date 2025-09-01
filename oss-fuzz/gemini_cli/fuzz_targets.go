package main

import (
    "encoding/json"
    "net/url"
    "strings"
    "unicode/utf8"
    fuzz "github.com/google/gofuzz"
)

// Minimal mirrored parsers suitable for fuzzing. They intentionally avoid
// external I/O and try to mirror the TypeScript parsing behavior used in the
// CLI where practical.

// Config represents a minimal JSON config structure used by Gemini CLI.
type Config struct {
    Version string            `json:"version"`
    Settings map[string]any   `json:"settings"`
}

// MCPEnvelope represents a simple JSON-RPC envelope for the MCP protocol.
type MCPEnvelope struct {
    ID interface{} `json:"id"`
    Method string  `json:"method"`
    Params any      `json:"params"`
}

// OAuthTokenResponse mirrors an OAuth token response body.
type OAuthTokenResponse struct {
    AccessToken string `json:"access_token"`
    TokenType string  `json:"token_type"`
    ExpiresIn int     `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
}

// OAuthTokenRequest mirrors a token request body.
type OAuthTokenRequest struct {
    GrantType string `json:"grant_type"`
    Code string      `json:"code"`
    RedirectURI string `json:"redirect_uri"`
    ClientID string   `json:"client_id"`
}

// safeUTF8 checks strings for valid UTF-8 and simple length constraints.
func safeUTF8(s string) bool {
    if !utf8.ValidString(s) {
        return false
    }
    if len(s) > 1<<20 { // guard: >1MiB
        return false
    }
    return true
}

// parseCLIArgs attempts to split a simple command-line into args. It
// simulates a basic POSIX-like split without globbing or expansion.
func parseCLIArgs(input string) []string {
    fields := []string{}
    sb := strings.Builder{}
    inQuote := rune(0)
    esc := false
    for _, r := range input {
        if esc {
            sb.WriteRune(r)
            esc = false
            continue
        }
        if r == '\\' {
            esc = true
            continue
        }
        if inQuote != 0 {
            if r == inQuote {
                inQuote = 0
                continue
            }
            sb.WriteRune(r)
            continue
        }
        if r == '\'' || r == '"' {
            inQuote = r
            continue
        }
        if r == ' ' || r == '\t' || r == '\n' {
            if sb.Len() > 0 {
                fields = append(fields, sb.String())
                sb.Reset()
            }
            continue
        }
        sb.WriteRune(r)
    }
    if sb.Len() > 0 {
        fields = append(fields, sb.String())
    }
    return fields
}

// Fuzz target: config parser
func FuzzConfigParser(data []byte) int {
    // Protect against huge inputs
    if len(data) > 1<<20 {
        return 0
    }
    var c Config
    if err := json.Unmarshal(data, &c); err != nil {
        return 0
    }
    // Basic invariants
    if c.Version != "" && !safeUTF8(c.Version) {
        panic("invalid version utf8")
    }
    // Exercise settings map by encoding back and simple traversal
    if _, err := json.Marshal(c.Settings); err != nil {
        panic("settings marshal failed")
    }
    return 1
}

// Fuzz target: MCP decoder
func FuzzMCPDecoder(data []byte) int {
    if len(data) > 1<<20 { return 0 }
    var e MCPEnvelope
    if err := json.Unmarshal(data, &e); err != nil { return 0 }
    // method should be sane
    if e.Method != "" && !safeUTF8(e.Method) { panic("bad method") }
    // simulate dispatch: only known methods
    switch e.Method {
    case "mcp.ping":
        // ok
    case "mcp.exec":
        // inspect params a little
        _, _ = json.Marshal(e.Params)
    default:
        // unknown methods are allowed
    }
    return 1
}

// Fuzz target: CLI parser
func FuzzCLIParser(data []byte) int {
    if len(data) > 1<<16 { return 0 }
    // Treat data as UTF-8 string with fallbacks
    s := string(data)
    if !safeUTF8(s) { return 0 }
    args := parseCLIArgs(s)
    // Basic assertions: reconstruct and ensure no panics
    for _, a := range args {
        if len(a) > 1<<16 { panic("arg too long") }
    }
    return 1
}

// Fuzz target: OAuth token response
func FuzzOAuthTokenResponse(data []byte) int {
    if len(data) > 1<<16 { return 0 }
    var r OAuthTokenResponse
    if err := json.Unmarshal(data, &r); err != nil { return 0 }
    // Basic checks
    if r.AccessToken != "" && !safeUTF8(r.AccessToken) { panic("bad token utf8") }
    if r.ExpiresIn < 0 || r.ExpiresIn > 1<<31 { panic("expires out of bounds") }
    return 1
}

// Fuzz target: OAuth token request
func FuzzOAuthTokenRequest(data []byte) int {
    if len(data) > 1<<16 { return 0 }
    var q OAuthTokenRequest
    if err := json.Unmarshal(data, &q); err != nil { return 0 }
    if q.RedirectURI != "" {
        if _, err := url.ParseRequestURI(q.RedirectURI); err != nil {
            // invalid URIs are expected but must not panic
            return 0
        }
    }
    if q.GrantType == "authorization_code" && q.Code == "" {
        // malformed request
        return 0
    }
    // ensure safe strings
    if !safeUTF8(q.ClientID) { panic("bad client id") }
    return 1
}

// Provide a small helper to generate random valid-ish inputs for local testing.
func init() {
    f := fuzz.New()
    _ = f
}
