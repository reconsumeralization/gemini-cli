# JetBrains IDE Companion - Security Architecture

## Overview

This document details the security architecture of the JetBrains IDE Companion plugin, which implements production-ready security features to protect against common attack vectors while maintaining seamless integration with Gemini CLI.

## Security Layers

### Layer 1: DNS Rebinding Protection

**Attack Vector**: DNS rebinding allows malicious websites to access local services by:

1. Serving malicious JavaScript from `evil.com`
2. Changing DNS resolution to point `evil.com` → `127.0.0.1`
3. Making requests to local services without CORS restrictions

**Mitigation**: Host header validation

```kotlin
private fun validateHostHeader(hostHeader: String?): Boolean {
    if (hostHeader == null) return false

    val hostname = hostHeader.substringBefore(":").lowercase().trim()
    return allowedHosts.any { allowedHost ->
        allowedHost.lowercase() == hostname
    }
}
```

**Allowed Hosts**:

- `localhost`
- `127.0.0.1`
- `[::1]` (IPv6 localhost)

All other hosts are rejected with `403 Forbidden`.

### Layer 2: Bearer Token Authentication

**Attack Vector**: Any local process could connect to the MCP server without authentication.

**Mitigation**: Cryptographically secure Bearer tokens

```kotlin
private fun generateSecureToken(): String {
    val random = SecureRandom()
    val bytes = ByteArray(32) // 256-bit token
    random.nextBytes(bytes)
    return Base64.getEncoder().encodeToString(bytes)
}
```

All requests must include:

```
Authorization: Bearer <token>
```

Invalid or missing tokens receive `401 Unauthorized`.

### Layer 3: CORS Policy

**Attack Vector**: Cross-origin requests from untrusted origins.

**Mitigation**: Strict CORS configuration

```kotlin
install(CORS) {
    allowedOrigins.forEach { origin ->
        val host = origin.removePrefix("http://").removePrefix("https://")
        allowHost(host, schemes = listOf("http", "https"))
    }

    allowCredentials = true
    maxAgeInSeconds = 3600
}
```

**Allowed Origins**:

- `http://localhost`
- `http://127.0.0.1`

Requests from other origins receive `403 Forbidden`.

### Layer 4: Secure Response Headers

**Mitigation**: Security headers prevent common web vulnerabilities

```kotlin
install(DefaultHeaders) {
    header("X-Content-Type-Options", "nosniff")
    header("X-Frame-Options", "DENY")
    header("X-XSS-Protection", "1; mode=block")
    header("Referrer-Policy", "strict-origin-when-cross-origin")
}
```

## Session Management

### Multi-Client Isolation

Each Gemini CLI instance gets a unique session ID to prevent state bleed:

```kotlin
private val activeSessions = ConcurrentHashMap<String, SessionContext>()

data class SessionContext(
    val sessionId: String,
    val connectedAt: Long,
    val workspacePath: String,
    val clientInfo: String = "gemini-cli"
)
```

Session IDs are:

- Generated using `UUID.randomUUID()`
- Tracked per HTTP request
- Isolated from other sessions
- Cleaned up on disconnect

### Workspace Isolation

**Attack Vector**: CLI instance in one project accessing context from another project.

**Mitigation**: Workspace path validation

Each session is bound to a specific workspace path. The discovery file includes:

```json
{
  "workspacePath": "/absolute/path/to/project"
}
```

Gemini CLI verifies it's running in a subdirectory of the workspace path before connecting.

## Network Binding

### Localhost-Only Binding

**Configuration**:

```kotlin
server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
    configureServer()
}.start(wait = false)
```

**Security Benefits**:

- Server only accessible from localhost
- No external network exposure
- Reduces attack surface to local processes only

### Dynamic Port Assignment

**Configuration**:

```kotlin
port = 0  // OS assigns available port
```

**Security Benefits**:

- Avoids port conflicts
- Unpredictable port reduces reconnaissance
- Documented in discovery file for legitimate CLI access

## Discovery File Security

### File Location

```
${TMPDIR}/gemini/ide/gemini-ide-server-${PID}-${PORT}.json
```

### File Permissions

**Unix-like Systems**:

```kotlin
Files.setPosixFilePermissions(
    path,
    PosixFilePermissions.fromString("rw-------")  // 0600
)
```

**Windows**:

- Inherits user-only access from TEMP directory

### File Content

```json
{
  "port": 12345,
  "workspacePath": "/path/to/project",
  "authToken": "base64-encoded-32-byte-token",
  "ideInfo": {
    "name": "jetbrains",
    "displayName": "JetBrains IDE"
  }
}
```

### Lifecycle Management

- Created on server start
- Deleted on server stop
- `deleteOnExit()` ensures cleanup even on abnormal termination

## Threat Model

### Threats Mitigated

1. **DNS Rebinding** - Host header validation
2. **Unauthorized Local Access** - Bearer token authentication
3. **Cross-Origin Attacks** - CORS policy
4. **Session Hijacking** - Cryptographic session IDs
5. **Cross-Project Leakage** - Workspace path validation
6. **Network Exposure** - Localhost-only binding
7. **Port Scanning** - Dynamic port assignment
8. **File Permission Issues** - Secure discovery file permissions

### Residual Risks

1. **Local Privilege Escalation**: A compromised process with access to TEMP directory could read the discovery file
   - **Mitigation**: File permissions (0600 on Unix)
   - **Acceptance**: Local privilege escalation is out of scope

2. **Memory Inspection**: A debugger could read the auth token from memory
   - **Mitigation**: None (root/admin access required)
   - **Acceptance**: If attacker has debugging privileges, system is already compromised

3. **Process Injection**: Malicious code in IDE process could access MCP server
   - **Mitigation**: None (process isolation is OS responsibility)
   - **Acceptance**: If IDE process is compromised, MCP server access is least concern

## Security Testing

### Test Coverage

1. **DNS Rebinding Tests**: Verify rejection of non-localhost Host headers
2. **Authentication Tests**: Verify token validation on all endpoints
3. **Session Isolation Tests**: Verify no state bleed between clients
4. **CORS Tests**: Verify origin validation
5. **Concurrency Tests**: Verify 50+ concurrent clients work correctly
6. **Permission Tests**: Verify discovery file permissions

### Security Validation

```bash
# Test 1: Valid request
curl -H "Host: localhost:PORT" \
     -H "Authorization: Bearer TOKEN" \
     http://127.0.0.1:PORT/mcp

# Test 2: DNS rebinding (should fail)
curl -H "Host: evil.com:PORT" \
     -H "Authorization: Bearer TOKEN" \
     http://127.0.0.1:PORT/mcp

# Test 3: Missing auth (should fail)
curl -H "Host: localhost:PORT" \
     http://127.0.0.1:PORT/mcp

# Test 4: Invalid token (should fail)
curl -H "Host: localhost:PORT" \
     -H "Authorization: Bearer invalid" \
     http://127.0.0.1:PORT/mcp
```

## Compliance

### Standards Followed

- **OWASP Top 10**: Addresses injection, authentication, sensitive data exposure
- **CWE-918**: Server-Side Request Forgery (DNS rebinding)
- **CWE-285**: Improper Authorization
- **CWE-346**: Origin Validation Error
- **RFC 6749**: OAuth 2.0 Bearer Token Usage

### Industry Best Practices

- Defense in depth (multiple security layers)
- Principle of least privilege (localhost-only, minimal permissions)
- Secure by default (all security features enabled)
- Fail securely (reject on validation failure)
- Complete mediation (validate every request)

## Security Maintenance

### Update Procedures

1. **Dependency Updates**: Monitor Ktor, MCP SDK for security patches
2. **Vulnerability Scanning**: Use Gradle dependency checks
3. **Security Audits**: Review code for new attack vectors
4. **Penetration Testing**: Test against OWASP attack patterns

### Incident Response

If a security vulnerability is discovered:

1. Report via [g.co/vulnz](https://g.co/vulnz)
2. Do not disclose publicly until patched
3. Follow coordinated disclosure timeline
4. Publish security advisory after patch

## References

- [Gemini CLI IDE Companion Specification](https://github.com/google-gemini/gemini-cli/blob/main/docs/ide-companion-spec.md)
- [VS Code Companion Reference Implementation](https://github.com/google-gemini/gemini-cli/tree/main/packages/vscode-ide-companion)
- [MCP Protocol Specification](https://modelcontextprotocol.io/specification/)
- [OWASP DNS Rebinding](https://owasp.org/www-community/attacks/DNS_Rebinding)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)

---

**Last Updated**: October 21, 2025  
**Version**: 1.0.0  
**Maintainers**: Google Gemini CLI Team
