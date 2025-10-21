# JetBrains IDE Companion Plugin

A production-ready companion plugin for JetBrains IDEs that enables seamless integration with Gemini CLI.

## Features

- **🔒 Security-First Design**: DNS rebinding protection, Bearer token authentication, and comprehensive security validation
- **🔄 Multi-Client Support**: Handles multiple concurrent CLI sessions with proper isolation
- **📁 Workspace Context**: Real-time awareness of open files, cursor position, and text selections
- **🔀 Native Diffing**: View and edit Gemini's suggested changes directly in your IDE's diff viewer
- **⚡ High Performance**: Efficient session management and context tracking

## Architecture

This plugin implements the [Gemini CLI Companion Extension Specification](https://github.com/google-gemini/gemini-cli/blob/main/docs/ide-companion-spec.md) using:

- **MCP over HTTP**: Model Context Protocol implementation with secure HTTP transport
- **Session Management**: Single MCP server instance with multi-client session tracking
- **Discovery Mechanism**: File-based coordination between IDE and CLI processes
- **Security Layers**: Host validation, authentication, CORS, and secure headers

## Security Features

### DNS Rebinding Protection

```kotlin
private fun validateHostHeader(hostHeader: String?): Boolean {
    if (hostHeader == null) return false

    val hostname = hostHeader.substringBefore(":").lowercase().trim()
    return allowedHosts.any { allowedHost ->
        allowedHost.lowercase() == hostname
    }
}
```

### Bearer Token Authentication

```kotlin
private fun validateAuthorization(authHeader: String?): Boolean {
    if (authHeader == null) return false

    val parts = authHeader.split(" ")
    if (parts.size != 2 || parts[0] != "Bearer") {
        return false
    }

    return parts[1] == authToken
}
```

### Multi-Client Session Isolation

```kotlin
private val activeSessions = ConcurrentHashMap<String, SessionContext>()

data class SessionContext(
    val sessionId: String,
    val connectedAt: Long,
    val workspacePath: String,
    val clientInfo: String = "gemini-cli"
)
```

## Installation

### From JetBrains Marketplace

1. Open your JetBrains IDE
2. Go to `File` → `Settings` → `Plugins`
3. Search for "Gemini CLI Companion"
4. Install and restart your IDE

### Manual Installation

1. Download the plugin JAR from the [Releases](../../releases) page
2. Go to `File` → `Settings` → `Plugins`
3. Click the gear icon → `Install Plugin from Disk`
4. Select the downloaded JAR file
5. Restart your IDE

## Usage

1. **Install Gemini CLI**: Follow the [Gemini CLI installation guide](https://github.com/google-gemini/gemini-cli#installation)

2. **Start the Plugin**: The plugin automatically starts when you open a project

3. **Run Gemini CLI**: Use the integrated terminal in your IDE:

   ```bash
   gemini
   ```

4. **Enable Integration**: In the CLI, run:
   ```
   /ide enable
   ```

## Development

### Building from Source

```bash
git clone https://github.com/google-gemini/gemini-cli
cd gemini-cli/ai/jetbrains-ide-companion
./gradlew buildPlugin
```

### Running Tests

```bash
./gradlew test
```

### Security Testing

The plugin includes comprehensive security tests:

```bash
./gradlew test --tests "*SecurityValidationTest*"
```

## Configuration

The plugin automatically configures itself with secure defaults:

- **Port**: Dynamically assigned (OS selects via port 0)
- **Host**: `127.0.0.1` (localhost only)
- **Authentication**: Bearer token with 32-byte secure random generation
- **CORS**: Strict origin validation
- **Headers**: Security headers (X-Content-Type-Options, X-Frame-Options, etc.)

## Troubleshooting

### Connection Issues

- Ensure Gemini CLI is installed and accessible from your IDE's terminal
- Check that the plugin is enabled in `File` → `Settings` → `Plugins`
- Verify your project is trusted (JetBrains security requirement)

### Security Warnings

- The plugin binds to `127.0.0.1` only for security
- All requests require valid Bearer token authentication
- Host header validation prevents DNS rebinding attacks

### Performance

- The plugin uses efficient session management
- Context updates are debounced to prevent excessive notifications
- File tracking is limited to 10 most recent files

## Contributing

We welcome contributions! Please see our [Contributing Guide](../../CONTRIBUTING.md) for details.

### Security Considerations

- All security features must be tested
- DNS rebinding protection is mandatory
- Authentication tokens must be cryptographically secure
- Session isolation must be maintained

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../../LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/google-gemini/gemini-cli/issues)
- **Security**: [Security Policy](../../SECURITY.md)
- **Documentation**: [Gemini CLI Docs](https://github.com/google-gemini/gemini-cli/tree/main/docs)

---

**Built with ❤️ by Google and the open source community**
