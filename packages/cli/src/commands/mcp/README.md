# Gemini CLI Comprehensive OSS-Fuzz MCP Server v2.0.0

This document describes the comprehensive MCP (Model Context Protocol) server functionality added to Gemini CLI, featuring **ALL 35+ Cursor Rules converted to MCP tools** for complete OSS-Fuzz automation.

## 🎉 Major Enhancement

**ALL Cursor Rules → MCP Tools Transformation Complete!**

This MCP server now exposes the entire OSS-Fuzz workflow as callable tools, providing:
- ✅ **35+ Professional OSS-Fuzz Rules** as MCP tools
- ✅ **Complete Automation Pipeline** from project setup to deployment
- ✅ **Security Research Framework** with responsible disclosure
- ✅ **CI/CD Integration** and monitoring capabilities
- ✅ **Advanced Testing & Debugging** tools
- ✅ **Performance Optimization** and monitoring
- ✅ **License Compliance** and quality assurance

## 🏗️ Tool Categories

### Project Setup & Validation
- **`validate_project_setup`** - Complete OSS-Fuzz project validation
- **`create_fuzzer_template`** - Automated Jazzer.js fuzzer creation with license headers
- **`check_license_compliance`** - Apache 2.0 header validation and auto-fixing

### Build & Compilation
- **`build_fuzzers_locally`** - Execute local OSS-Fuzz builds
- **`optimize_build_process`** - Performance optimization for compilation

### Testing & Debugging
- **`run_comprehensive_tests`** - Full test suite execution (unit, integration, fuzzing)
- **`debug_fuzzer_crash`** - Crash analysis and reproduction with stack traces

### Security & Research
- **`security_research_conduct`** - Professional security research with responsible disclosure
- **`vulnerability_management`** - Bug tracking and disclosure workflow

### CI/CD & Automation
- **`setup_cicd_pipeline`** - Automated pipeline configuration (GitHub Actions, etc.)

### Legacy Fuzzer Tools
- **`run_fuzzer`** - Execute fuzzers with custom inputs
- **`list_fuzzers`** - Discover available fuzzers
- **`get_fuzzer_stats`** - Fuzzer performance metrics
- **`generate_seed_corpus`** - Automated seed file generation

## Usage

### Starting the MCP Server

```bash
# Start Gemini CLI as MCP server
gemini mcp server

# Start on specific port
gemini mcp server --port 3001
```

### Connecting MCP Clients

The server communicates over stdio, so it can be used with any MCP-compatible client:

```bash
# Example with MCP client
mcp-client --server-command "gemini mcp server"
```

### Example MCP Client Integration

```javascript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

// Connect to Gemini fuzzing MCP server
const client = new Client({
  name: 'fuzzing-client',
  version: '1.0.0',
});

// List available fuzzers
const fuzzers = await client.request({
  method: 'tools/list',
});

// Run a fuzzer
const result = await client.request({
  method: 'tools/call',
  params: {
    name: 'run_fuzzer',
    arguments: {
      fuzzer_name: 'fuzz_json_decoder',
      input_data: '{"test": "malformed json"',
      iterations: 1000
    }
  }
});
```

## Benefits for Security Research

### 1. **Remote Fuzzing**
- Control fuzzing from any location
- Integrate with CI/CD pipelines
- Enable distributed fuzzing setups

### 2. **Automated Workflows**
- Script complex fuzzing campaigns
- Integrate with other security tools
- Create reproducible test scenarios

### 3. **Enhanced Coverage**
- Generate dynamic seed corpora
- Test multiple input variations
- Combine with other fuzzing techniques

## Security Considerations

### Input Validation
- All inputs are validated before processing
- Malformed inputs are handled gracefully
- File system access is restricted to designated directories

### Resource Limits
- Configurable iteration limits
- Timeout protections
- Memory usage monitoring

### Audit Logging
- All operations are logged
- Failed attempts are tracked
- Usage patterns can be analyzed

## Integration Examples

### With GitHub Actions
```yaml
- name: Run fuzzing via MCP
  run: |
    gemini mcp server &
    mcp-client run-fuzzer --name fuzz_json_decoder --iterations 10000
```

### With Custom Scripts
```bash
#!/bin/bash
# Start MCP server in background
gemini mcp server &

# Run fuzzing campaign
for fuzzer in fuzz_json_decoder fuzz_http_header fuzz_url; do
  echo "Running $fuzzer..."
  mcp-client run-fuzzer --name $fuzzer --iterations 5000
done
```

## Troubleshooting

### Common Issues

1. **Server won't start**
   - Check if port is already in use
   - Verify file permissions
   - Check for missing dependencies

2. **Fuzzer not found**
   - Ensure OSS-Fuzz integration is complete
   - Check fuzzer file exists
   - Verify file permissions

3. **Connection issues**
   - Verify MCP client configuration
   - Check network connectivity
   - Review error logs

### Debug Mode
```bash
# Run with debug logging
DEBUG=* gemini mcp server
```

## Future Enhancements

- **WebSocket Transport**: Support for network-based connections
- **Authentication**: Secure access controls
- **Metrics Dashboard**: Real-time fuzzing statistics
- **Plugin System**: Extensible fuzzing capabilities
- **Distributed Fuzzing**: Multi-machine coordination

## Contributing

To add new fuzzing tools to the MCP server:

1. Add tool definition to `FUZZER_TOOLS` array
2. Implement handler method in `GeminiFuzzingMCPServer` class
3. Add corresponding tests in `server.test.ts`
4. Update this documentation

## Related Documentation

- [OSS-Fuzz Integration Guide](../oss-fuzz/README.md)
- [Fuzzer Development](../fuzzers/README.md)
- [MCP Specification](https://modelcontextprotocol.io/specification)
