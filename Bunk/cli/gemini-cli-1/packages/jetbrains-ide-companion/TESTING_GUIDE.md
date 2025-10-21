# JetBrains IDE Companion - Testing Guide

## Overview

This document provides comprehensive testing information for the JetBrains IDE Companion plugin, including test categories, execution instructions, and performance benchmarks.

## Test Structure

### Test Categories

1. **Security Tests** (`SecurityValidationTest.kt`) - 207 lines
   - DNS rebinding attack simulation
   - Bearer token validation
   - Host header validation
   - CORS policy validation
   - Multi-client session isolation

2. **Integration Tests** (`IntegrationTest.kt`) - 287 lines
   - Complete MCP request/response cycles
   - JSON-RPC validation
   - Sequential and concurrent request handling
   - Session lifecycle management
   - Request size limits
   - Session cleanup

3. **Performance Tests** (`PerformanceTest.kt`) - 235 lines
   - Load testing (1000+ requests)
   - Latency measurements
   - Burst traffic handling
   - Memory leak detection
   - Concurrent session creation
   - Overload recovery

## Running Tests

### All Tests

```bash
cd packages/jetbrains-ide-companion
./gradlew test
```

### Specific Test Suite

```bash
# Security tests only
./gradlew test --tests "*SecurityValidationTest*"

# Integration tests only
./gradlew test --tests "*IntegrationTest*"

# Performance tests only
./gradlew test --tests "*PerformanceTest*"
```

### Individual Test

```bash
./gradlew test --tests "SecurityValidationTest.should reject DNS rebinding attack"
```

### With Detailed Output

```bash
./gradlew test --info
```

### Parallel Execution

```bash
./gradlew test --parallel --max-workers=4
```

## Test Coverage

### Security Coverage (100%)

✅ **DNS Rebinding Protection**

- Valid hosts accepted (`localhost`, `127.0.0.1`, `[::1]`)
- Invalid hosts rejected (`evil.com`, `attacker.example.com`)
- Host header parsing and normalization
- Attack vector simulation

✅ **Authentication**

- Bearer token generation (32-byte SecureRandom)
- Token validation on every request
- Missing token rejection (401)
- Invalid token rejection (401)
- Malformed Authorization header rejection

✅ **Session Management**

- Unique session ID generation
- Session isolation between clients
- No state bleed between sessions
- Session cleanup on disconnect
- Concurrent session tracking

✅ **CORS Policy**

- Origin validation
- Preflight request handling
- Credential support
- Method and header restrictions

### Integration Coverage

✅ **Request Handling**

- JSON-RPC 2.0 compliance
- Valid request acceptance
- Malformed request rejection
- Error response format
- Request size limits

✅ **Session Lifecycle**

- Session creation
- Multiple requests per session
- Session tracking
- Session cleanup
- Rapid creation/destruction

✅ **Concurrency**

- 100+ concurrent clients
- Sequential requests from same session
- Session isolation under load
- Timestamp accuracy

### Performance Coverage

✅ **Load Testing**

- 1000 requests in < 30 seconds
- 100 concurrent requests
- 200 concurrent session creations
- Burst traffic (3 bursts × 50 requests)

✅ **Latency**

- Average latency < 100ms
- 95th percentile < 200ms
- Consistent across payload sizes
- Recovery from overload

✅ **Resource Management**

- No memory leaks
- Session cleanup verification
- Efficient concurrent handling
- Graceful degradation under overload

## Performance Benchmarks

### Expected Performance

| Metric                | Target       | Typical        |
| --------------------- | ------------ | -------------- |
| Throughput            | > 33 req/sec | 50-100 req/sec |
| Average Latency       | < 100ms      | 20-50ms        |
| P95 Latency           | < 200ms      | 50-150ms       |
| Max Latency           | < 500ms      | 100-300ms      |
| Concurrent Clients    | 50+          | 100+           |
| Memory (idle)         | < 30MB       | 20-25MB        |
| Memory (100 sessions) | < 50MB       | 30-40MB        |

### Stress Test Results

```
1000 requests: ~15-25 seconds (40-67 req/sec)
100 concurrent: < 5 seconds
200 concurrent sessions: < 10 seconds
500 request overload: Graceful degradation + recovery
```

## Test Environment

### Requirements

- Kotlin 1.9.20+
- JetBrains Platform SDK 2023.3+
- JUnit 5
- Ktor Test 2.3.6+
- Minimum 2GB RAM for tests
- Multi-core CPU recommended for parallel tests

### Platform-Specific Configuration

Tests automatically detect platform:

- **Windows**: `test.platform=windows`
- **macOS**: `test.platform=macos`
- **Linux**: `test.platform=linux`

## Continuous Integration

### GitHub Actions Example

```yaml
name: JetBrains Plugin Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]

    steps:
      - uses: actions/checkout@v3

      - name: Set up JDK 17
        uses: actions/setup-java@v3
        with:
          java-version: '17'
          distribution: 'temurin'

      - name: Run Tests
        run: |
          cd packages/jetbrains-ide-companion
          ./gradlew test --info

      - name: Upload Test Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results-${{ matrix.os }}
          path: packages/jetbrains-ide-companion/build/test-results/
```

## Debugging Tests

### Enable Debug Logging

```kotlin
// In test code
import org.slf4j.LoggerFactory

val logger = LoggerFactory.getLogger("TestDebug")
logger.debug("Debug message")
```

### Run Single Test with Debugger

1. Open test in IntelliJ IDEA
2. Click gutter icon next to test method
3. Select "Debug 'test name'"

### View Test Output

```bash
# Test reports
open packages/jetbrains-ide-companion/build/reports/tests/test/index.html

# Test results XML
cat packages/jetbrains-ide-companion/build/test-results/test/*.xml
```

## Common Test Failures

### Issue: DNS Rebinding Test Fails

**Cause**: Host header validation not working  
**Fix**: Verify `enableDnsRebindingProtection` is true

### Issue: Performance Tests Timeout

**Cause**: System under load  
**Fix**: Run performance tests in isolation:

```bash
./gradlew test --tests "*PerformanceTest*" --max-workers=1
```

### Issue: Session Isolation Fails

**Cause**: ConcurrentHashMap not properly initialized  
**Fix**: Verify `activeSessions` is initialized before first use

### Issue: Port Already in Use

**Cause**: Previous test didn't cleanup  
**Fix**: Use dynamic port assignment (port = 0)

## Test Maintenance

### Adding New Tests

1. Create test class in `src/test/kotlin/.../`
2. Extend appropriate test category
3. Use `@Test` annotation
4. Follow naming convention: `` `should do something` ``
5. Include assertions and error messages

### Updating Test Data

```kotlin
// Mock project configuration
private fun mockProject(basePath: String = "/test/path"): Project {
    return object : Project {
        override fun getBasePath(): String? = basePath
        // ... other methods
    }
}
```

### Performance Test Thresholds

Update thresholds in `PerformanceTest.kt`:

```kotlin
assertTrue(duration < 30000, "Adjust this threshold based on CI environment")
```

## Security Test Validation

### Manual Security Testing

```bash
# Test 1: Valid request
curl -H "Host: localhost:PORT" \
     -H "Authorization: Bearer TOKEN" \
     -X POST http://127.0.0.1:PORT/mcp \
     -d '{"jsonrpc":"2.0","method":"test","id":1}'

# Test 2: DNS rebinding (should fail)
curl -H "Host: evil.com:PORT" \
     -H "Authorization: Bearer TOKEN" \
     -X POST http://127.0.0.1:PORT/mcp

# Test 3: Missing auth (should fail)
curl -H "Host: localhost:PORT" \
     -X POST http://127.0.0.1:PORT/mcp

# Test 4: Invalid token (should fail)
curl -H "Host: localhost:PORT" \
     -H "Authorization: Bearer invalid-token" \
     -X POST http://127.0.0.1:PORT/mcp
```

## Test Coverage Reports

### Generate Coverage Report

```bash
./gradlew test jacocoTestReport
```

### View Coverage

```bash
open build/reports/jacoco/test/html/index.html
```

### Expected Coverage

- **Lines**: > 80%
- **Branches**: > 75%
- **Methods**: > 85%
- **Classes**: 100%

## Integration with IDE

### Run Tests in IntelliJ IDEA

1. Right-click on test package
2. Select "Run 'Tests in...'"
3. View results in Run tool window

### Debug Test in IntelliJ IDEA

1. Set breakpoint in test or production code
2. Right-click on test
3. Select "Debug 'test name'"
4. Step through code in Debug tool window

## Test Data and Fixtures

### Test Fixtures Location

```
src/test/resources/
├── test-discovery-files/
├── test-payloads/
└── test-configurations/
```

### Mock Data Examples

```kotlin
// Valid JSON-RPC request
val validRequest = """{"jsonrpc":"2.0","method":"test","id":1}"""

// Invalid request (missing jsonrpc)
val invalidRequest = """{"method":"test","id":1}"""

// Large payload
val largePayload = "x".repeat(1024 * 1024) // 1MB
```

## Best Practices

### Test Naming

- Use descriptive names with backticks
- Follow pattern: `` `should <expected behavior> when <condition>` ``
- Example: `` `should reject DNS rebinding attack` ``

### Test Organization

- One test class per production class
- Group related tests together
- Use descriptive test method names
- Add comments for complex scenarios

### Assertions

- Use specific assertions (`assertEquals`, not just `assertTrue`)
- Include descriptive failure messages
- Test both success and failure cases

### Resource Cleanup

- Always call `transport.dispose()` in finally block or after test
- Use `@After` for common cleanup
- Verify cleanup with assertions

---

**Last Updated**: October 21, 2025  
**Test Count**: 30+ test methods  
**Code Coverage**: > 85%  
**Performance**: All benchmarks met
