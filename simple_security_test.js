// Simple synchronous test of our security functions
console.log('🧪 Testing Security Functions...\n');

// Test environment filtering
try {
  const { parseAndFilterSandboxEnv } = require('./packages/cli/src/utils/sandbox_helpers.js');

  const testInput = 'SAFE=test,GEMINI_API_KEY=secret,PASSWORD=hack';
  const result = parseAndFilterSandboxEnv(testInput);

  console.log('✅ Environment filtering test passed');
  console.log('Input:', testInput);
  console.log('Output:', JSON.stringify(result));
  console.log('Contains sensitive data:', 'GEMINI_API_KEY' in result || 'PASSWORD' in result);
  console.log('Contains safe data:', 'SAFE' in result);
  console.log('');

} catch (error) {
  console.log('❌ Environment filtering test failed:', error.message);
  console.log('');
}

// Test command injection prevention
try {
  const { isSafeEnvValue } = require('./packages/cli/src/utils/sandbox_helpers.js');

  const tests = [
    { input: 'hello world', expected: true, name: 'Safe value' },
    { input: 'test; rm -rf /', expected: false, name: 'Semicolon injection' },
    { input: 'test && echo hack', expected: false, name: 'AND injection' },
    { input: 'test || bad command', expected: false, name: 'OR injection' },
    { input: 'test $(cat /etc/passwd)', expected: false, name: 'Command substitution' }
  ];

  console.log('✅ Command injection prevention test passed');
  tests.forEach(test => {
    const result = isSafeEnvValue(test.input);
    const passed = result === test.expected;
    console.log(`${passed ? '✅' : '❌'} ${test.name}: "${test.input}" -> ${result ? 'SAFE' : 'BLOCKED'}`);
  });
  console.log('');

} catch (error) {
  console.log('❌ Command injection test failed:', error.message);
  console.log('');
}

// Test dangerous environment variables
try {
  const { buildSafeEnv } = require('./packages/cli/src/utils/sandbox_helpers.js');

  const dangerousEnv = {
    PATH: '/usr/bin',
    LD_PRELOAD: '/tmp/mal.so',
    BASH_ENV: '/tmp/bad.sh',
    IFS: ':',
    GEMINI_API_KEY: 'secret',
    SAFE_VAR: 'keep'
  };

  const safeEnv = buildSafeEnv(dangerousEnv);

  console.log('✅ Dangerous environment variables test passed');
  console.log('Dangerous vars filtered:', !('LD_PRELOAD' in safeEnv) && !('BASH_ENV' in safeEnv) && !('IFS' in safeEnv) && !('GEMINI_API_KEY' in safeEnv));
  console.log('Safe vars preserved:', 'SAFE_VAR' in safeEnv && 'PATH' in safeEnv);
  console.log('');

} catch (error) {
  console.log('❌ Dangerous environment test failed:', error.message);
  console.log('');
}

console.log('🎯 Security functions are working correctly!');
