#!/usr/bin/env node

/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Demonstration of the Enhanced Security System with User Profiles
 */

/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable no-undef */

console.log('🚀 GEMINI CLI ENHANCED SECURITY SYSTEM DEMO');
console.log('═════════════════════════════════════════════════════════════\n');

try {
  const {
    setSecurityProfile,
    showSecurityInfo,
    showSecurityTutorial,
    isCommandAllowed
  } = require('./packages/core/src/utils/shell-utils.ts');

  // Mock config for testing
  const mockConfig = {
    getCoreTools: () => ['ShellTool(echo)', 'ShellTool(ls)'],
    getExcludeTools: () => [],
    getApprovalMode: () => 'yolo',
    getSessionId: () => 'demo-session-123'
  };

  console.log('📋 DEMONSTRATION SCENARIOS:');
  console.log('═════════════════════════════════════════════════════════════\n');

  // Scenario 1: Default Standard Profile
  console.log('1️⃣  DEFAULT STANDARD PROFILE (Balanced Security):');
  console.log('──────────────────────────────────────────────────');

  const testCommands = [
    'echo "Hello World"',    // Safe - should pass
    'ls -la',                // Safe - should pass
    'rm -rf /tmp/cache',     // Dangerous - should block
    'cp file1.txt file2.txt', // Risky - should warn
    'curl https://api.example.com', // Risky - should warn
  ];

  testCommands.forEach(cmd => {
    const result = isCommandAllowed(cmd, mockConfig);
    const status = result.allowed ?
      (result.risk === 'medium' ? '⚠️  ALLOWED WITH WARNING' : '✅ ALLOWED') :
      '❌ BLOCKED';
    console.log(`   ${status} - ${cmd}`);
  });

  console.log('\n2️⃣  SWITCHING TO BEGINNER PROFILE (Maximum Safety):');
  console.log('─────────────────────────────────────────────────────');

  setSecurityProfile('beginner');

  const beginnerCommands = [
    'echo "Hello"',         // Safe - should pass
    'ls',                    // Safe - should pass
    'cat file.txt',          // Not in beginner allowlist - should block
    'rm file.txt',           // Dangerous - should block
    'curl api.com',          // Not in beginner allowlist - should block
  ];

  beginnerCommands.forEach(cmd => {
    const result = isCommandAllowed(cmd, mockConfig);
    const status = result.allowed ?
      (result.risk === 'medium' ? '⚠️  ALLOWED WITH WARNING' : '✅ ALLOWED') :
      '❌ BLOCKED';
    console.log(`   ${status} - ${cmd}`);
  });

  console.log('\n3️⃣  SWITCHING TO DEVELOPER PROFILE (Permissive):');
  console.log('──────────────────────────────────────────────────');

  setSecurityProfile('developer');

  const developerCommands = [
    'echo "Building project"',  // Safe - should pass
    'npm install',              // Safe - should pass
    'git push origin main',     // Safe - should pass
    'docker build .',           // Safe - should pass
    'rm -rf node_modules',      // Risky - should warn
    'sudo npm install -g',      // Dangerous - should block
  ];

  developerCommands.forEach(cmd => {
    const result = isCommandAllowed(cmd, mockConfig);
    const status = result.allowed ?
      (result.risk === 'medium' ? '⚠️  ALLOWED WITH WARNING' : '✅ ALLOWED') :
      '❌ BLOCKED';
    console.log(`   ${status} - ${cmd}`);
  });

  console.log('\n4️⃣  SECURITY INFORMATION DISPLAY:');
  console.log('────────────────────────────────────');

  // Show current security profile information
  showSecurityInfo();

  console.log('\n5️⃣  SECURITY TUTORIAL:');
  console.log('─────────────────────────');

  showSecurityTutorial();

  console.log('\n🎯 KEY BENEFITS OF THE ENHANCED SYSTEM:');
  console.log('═════════════════════════════════════════════════════════════');
  console.log('✅ USER EDUCATION: Blocked commands provide helpful alternatives');
  console.log('✅ PROFILE CUSTOMIZATION: Different security levels for different users');
  console.log('✅ RISK-BASED WARNINGS: Medium-risk commands show warnings, not blocks');
  console.log('✅ COMPREHENSIVE LOGGING: Full audit trail for security monitoring');
  console.log('✅ BACKWARD COMPATIBILITY: Existing workflows continue to work');
  console.log('✅ FLEXIBLE SECURITY: Users can adjust security based on their needs');
  console.log('✅ EDUCATIONAL FEEDBACK: Users learn safer command alternatives');
  console.log('✅ AUTOMATION PRESERVED: YOLO mode works but with safety controls');

  console.log('\n🔒 SECURITY COMPARISON:');
  console.log('═════════════════════════════════════════════════════════════');
  console.log('BEFORE: YOLO mode = execute ANY command without checks');
  console.log('AFTER:  YOLO mode = execute SAFE commands, warn on RISKY, block DANGEROUS');
  console.log('');
  console.log('BEFORE: All-or-nothing security approach');
  console.log('AFTER:  Granular, profile-based security with education');

  console.log('\n🎉 ENHANCED SECURITY SYSTEM DEMO COMPLETE!');
  console.log('═════════════════════════════════════════════════════════════');

} catch (error) {
  console.error('❌ Demo failed:', error.message);
  console.error('This might indicate an issue with the security implementation.');
}
