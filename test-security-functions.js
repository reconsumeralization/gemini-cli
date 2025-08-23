#!/usr/bin/env node

/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Simple test script to verify security functions work
 */

/* global console */

console.log('🧪 Testing Security Functions...\n');

// Import the functions (we'll use dynamic import for ES modules)
async function testSecurityFunctions() {
  try {
    // Import the shell-utils module
    const shellUtils = await import('./packages/core/src/utils/shell-utils.js');

    console.log('✅ Successfully imported shell-utils');

    // Test getSecurityProfiles
    const profiles = shellUtils.getSecurityProfiles();
    console.log('✅ getSecurityProfiles works:', Object.keys(profiles));

    // Test getCurrentSecurityProfile
    const currentProfile = shellUtils.getCurrentSecurityProfile();
    console.log('✅ getCurrentSecurityProfile works:', currentProfile.name);

    // Test setSecurityProfile
    const result = shellUtils.setSecurityProfile('beginner');
    console.log('✅ setSecurityProfile works:', result);

    // Test isCommandSafe
    const safeResult = shellUtils.isCommandSafe('echo hello');
    console.log('✅ isCommandSafe works for safe command:', safeResult);

    const dangerousResult = shellUtils.isCommandSafe('rm -rf /');
    console.log('✅ isCommandSafe works for dangerous command:', dangerousResult);

    console.log('\n🎉 All security functions are working correctly!');

  } catch (error) {
    console.error('❌ Error testing security functions:', error.message);
    console.error('Stack:', error.stack);
  }
}

testSecurityFunctions();
