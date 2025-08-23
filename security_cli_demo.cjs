#!/usr/bin/env node

/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Interactive CLI for demonstrating Gemini CLI security features
 */

/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable no-undef */

const fs = require('fs');
const path = require('path');

console.log('🔒 GEMINI CLI SECURITY MANAGEMENT');
console.log('═════════════════════════════════════════════════════════════\n');

const args = process.argv.slice(2);
const command = args[0];

if (!command) {
  showHelp();
  process.exit(0);
}

try {
  // Mock security functions based on the implementation
  function mockIsCommandAllowed(command) {
    const dangerousCommands = ['rm', 'sudo', 'chmod', 'eval', 'exec'];
    const hasDangerous = dangerousCommands.some(cmd => command.includes(cmd));

    if (hasDangerous) {
      return {
        allowed: false,
        reason: 'Command contains dangerous operations',
        risk: 'high'
      };
    }

    const mediumRiskCommands = ['cp', 'mv', 'curl', 'wget'];
    const hasMediumRisk = mediumRiskCommands.some(cmd => command.includes(cmd));

    if (hasMediumRisk) {
      return {
        allowed: true,
        reason: 'Command has potential risks but is generally safe',
        risk: 'medium'
      };
    }

    return {
      allowed: true,
      reason: 'Command appears safe for execution',
      risk: 'low'
    };
  }

  function showSecurityInfo() {
    console.log('🔒 Security Profile: Standard (Default)');
    console.log('⚡ Risk Tolerance: Balanced security');
    console.log('📚 Education Level: Helpful guidance');
    console.log('🚫 Blocked Commands: rm, sudo, chmod, eval, exec');
    console.log('⚠️  Medium Risk Commands: cp, mv, curl, wget');
    console.log('✅ Safe Commands: echo, ls, cat, pwd, git, npm, node');
    console.log('📊 Commands Allowed: ~40 common commands');
    console.log('🛡️  Injection Protection: Active');
    console.log('🔐 Environment Filtering: Active');
  }

  function showSecurityTutorial() {
    console.log('📚 SECURITY TUTORIAL');
    console.log('═════════════════════════════════════════════════════════════\n');

    console.log('1. 🔒 Understanding Security Profiles:');
    console.log('   • Beginner: Maximum safety, few commands');
    console.log('   • Standard: Balanced (recommended)');
    console.log('   • Advanced: More permissive');
    console.log('   • Developer: Full development access\n');

    console.log('2. 🛡️ Safe Commands (Always Allowed):');
    console.log('   • echo, ls, cat, pwd, whoami, date');
    console.log('   • git status, npm list, node --version\n');

    console.log('3. ⚠️ Medium Risk Commands (Warnings):');
    console.log('   • cp, mv, curl, wget');
    console.log('   • Shows warnings but still executes\n');

    console.log('4. 🚫 Dangerous Commands (Blocked):');
    console.log('   • rm, sudo, chmod, eval, exec');
    console.log('   • Completely blocked for security\n');

    console.log('5. 💡 Best Practices:');
    console.log('   • Use Standard profile for daily work');
    console.log('   • Test commands with "security_cli test"');
    console.log('   • Learn from security warnings');
    console.log('   • Switch to Developer for development tasks\n');

    console.log('6. 🎯 YOLO Mode is Now Safe:');
    console.log('   • Previously: Any command executed');
    console.log('   • Now: Intelligent safety controls');
    console.log('   • Dangerous commands still blocked');
    console.log('   • Educational feedback provided');
  }

  function setSecurityProfile(profile) {
    const profiles = ['beginner', 'standard', 'advanced', 'developer'];
    if (!profiles.includes(profile)) {
      console.log(`❌ Invalid profile: ${profile}`);
      console.log(`Available profiles: ${profiles.join(', ')}`);
      return;
    }
    console.log(`✅ Security profile set to: ${profile}`);
    console.log('📝 Profile changes take effect immediately');
  }

  function testCommand(cmd) {
    if (!cmd) {
      console.log('❌ Please provide a command to test');
      console.log('Example: node security_cli.js test "rm -rf /tmp"');
      return;
    }

    console.log(`🧪 Testing command: "${cmd}"`);
    const result = mockIsCommandAllowed(cmd, {});

    console.log(`\n📊 Test Results:`);
    console.log(`   Allowed: ${result.allowed ? '✅ YES' : '❌ NO'}`);
    console.log(`   Risk Level: ${result.risk.toUpperCase()}`);
    console.log(`   Reason: ${result.reason}`);

    if (!result.allowed) {
      console.log(`\n💡 Safe Alternatives:`);
      if (cmd.includes('rm')) {
        console.log(`   • Use: rm -i (interactive mode)`);
        console.log(`   • Use: trash-cli for recoverable deletion`);
        console.log(`   • Use: git rm for version-controlled files`);
      } else if (cmd.includes('sudo')) {
        console.log(`   • Use: Regular user permissions`);
        console.log(`   • Use: Docker for isolated operations`);
        console.log(`   • Ask system administrator for help`);
      } else {
        console.log(`   • Use safer alternatives`);
        console.log(`   • Check command documentation`);
        console.log(`   • Test with less privileged access`);
      }
    }
  }

  function showLogs() {
    const logDir = path.join(require('os').tmpdir(), 'gemini-cli-security');
    console.log(`📋 Security Logs Location: ${logDir}`);

    if (fs.existsSync(logDir)) {
      const files = fs.readdirSync(logDir);
      if (files.length > 0) {
        console.log('📄 Available log files:');
        files.forEach(file => console.log(`   • ${file}`));
      } else {
        console.log('📭 No log files found');
      }
    } else {
      console.log('📭 Log directory does not exist yet');
      console.log('   Logs will be created when commands are executed');
    }
  }

  // Note: mockConfig was removed as it was unused

  switch (command) {
    case 'info':
      console.log('📊 Current Security Configuration:');
      showSecurityInfo();
      break;

    case 'set': {
      const profile = args[1];
      setSecurityProfile(profile);
      break;
    }

    case 'test': {
      const testCmd = args.slice(1).join(' ');
      testCommand(testCmd);
      break;
    }

    case 'logs':
      showLogs();
      break;

    case 'tutorial':
      showSecurityTutorial();
      break;

    case 'profiles':
      console.log('👥 Available Security Profiles:');
      console.log('   🛡️  beginner - Maximum safety, few commands');
      console.log('   ⚖️  standard - Balanced security (recommended)');
      console.log('   🔧 advanced - More permissive, some warnings');
      console.log('   💻 developer - Full development access');
      break;

    default:
      console.log(`❌ Unknown command: ${command}`);
      showHelp();
      break;
  }

} catch (error) {
  console.log(`❌ Error: ${error.message}`);
  console.log('🔧 This demo shows the security features that would be available');
}

function showHelp() {
  console.log('💡 Available Commands:');
  console.log('   info              - Show current security configuration');
  console.log('   set <profile>     - Set security profile (beginner|standard|advanced|developer)');
  console.log('   test "<command>"  - Test a command against security rules');
  console.log('   logs              - Show security log information');
  console.log('   tutorial          - Show security tutorial');
  console.log('   profiles          - List available security profiles');
  console.log('');
  console.log('📚 Examples:');
  console.log('   node security_cli_demo.cjs info');
  console.log('   node security_cli_demo.cjs set standard');
  console.log('   node security_cli_demo.cjs test "rm -rf /tmp"');
  console.log('   node security_cli_demo.cjs tutorial');
}
