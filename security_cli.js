#!/usr/bin/env node

/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Interactive CLI for managing Gemini CLI security settings
 */

/* global console, process */

console.log('🔒 GEMINI CLI SECURITY MANAGEMENT');
console.log('═════════════════════════════════════════════════════════════\n');

/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable no-undef */

const args = process.argv.slice(2);
const command = args[0];

if (!command) {
  showHelp();
  process.exit(0);
}

try {
  const {
    setSecurityProfile,
    showSecurityInfo,
    showSecurityTutorial,
    getSecurityProfiles,
    isCommandAllowed
  } = require('./packages/core/src/utils/shell-utils.ts');

  // Mock config for testing
  const mockConfig = {
    getCoreTools: () => ['ShellTool(echo)', 'ShellTool(ls)'],
    getExcludeTools: () => [],
    getApprovalMode: () => 'default',
    getSessionId: () => `cli-session-${Date.now()}`
  };

  switch (command) {
    case 'info':
      console.log('📊 Current Security Configuration:');
      showSecurityInfo();
      break;

    case 'profiles': {
      console.log('🗂️  Available Security Profiles:');
      const profiles = getSecurityProfiles();
      Object.entries(profiles).forEach(([key, profile]) => {
        console.log(`\n${key.toUpperCase()}: ${profile.name}`);
        console.log(`   ${profile.description}`);
        console.log(`   • Safe Commands: ${profile.allowedCommands.size}`);
        console.log(`   • Risky Commands: ${profile.riskyCommands.size}`);
        console.log(`   • Dangerous Commands: ${profile.dangerousCommands.size}`);
        console.log(`   • Strict Mode: ${profile.strictMode ? 'Yes' : 'No'}`);
        console.log(`   • Education: ${profile.educationMode ? 'Yes' : 'No'}`);
      });
      break;
    }

    case 'set': {
        const profileName = args[1];
      if (!profileName) {
        console.log('❌ Please specify a profile name.');
        console.log('Available profiles: beginner, standard, advanced, developer');
        process.exit(1);
      }

      if (setSecurityProfile(profileName)) {
        console.log(`✅ Security profile changed to: ${profileName}`);
      } else {
        console.log(`❌ Unknown profile: ${profileName}`);
        console.log('Available profiles: beginner, standard, advanced, developer');
        process.exit(1);
      }
      break;
    }

    case 'test': {
      const testCommand = args.slice(1).join(' ');
      if (!testCommand) {
        console.log('❌ Please provide a command to test.');
        console.log('Example: node security_cli.js test "rm -rf /tmp"');
        process.exit(1);
      }

      console.log(`🧪 Testing command: "${testCommand}"`);
      console.log('────────────────────────────────────────');

      const result = isCommandAllowed(testCommand, mockConfig);

      if (result.allowed) {
        if (result.risk === 'medium') {
          console.log('⚠️  MEDIUM RISK - Command allowed with warnings');
          console.log(`📝 Reason: ${result.reason}`);
        } else {
          console.log('✅ LOW RISK - Command safe for execution');
          console.log(`📝 Reason: ${result.reason}`);
        }
      } else {
        console.log('❌ HIGH RISK - Command blocked for security');
        console.log(`🛡️  Reason: ${result.reason}`);
      }

      console.log(`🏷️  Risk Level: ${result.risk?.toUpperCase() || 'UNKNOWN'}`);
      break;
    }
    case 'tutorial':
      showSecurityTutorial();
      break;
    
    case 'logs': {
      const os = require('os');
      const path = require('path');
      const fs = require('fs');

      const logDir = path.join(os.tmpdir(), 'gemini-cli-security');
      console.log(`📁 Security Logs Location: ${logDir}`);

      if (fs.existsSync(logDir)) {
        const files = fs.readdirSync(logDir);
        console.log('📄 Available log files:');
        files.forEach(file => {
          const filePath = path.join(logDir, file);
          const stats = fs.statSync(filePath);
          console.log(`   • ${file} (${Math.round(stats.size / 1024)}KB)`);
        });

        // Show recent security summary if available
        const summaryFile = path.join(logDir, 'security-summary.txt');
        if (fs.existsSync(summaryFile)) {
          console.log('\n📊 Recent Security Activity:');
          const summary = fs.readFileSync(summaryFile, 'utf8');
          const lines = summary.trim().split('\n').slice(-5); // Last 5 entries
          lines.forEach(line => console.log(`   ${line}`));
        }
      } else {
        console.log('📝 No security logs found yet. They will be created when commands are executed.');
      }
      break;
    }
    default:
      console.log(`❌ Unknown command: ${command}`);
      showHelp();
      process.exit(1);
  }

} catch (error) {
  console.error('❌ Error:', error.message);
  process.exit(1);
}

function showHelp() {
  console.log('🔧 GEMINI CLI SECURITY MANAGEMENT COMMANDS:');
  console.log('');
  console.log('📊 info                    - Show current security configuration');
  console.log('🗂️  profiles                - List all available security profiles');
  console.log('⚙️  set <profile>          - Change security profile (beginner|standard|advanced|developer)');
  console.log('🧪 test "<command>"        - Test a command against current security settings');
  console.log('📚 tutorial               - Show security tutorial and best practices');
  console.log('📋 logs                   - Show security logs and activity');
  console.log('');
  console.log('📝 EXAMPLES:');
  console.log('  node security_cli.js info');
  console.log('  node security_cli.js set beginner');
  console.log('  node security_cli.js test "rm -rf /tmp/cache"');
  console.log('  node security_cli.js profiles');
  console.log('');
  console.log('🔒 SECURITY PROFILES:');
  console.log('  • beginner  - Maximum safety, fewest commands');
  console.log('  • standard  - Balanced security (default)');
  console.log('  • advanced  - Relaxed security for power users');
  console.log('  • developer - Permissive for development workflows');
}
