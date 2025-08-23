/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Interactive CLI for managing Gemini CLI security settings
 */

import {
  isCommandSafe,
  getSecurityProfiles,
  getCurrentSecurityProfile,
  setSecurityProfile
} from './packages/core/src/utils/shell-utils.js';

/**
 * Display current security configuration
 */
export function showSecurityInfo(): void {
  const profile = getCurrentSecurityProfile();

  console.log('🔒 Security Profile:', `${profile.name} (${profile.description})`);
  console.log('⚡ Risk Tolerance:', profile.strictMode ? 'Strict' : 'Balanced');
  console.log('📚 Education Level:', profile.educationMode ? 'Enabled' : 'Disabled');
  console.log('🚫 Blocked Commands:', profile.dangerousCommands.size);
  console.log('⚠️  Medium Risk Commands:', profile.riskyCommands.size);
  console.log('✅ Safe Commands:', profile.allowedCommands.size);
  console.log('📊 Commands Allowed:', '~40 common commands');
  console.log('🛡️  Injection Protection:', 'Active');
  console.log('🔐 Environment Filtering:', 'Active');
  console.log('📝 Log Level:', profile.logLevel);
}

/**
 * Display security tutorial
 */
export function showSecurityTutorial(): void {
  console.log('📚 SECURITY TUTORIAL');
  console.log('═════════════════════════════════════════════════════════════\n');

  console.log('1. 🔒 Understanding Security Profiles:');
  console.log('   • Beginner: Maximum safety, few commands');
  console.log('   • Standard: Balanced (recommended)');
  console.log('   • Advanced: More permissive, some warnings');
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

/**
 * Switch security profile
 */
export function changeSecurityProfile(profileName: string): boolean {
  const profiles = getSecurityProfiles();
  const profile = profiles[profileName as keyof typeof profiles];

  if (!profile) {
    console.log(`❌ Invalid profile: ${profileName}`);
    console.log(`Available profiles: ${Object.keys(profiles).join(', ')}`);
    return false;
  }

  const result = setSecurityProfile(profileName as keyof typeof profiles);
  if (result) {
    console.log(`✅ Security profile set to: ${profile.name}`);
    console.log('📝 Profile changes take effect immediately');
  } else {
    console.log(`❌ Failed to set security profile to: ${profileName}`);
  }

  return result;
}

/**
 * Test a command against security rules
 */
export function testCommandSecurity(command: string): void {
  if (!command) {
    console.log('❌ Please provide a command to test');
    console.log('Example: node security_cli.js test "rm -rf /"');
    return;
  }

  console.log(`🧪 Testing command: "${command}"`);
  const result = isCommandSafe(command);

  console.log(`\n📊 Test Results:`);
  console.log(`   Allowed: ${result.safe ? '✅ YES' : '❌ NO'}`);
  console.log(`   Risk Level: ${result.risk?.toUpperCase() || 'UNKNOWN'}`);

  if (result.reason) {
    console.log(`   Reason: ${result.reason}`);
  }

  if (!result.safe) {
    console.log(`\n💡 Safe Alternatives:`);
    if (command.includes('rm')) {
      console.log(`   • Use: rm -i (interactive mode)`);
      console.log(`   • Use: trash-cli for recoverable deletion`);
      console.log(`   • Use: git rm for version-controlled files`);
    } else if (command.includes('sudo')) {
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

/**
 * Show security log information
 */
export function showSecurityLogs(): void {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const fs = require('fs');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const path = require('path');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const os = require('os');

  const logDir = path.join(os.tmpdir(), 'gemini-cli-security');
  console.log(`📋 Security Logs Location: ${logDir}`);

  if (fs.existsSync(logDir)) {
    try {
      const files = fs.readdirSync(logDir);
      if (files.length > 0) {
        console.log('📄 Available log files:');
        files.forEach((file: string) => console.log(`   • ${file}`));
      } else {
        console.log('📭 No log files found');
      }
    } catch (error) {
      console.log('❌ Error reading log directory:', error instanceof Error ? error.message : 'Unknown error');
    }
  } else {
    console.log('📭 Log directory does not exist yet');
    console.log('   Logs will be created when commands are executed');
  }
}

/**
 * List available security profiles
 */
export function listSecurityProfiles(): void {
  const profiles = getSecurityProfiles();

  console.log('👥 Available Security Profiles:');
  Object.entries(profiles).forEach(([key, profile]) => {
    const icon = key === 'beginner' ? '🛡️' : key === 'standard' ? '⚖️' : key === 'advanced' ? '🔧' : '💻';
    console.log(`   ${icon} ${profile.name} - ${profile.description}`);
  });
}

/**
 * Main CLI handler
 */
export function handleSecurityCommand(args: string[]): void {
  const command = args[0];

  if (!command) {
    showHelp();
    return;
  }

  try {
    switch (command) {
      case 'info':
        showSecurityInfo();
        break;
      case 'set': {
        const profile = args[1] as string;
        if (!profile) {
          console.log('❌ Please specify a profile name');
          console.log('Example: node security-cli.js set beginner');
          return;
        }
        changeSecurityProfile(profile);
        break;
      }
      case 'test': {
        const testCmd = args.slice(1).join(' ') as string;
        testCommandSecurity(testCmd);
        break;
      }
      case 'logs': {
        showSecurityLogs();
        break;
      }
      case 'tutorial':
        showSecurityTutorial();
        break;

      case 'profiles':
        listSecurityProfiles();
        break;

      default:
        console.log(`❌ Unknown command: ${command}`);
        showHelp();
        break;
    }
  } catch (error) {
    console.error(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Show help information
 */
function showHelp(): void {
  console.log('💡 Available Commands:');
  console.log('   info              - Show current security configuration');
  console.log('   set <profile>     - Set security profile (beginner|standard|advanced|developer)');
  console.log('   test "<command>"  - Test a command against security rules');
  console.log('   logs              - Show security log information');
  console.log('   tutorial          - Show security tutorial');
  console.log('   profiles          - List available security profiles');
  console.log('');
  console.log('📚 Examples:');
  console.log('   node security-cli.js info');
  console.log('   node security-cli.js set standard');
  console.log('   node security-cli.js test "rm -rf /tmp"');
  console.log('   node security-cli.js tutorial');
}
