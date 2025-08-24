/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { CommandModule } from 'yargs';
import {
  securityManager,
  getSecurityReport,
  getSecurityStats,
  switchSecurityProfile,
  assessCommandRisk
} from '../utils/security-manager.js';
import { SecurityProfile } from '../utils/security-profiles.js';

interface SecurityArgs {
  profile?: SecurityProfile;
  stats?: boolean;
  report?: boolean;
  test?: string;
  clear?: boolean;
}

const securityCommand: CommandModule<{}, SecurityArgs> = {
  command: 'security',
  describe: 'Manage security settings and view security information',
  builder: (yargs) =>
    yargs
      .option('profile', {
        alias: 'p',
        describe: 'Switch security profile (beginner, standard, advanced, developer)',
        type: 'string',
        choices: Object.values(SecurityProfile)
      })
      .option('stats', {
        alias: 's',
        describe: 'Show security statistics',
        type: 'boolean'
      })
      .option('report', {
        alias: 'r',
        describe: 'Show detailed security report',
        type: 'boolean'
      })
      .option('test', {
        alias: 't',
        describe: 'Test a command for security risks',
        type: 'string'
      })
      .option('clear', {
        alias: 'c',
        describe: 'Clear security event log',
        type: 'boolean'
      })
      .example('$0 security --profile standard', 'Switch to standard security profile')
      .example('$0 security --stats', 'Show security statistics')
      .example('$0 security --test "rm -rf /"', 'Test command for security risks')
      .example('$0 security --report', 'Show detailed security report'),

  handler: async (argv) => {
    try {
      // Handle profile switching
      if (argv.profile) {
        switchSecurityProfile(argv.profile);
        const config = securityManager.getConfig();
        console.log(`🔒 Security profile switched to: ${config.profile}`);
        console.log(`   Auto-block dangerous: ${config.autoBlockDangerous}`);
        console.log(`   Require confirmation: ${config.requireConfirmation}`);
        console.log(`   Educational mode: ${config.educationalMode}`);
        return;
      }

      // Handle stats display
      if (argv.stats) {
        const stats = getSecurityStats();
        console.log('🔒 Security Statistics:');
        console.log(`   Total Commands Processed: ${stats.totalCommands}`);
        console.log(`   Commands Allowed: ${stats.allowedCommands}`);
        console.log(`   Commands Blocked: ${stats.blockedCommands}`);
        console.log(`   Commands Requiring Confirmation: ${stats.confirmedCommands}`);

        const blockRate = stats.totalCommands > 0
          ? ((stats.blockedCommands / stats.totalCommands) * 100).toFixed(1)
          : '0.0';
        console.log(`   Block Rate: ${blockRate}%`);
        return;
      }

      // Handle report display
      if (argv.report) {
        console.log(getSecurityReport());
        return;
      }

      // Handle command testing
      if (argv.test) {
        const assessment = assessCommandRisk(argv.test);
        const riskEmoji = assessment.risk === 'dangerous' ? '🔴' :
                         assessment.risk === 'medium_risk' ? '🟡' : '🟢';

        console.log(`🔍 Security Assessment for: "${argv.test}"`);
        console.log(`Risk Level: ${riskEmoji} ${assessment.risk.replace('_', ' ').toUpperCase()}`);
        console.log(`Reasoning: ${assessment.reasoning}`);

        if (assessment.blockedPatterns.length > 0) {
          console.log(`Blocked Patterns: ${assessment.blockedPatterns.join(', ')}`);
        }

        if (assessment.suggestions.length > 0) {
          console.log(`💡 Suggestions:`);
          assessment.suggestions.forEach((suggestion, index) => {
            console.log(`   ${index + 1}. ${suggestion}`);
          });
        }
        return;
      }

      // Handle log clearing
      if (argv.clear) {
        securityManager.clearLog();
        console.log('🗑️  Security event log cleared');
        return;
      }

      // Default: show current configuration
      const config = securityManager.getConfig();
      const stats = getSecurityStats();

      console.log('🔒 Gemini CLI Security System');
      console.log('══════════════════════════════');
      console.log(`Current Profile: ${config.profile}`);
      console.log(`Security Enabled: ${config.enabled}`);
      console.log(`Auto-block Dangerous: ${config.autoBlockDangerous}`);
      console.log(`Require Confirmation: ${config.requireConfirmation}`);
      console.log(`Educational Mode: ${config.educationalMode}`);
      console.log(`Security Logging: ${config.logSecurityEvents}`);
      console.log('');
      console.log(`Commands Processed: ${stats.totalCommands}`);
      console.log(`Commands Blocked: ${stats.blockedCommands}`);

      console.log('');
      console.log('📚 Available Commands:');
      console.log('  --profile <type>    Switch security profile');
      console.log('  --stats            Show security statistics');
      console.log('  --report           Show detailed security report');
      console.log('  --test "command"   Test a command for security risks');
      console.log('  --clear            Clear security event log');
      console.log('');
      console.log('🔧 Security Profiles:');
      console.log('  beginner  - Maximum protection, educational feedback');
      console.log('  standard  - Balanced security and usability');
      console.log('  advanced  - Minimal restrictions for power users');
      console.log('  developer - Unrestricted access for development');

    } catch (error) {
      console.error('❌ Security command failed:', error);
      process.exit(1);
    }
  }
};

export default securityCommand;
