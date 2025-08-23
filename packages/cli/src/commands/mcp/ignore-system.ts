/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { CommandModule } from 'yargs';
import { SettingScope, loadSettings } from '../../config/settings.js';

interface IgnoreSystemArgs {
  enable?: boolean;
  disable?: boolean;
  scope?: string;
}

export const ignoreSystemCommand: CommandModule<{}, IgnoreSystemArgs> = {
  command: 'ignore-system',
  describe: 'Toggle ignoring system-level MCP server configurations',
  builder: (yargs) =>
    yargs
      .option('enable', {
        type: 'boolean',
        describe: 'Enable ignoring system MCP settings (use only user/workspace settings)',
      })
      .option('disable', {
        type: 'boolean', 
        describe: 'Disable ignoring system MCP settings (allow system override)',
      })
      .option('scope', {
        type: 'string',
        choices: ['user', 'workspace'],
        default: 'user',
        describe: 'Scope for the setting',
      })
      .conflicts('enable', 'disable'),
  handler: async (argv) => {
    const cwd = process.cwd();
    const settings = loadSettings(cwd);

    if (!argv.enable && !argv.disable) {
      // Show current status
      const current = settings.merged.ignoreMCPSystemSettings;
      console.log(`Current status: ${current ? 'ENABLED' : 'DISABLED'}`);
      console.log(
        current 
          ? '✅ System MCP settings are being ignored - using only user/workspace settings'
          : '❌ System MCP settings can override user settings'
      );
      console.log('\nUse --enable or --disable to change this setting.');
      return;
    }

    const scope = argv.scope === 'workspace' ? SettingScope.Workspace : SettingScope.User;
    const newValue = argv.enable ? true : false;

    try {
      settings.setValue(scope, 'ignoreMCPSystemSettings', newValue);
      
      console.log(`✅ Successfully ${newValue ? 'enabled' : 'disabled'} ignoring system MCP settings`);
      console.log(`📍 Scope: ${scope}`);
      console.log(
        newValue
          ? '🔒 Your MCP server configurations will no longer be overridden by system settings'
          : '🔓 System MCP server configurations can now override your settings'
      );
      console.log('\n⚠️  Restart the CLI for changes to take effect.');
    } catch (error) {
      console.error('❌ Failed to update setting:', error);
      process.exit(1);
    }
  },
};
