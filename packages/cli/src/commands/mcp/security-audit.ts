/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { CommandModule } from 'yargs';
import { loadSettings, getSystemSettingsPath, SettingScope } from '../../config/settings.js';
import * as fs from 'fs';
import * as path from 'path';

interface SecurityAuditArgs {
  fix?: boolean;
  backup?: boolean;
  verbose?: boolean;
}

// Suspicious patterns that might indicate malicious MCP servers
const SUSPICIOUS_PATTERNS = [
  /eval\s*\(/i,
  /exec\s*\(/i,
  /spawn\s*\(/i,
  /child_process/i,
  /require\s*\(/i,
  /import\s*\(/i,
  /\.exe/i,
  /\.bat/i,
  /\.sh/i,
  /curl\s+http/i,
  /wget\s+http/i,
  /powershell/i,
  /cmd\s*\/c/i,
  /bash\s*-c/i,
  /python\s*-c/i,
  /node\s*-e/i,
  /npm\s+run/i,
  /yarn\s+run/i,
];

// Known malicious MCP server names or patterns
const MALICIOUS_INDICATORS = [
  'malware',
  'backdoor',
  'keylogger',
  'spyware',
  'trojan',
  'virus',
  'hack',
  'exploit',
  'payload',
  'reverse-shell',
  'bind-shell',
  'meterpreter',
  'beacon',
  'c2',
  'command-control',
];

export const securityAuditCommand: CommandModule<object, SecurityAuditArgs> = {
  command: 'security-audit',
  describe: 'Audit MCP server configurations for security threats',
  builder: (yargs) =>
    yargs
      .option('fix', {
        type: 'boolean',
        describe: 'Automatically fix detected issues by enabling ignoreMCPSystemSettings',
      })
      .option('backup', {
        type: 'boolean',
        describe: 'Create backup of current settings before making changes',
      })
      .option('verbose', {
        type: 'boolean',
        describe: 'Show detailed information about detected issues',
      }),
  handler: async (argv) => {
    const cwd = process.cwd();
    const settings = loadSettings(cwd);
    const systemSettingsPath = getSystemSettingsPath();
    
    console.log('🔍 **MCP Security Audit**\n');
    
    // Check if system settings file exists
    const systemFileExists = fs.existsSync(systemSettingsPath);
    console.log(`📍 System settings path: ${systemSettingsPath}`);
    console.log(`📁 System file exists: ${systemFileExists ? '❌ YES' : '✅ NO'}`);
    
    if (!systemFileExists) {
      console.log('\n✅ **No system settings file detected - you are safe!**');
      return;
    }
    
    // Analyze system settings for threats
    const threats = await analyzeSystemSettings(systemSettingsPath, argv.verbose);
    
    if (threats.length === 0) {
      console.log('\n✅ **No security threats detected in system settings**');
      return;
    }
    
    // Report threats
    console.log(`\n🚨 **SECURITY THREATS DETECTED: ${threats.length}**\n`);
    
    threats.forEach((threat, index) => {
      console.log(`${index + 1}. **${threat.severity.toUpperCase()}**: ${threat.description}`);
      if (argv.verbose && threat.details) {
        console.log(`   Details: ${threat.details}`);
      }
      if (threat.recommendation) {
        console.log(`   Recommendation: ${threat.recommendation}`);
      }
      console.log('');
    });
    
    // Provide immediate protection
    console.log('🛡️ **IMMEDIATE PROTECTION OPTIONS:**\n');
    
    if (argv.fix) {
      console.log('🔧 **Applying automatic fix...**');
      
      if (argv.backup) {
        await createBackup(settings);
      }
      
      // Enable ignoreMCPSystemSettings to block malicious system settings
      try {
        settings.setValue(SettingScope.User, 'ignoreMCPSystemSettings', true);
        console.log('✅ **Successfully enabled ignoreMCPSystemSettings**');
        console.log('🔒 **System MCP settings are now blocked**');
        console.log('⚠️  **Restart the CLI for changes to take effect**');
      } catch (error) {
        console.error('❌ **Failed to apply fix:', error);
        process.exit(1);
      }
    } else {
      console.log('1. **Enable protection immediately:**');
      console.log('   gemini mcp security-audit --fix');
      console.log('');
      console.log('2. **Enable protection with backup:**');
      console.log('   gemini mcp security-audit --fix --backup');
      console.log('');
      console.log('3. **Manual protection:**');
      console.log('   gemini mcp ignore-system --enable');
      console.log('');
      console.log('4. **Remove malicious system file (requires admin):**');
      console.log(`   rm "${systemSettingsPath}"`);
      console.log('');
    }
    
    // Additional security recommendations
    console.log('🔒 **SECURITY RECOMMENDATIONS:**\n');
    console.log('• Review the system settings file manually');
    console.log('• Check system logs for unauthorized access');
    console.log('• Update your system and security software');
    console.log('• Consider running a full system security scan');
    console.log('• Monitor for unusual network activity');
    console.log('• Change passwords if suspicious activity detected');
  },
};

interface SecurityThreat {
  severity: 'high' | 'medium' | 'low';
  description: string;
  details?: string;
  recommendation?: string;
}

async function analyzeSystemSettings(systemPath: string, _verbose: boolean = false): Promise<SecurityThreat[]> {
  const threats: SecurityThreat[] = [];
  
  try {
    const content = fs.readFileSync(systemPath, 'utf-8');
    const settings = JSON.parse(content);
    
    // Check for MCP servers
    if (settings.mcpServers && typeof settings.mcpServers === 'object') {
      const mcpServers = settings.mcpServers;
      
      for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
        const config = serverConfig as Record<string, unknown>;
        
        // Check server name for malicious indicators
        const suspiciousName = MALICIOUS_INDICATORS.some(indicator => 
          serverName.toLowerCase().includes(indicator.toLowerCase())
        );
        
        if (suspiciousName) {
          threats.push({
            severity: 'high',
            description: `Suspicious MCP server name: "${serverName}"`,
            details: `Server name contains potentially malicious keywords`,
            recommendation: 'Remove or rename this server configuration'
          });
        }
        
        // Check command for suspicious patterns
        if (config['command'] && typeof config['command'] === 'string') {
          const suspiciousCommand = SUSPICIOUS_PATTERNS.some(pattern => 
            pattern.test(config['command'] as string)
          );
          
          if (suspiciousCommand) {
            threats.push({
              severity: 'high',
              description: `Suspicious command in MCP server "${serverName}"`,
              details: `Command: ${config['command']}`,
              recommendation: 'Review and remove this server configuration'
            });
          }
        }
        
        // Check for suspicious URLs
        if (config['url'] && typeof config['url'] === 'string') {
          const url = (config['url'] as string).toLowerCase();
          if (url.includes('http://') || url.includes('https://')) {
            // Check for suspicious domains or IPs
            if (url.includes('localhost') || url.includes('127.0.0.1') || url.includes('0.0.0.0')) {
              threats.push({
                severity: 'medium',
                description: `MCP server "${serverName}" connects to localhost`,
                details: `URL: ${config['url']}`,
                recommendation: 'Review if this local connection is legitimate'
              });
            }
          }
        }
        
        // Check for suspicious environment variables
        if (config['env'] && typeof config['env'] === 'object') {
          const envVars = Object.keys(config['env'] as Record<string, unknown>);
          const suspiciousEnvVars = envVars.filter(envVar => 
            envVar.toLowerCase().includes('key') || 
            envVar.toLowerCase().includes('token') ||
            envVar.toLowerCase().includes('secret') ||
            envVar.toLowerCase().includes('password')
          );
          
          if (suspiciousEnvVars.length > 0) {
            threats.push({
              severity: 'medium',
              description: `MCP server "${serverName}" has suspicious environment variables`,
              details: `Variables: ${suspiciousEnvVars.join(', ')}`,
              recommendation: 'Review if these environment variables are necessary'
            });
          }
        }
      }
    }
    
    // Check for other suspicious settings
    if (settings.allowMCPServers && Array.isArray(settings.allowMCPServers)) {
      const suspiciousAllowed = settings.allowMCPServers.filter((server: string) => 
        MALICIOUS_INDICATORS.some(indicator => 
          server.toLowerCase().includes(indicator.toLowerCase())
        )
      );
      
      if (suspiciousAllowed.length > 0) {
        threats.push({
          severity: 'high',
          description: 'Suspicious servers in allowMCPServers list',
          details: `Servers: ${suspiciousAllowed.join(', ')}`,
          recommendation: 'Remove suspicious servers from allowlist'
        });
      }
    }
    
    // Check file permissions (Unix-like systems)
    if (process.platform !== 'win32') {
      try {
        const stats = fs.statSync(systemPath);
        const mode = stats.mode & 0o777;
        
        if (mode & 0o002) { // World writable
          threats.push({
            severity: 'high',
            description: 'System settings file is world-writable',
            details: `File permissions: ${mode.toString(8)}`,
            recommendation: 'Change file permissions to 644 or 600'
          });
        }
      } catch (_error) {
        // Ignore permission errors
      }
    }
    
  } catch (error) {
    threats.push({
      severity: 'medium',
      description: 'Unable to parse system settings file',
      details: `Error: ${error}`,
      recommendation: 'Check file format and permissions'
    });
  }
  
  return threats;
}

async function createBackup(settings: { user: { settings: unknown }; workspace: { settings: unknown }; system: { settings: unknown } }): Promise<void> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = path.join(process.cwd(), `.gemini-settings-backup-${timestamp}.json`);
  
  try {
    const backupData = {
      timestamp: new Date().toISOString(),
      userSettings: settings.user.settings,
      workspaceSettings: settings.workspace.settings,
      systemSettings: settings.system.settings,
    };
    
    fs.writeFileSync(backupPath, JSON.stringify(backupData, null, 2));
    console.log(`✅ **Backup created:** ${backupPath}`);
  } catch (error) {
    console.error('❌ **Failed to create backup:', error);
  }
}
