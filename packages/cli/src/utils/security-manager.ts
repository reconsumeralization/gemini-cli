/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Security Manager - Comprehensive Security System for Gemini CLI
 *
 * Implements a 4-tier security model:
 * - Beginner: Maximum protection, educational feedback
 * - Standard: Balanced security and usability
 * - Advanced: Minimal restrictions for power users
 * - Developer: Unrestricted access for development
 */

import { SecurityProfile, CommandRisk, SecurityConfig } from './security-profiles.js';

export interface SecurityEvent {
  timestamp: Date;
  command: string;
  risk: CommandRisk;
  action: 'allowed' | 'blocked' | 'confirmed';
  profile: SecurityProfile;
  reason?: string;
}

export interface CommandAssessment {
  risk: CommandRisk;
  reasoning: string;
  blockedPatterns: string[];
  suggestions: string[];
}

export class SecurityManager {
  private config: SecurityConfig;
  private eventLog: SecurityEvent[] = [];
  private maxLogSize = 1000;

  constructor(profile: SecurityProfile = SecurityProfile.STANDARD) {
    this.config = this.getDefaultConfig(profile);
  }

  /**
   * Assess the security risk of a command
   */
  assessCommand(command: string): CommandAssessment {
    const assessment: CommandAssessment = {
      risk: CommandRisk.SAFE,
      reasoning: 'Command appears safe',
      blockedPatterns: [],
      suggestions: []
    };

    // Check for dangerous patterns
    const dangerousPatterns = [
      { pattern: /rm\s+-rf\s+.*\//, risk: CommandRisk.DANGEROUS, reason: 'Recursive deletion of system directories' },
      { pattern: /dd\s+if=/, risk: CommandRisk.DANGEROUS, reason: 'Disk overwriting operations' },
      { pattern: /mkfs\./, risk: CommandRisk.DANGEROUS, reason: 'Filesystem creation' },
      { pattern: /format\s+/, risk: CommandRisk.DANGEROUS, reason: 'Drive formatting' },
      { pattern: /chmod\s+\+x\s+.*\.(?:exe|bat|cmd|scr|vbs|js|py|pl|php|rb)/, risk: CommandRisk.MEDIUM_RISK, reason: 'Making potentially harmful scripts executable' },
      { pattern: /sudo\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'Superuser operations' },
      { pattern: /curl\s+.*\|\s*(?:bash|sh|zsh)/, risk: CommandRisk.DANGEROUS, reason: 'Download and execute operations' },
      { pattern: /wget\s+.*\|\s*(?:bash|sh|zsh)/, risk: CommandRisk.DANGEROUS, reason: 'Download and execute operations' },
      { pattern: /eval\s+.*\$\(.*\)/, risk: CommandRisk.DANGEROUS, reason: 'Eval with command substitution' },
      { pattern: /chmod\s+777/, risk: CommandRisk.MEDIUM_RISK, reason: 'Dangerous permissions' },
      { pattern: /kill\s+.*-9/, risk: CommandRisk.MEDIUM_RISK, reason: 'Force killing processes' },
      { pattern: /systemctl\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'System service management' },
      { pattern: /mount\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'Mount operations' },
      { pattern: /umount\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'Unmount operations' },
      { pattern: /fdisk\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'Disk partitioning' },
      { pattern: /iptables\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'Firewall rules' },
      { pattern: /sysctl\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'Kernel parameter modification' },
      { pattern: /modprobe\s+/, risk: CommandRisk.MEDIUM_RISK, reason: 'Kernel module loading' }
    ];

    for (const { pattern, risk, reason } of dangerousPatterns) {
      if (pattern.test(command)) {
        assessment.blockedPatterns.push(pattern.source);
        if (risk === CommandRisk.DANGEROUS) {
          assessment.risk = CommandRisk.DANGEROUS;
          assessment.reasoning = reason;
          break;
        } else if (risk === CommandRisk.MEDIUM_RISK && assessment.risk !== CommandRisk.DANGEROUS) {
          assessment.risk = CommandRisk.MEDIUM_RISK;
          assessment.reasoning = reason;
        }
      }
    }

    // Generate suggestions based on risk
    if (assessment.risk === CommandRisk.DANGEROUS) {
      assessment.suggestions = [
        'Consider using safer alternatives like `rm -i` for interactive deletion',
        'Use `ls` or `find` to verify paths before deletion',
        'Create backups before destructive operations',
        'Consider using version control or snapshots'
      ];
    } else if (assessment.risk === CommandRisk.MEDIUM_RISK) {
      assessment.suggestions = [
        'Use `ls -la` to verify file permissions before changes',
        'Consider using `sudo -l` to see allowed commands',
        'Use `which` to verify command paths',
        'Consider non-destructive alternatives'
      ];
    }

    return assessment;
  }

  /**
   * Check if a command should be allowed based on current security profile
   */
  async checkCommand(command: string): Promise<{ allowed: boolean; reason?: string; suggestions?: string[] }> {
    if (this.config.profile === SecurityProfile.DEVELOPER) {
      this.logEvent(command, CommandRisk.SAFE, 'allowed', 'Developer mode - unrestricted');
      return { allowed: true };
    }

    const assessment = this.assessCommand(command);

    // Auto-block dangerous commands if configured
    if (assessment.risk === CommandRisk.DANGEROUS && this.config.autoBlockDangerous) {
      this.logEvent(command, assessment.risk, 'blocked', assessment.reasoning);
      return {
        allowed: false,
        reason: assessment.reasoning,
        suggestions: assessment.suggestions
      };
    }

    // Require confirmation for medium-risk commands if configured
    if (assessment.risk === CommandRisk.MEDIUM_RISK && this.config.requireConfirmation) {
      this.logEvent(command, assessment.risk, 'confirmed', assessment.reasoning);
      return {
        allowed: false, // Will be handled by caller for confirmation
        reason: assessment.reasoning,
        suggestions: assessment.suggestions
      };
    }

    this.logEvent(command, assessment.risk, 'allowed', assessment.reasoning);
    return { allowed: true };
  }

  /**
   * Switch security profile
   */
  switchProfile(profile: SecurityProfile): void {
    this.config = this.getDefaultConfig(profile);
    console.log(`🔒 Security profile switched to: ${profile}`);
  }

  /**
   * Get current security configuration
   */
  getConfig(): SecurityConfig {
    return { ...this.config };
  }

  /**
   * Get security event log
   */
  getEventLog(): SecurityEvent[] {
    return [...this.eventLog];
  }

  /**
   * Clear security event log
   */
  clearLog(): void {
    this.eventLog = [];
  }

  /**
   * Get security statistics
   */
  getStats(): {
    totalCommands: number;
    blockedCommands: number;
    confirmedCommands: number;
    allowedCommands: number;
  } {
    const totalCommands = this.eventLog.length;
    const blockedCommands = this.eventLog.filter(e => e.action === 'blocked').length;
    const confirmedCommands = this.eventLog.filter(e => e.action === 'confirmed').length;
    const allowedCommands = this.eventLog.filter(e => e.action === 'allowed').length;

    return {
      totalCommands,
      blockedCommands,
      confirmedCommands,
      allowedCommands
    };
  }

  /**
   * Generate security report
   */
  generateReport(): string {
    const stats = this.getStats();
    const recentEvents = this.eventLog.slice(-10);

    let report = `
🔒 Security Report - ${this.config.profile} Profile
═══════════════════════════════════════════════════

📊 Statistics:
• Total Commands Processed: ${stats.totalCommands}
• Commands Allowed: ${stats.allowedCommands}
• Commands Blocked: ${stats.blockedCommands}
• Commands Requiring Confirmation: ${stats.confirmedCommands}

⚙️  Current Configuration:
• Auto-block Dangerous: ${this.config.autoBlockDangerous}
• Require Confirmation: ${this.config.requireConfirmation}
• Educational Mode: ${this.config.educationalMode}
• Security Logging: ${this.config.logSecurityEvents}

📋 Recent Activity:
`;

    recentEvents.forEach((event, index) => {
      const action = event.action === 'allowed' ? '✅' :
                    event.action === 'blocked' ? '❌' : '⚠️';
      const risk = event.risk === CommandRisk.DANGEROUS ? '🔴' :
                  event.risk === CommandRisk.MEDIUM_RISK ? '🟡' : '🟢';
      report += `${index + 1}. ${action} ${risk} ${event.command}\n`;
      if (event.reason) {
        report += `   Reason: ${event.reason}\n`;
      }
    });

    return report;
  }

  private getDefaultConfig(profile: SecurityProfile): SecurityConfig {
    const configs: Record<SecurityProfile, SecurityConfig> = {
      [SecurityProfile.BEGINNER]: {
        profile: SecurityProfile.BEGINNER,
        enabled: true,
        autoBlockDangerous: true,
        requireConfirmation: true,
        educationalMode: true,
        logSecurityEvents: true
      },
      [SecurityProfile.STANDARD]: {
        profile: SecurityProfile.STANDARD,
        enabled: true,
        autoBlockDangerous: true,
        requireConfirmation: false,
        educationalMode: false,
        logSecurityEvents: true
      },
      [SecurityProfile.ADVANCED]: {
        profile: SecurityProfile.ADVANCED,
        enabled: true,
        autoBlockDangerous: false,
        requireConfirmation: false,
        educationalMode: false,
        logSecurityEvents: false
      },
      [SecurityProfile.DEVELOPER]: {
        profile: SecurityProfile.DEVELOPER,
        enabled: false,
        autoBlockDangerous: false,
        requireConfirmation: false,
        educationalMode: false,
        logSecurityEvents: false
      }
    };

    return configs[profile];
  }

  private logEvent(command: string, risk: CommandRisk, action: 'allowed' | 'blocked' | 'confirmed', reason?: string): void {
    const event: SecurityEvent = {
      timestamp: new Date(),
      command,
      risk,
      action,
      profile: this.config.profile,
      reason
    };

    this.eventLog.push(event);

    // Maintain max log size
    if (this.eventLog.length > this.maxLogSize) {
      this.eventLog = this.eventLog.slice(-this.maxLogSize);
    }
  }
}

// Export singleton instance
export const securityManager = new SecurityManager();

// Export utility functions
export function assessCommandRisk(command: string): CommandAssessment {
  return securityManager.assessCommand(command);
}

export function checkCommandSecurity(command: string): Promise<{ allowed: boolean; reason?: string; suggestions?: string[] }> {
  return securityManager.checkCommand(command);
}

export function switchSecurityProfile(profile: SecurityProfile): void {
  securityManager.switchProfile(profile);
}

export function getSecurityReport(): string {
  return securityManager.generateReport();
}

export function getSecurityStats(): {
  totalCommands: number;
  blockedCommands: number;
  confirmedCommands: number;
  allowedCommands: number;
} {
  return securityManager.getStats();
}
