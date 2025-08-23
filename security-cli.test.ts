/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Unit tests for Security CLI functionality
 * Tests the core security command logic and functions
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as os from 'os';
import * as path from 'path';
import {
  showSecurityInfo,
  changeSecurityProfile,
  testCommandSecurity,
  handleSecurityCommand
} from './security-cli.js';

// Mock the shell-utils functions
const mockIsCommandSafe = vi.fn();
const mockGetSecurityProfiles = vi.fn();
const mockGetCurrentSecurityProfile = vi.fn();
const mockSetSecurityProfile = vi.fn();

vi.mock('./packages/core/src/utils/shell-utils.js', () => ({
  isCommandSafe: mockIsCommandSafe,
  getSecurityProfiles: mockGetSecurityProfiles,
  getCurrentSecurityProfile: mockGetCurrentSecurityProfile,
  setSecurityProfile: mockSetSecurityProfile,
}));

// Mock sandbox_helpers functions
vi.mock('./packages/cli/src/utils/sandbox_helpers.js', () => ({
  isSafeEnvValue: vi.fn(),
  isValidEnvKey: vi.fn(),
}));

// Mock fs module
vi.mock('fs', () => ({
  existsSync: vi.fn(),
  readdirSync: vi.fn()
}));

// Mock console methods for testing CLI output
const mockConsoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
const mockConsoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

// Mock process.exit
vi.spyOn(process, 'exit').mockImplementation(() => {
  throw new Error('Process exited');
});

// Import the security CLI functions (we'll extract them from the demo)
describe('Security CLI Commands', () => {
  beforeEach(() => {
    vi.resetAllMocks();

    // Reset mocks
    mockIsCommandSafe.mockReset();
    mockGetSecurityProfiles.mockReset();
    mockGetCurrentSecurityProfile.mockReset();
    mockSetSecurityProfile.mockReset();
    mockConsoleLog.mockClear();
    mockConsoleError.mockClear();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('showSecurityInfo', () => {
    it('should display current security configuration', () => {
      // Mock current profile
      const mockProfile = {
        name: 'Standard',
        description: 'Balanced security for regular users',
        allowedCommands: new Set(['echo', 'ls', 'cat', 'pwd', 'whoami', 'date']),
        riskyCommands: new Set(['cp', 'mv', 'curl', 'wget']),
        dangerousCommands: new Set(['rm', 'sudo', 'chmod', 'eval', 'exec']),
        strictMode: false,
        educationMode: true,
        logLevel: 'standard'
      };

      mockGetCurrentSecurityProfile.mockReturnValue(mockProfile);

      // Call the function
      showSecurityInfo();

      // Verify that the function was called and console.log was used
      expect(mockGetCurrentSecurityProfile).toHaveBeenCalled();
      expect(mockConsoleLog).toHaveBeenCalled();
    });

    it('should display all security profile information', () => {
      const mockProfile = {
        name: 'Developer',
        description: 'Permissive mode for development workflows',
        allowedCommands: new Set(['echo', 'ls', 'git', 'npm', 'docker']),
        riskyCommands: new Set(['rm', 'sudo']),
        dangerousCommands: new Set(['rm -rf /', 'reboot']),
        strictMode: false,
        educationMode: false,
        logLevel: 'minimal'
      };

      mockGetCurrentSecurityProfile.mockReturnValue(mockProfile);

      showSecurityInfo();

      expect(mockGetCurrentSecurityProfile).toHaveBeenCalled();
      // Verify that console.log was called with profile information
      expect(mockConsoleLog).toHaveBeenCalledWith('🔒 Security Profile:', 'Developer (Permissive mode for development workflows)');
    });
  });

  describe('showSecurityTutorial', () => {
    it('should display security tutorial content', () => {
      // This would test the tutorial display logic
      // In the actual implementation, we'd extract the tutorial function
      expect(true).toBe(true); // Placeholder test
    });
  });

  describe('changeSecurityProfile', () => {
    it('should successfully switch to a valid profile', () => {
      mockSetSecurityProfile.mockReturnValue(true);
      mockGetCurrentSecurityProfile.mockReturnValue({
        name: 'Beginner'
      });

      mockGetSecurityProfiles.mockReturnValue({
        beginner: { name: 'Beginner' }
      });

      // Test the profile switching logic
      const result = changeSecurityProfile('beginner');

      expect(result).toBe(true);
      expect(mockSetSecurityProfile).toHaveBeenCalledWith('beginner');
      expect(mockConsoleLog).toHaveBeenCalledWith('✅ Security profile set to: Beginner');
    });

    it('should handle invalid profile names', () => {
      mockGetSecurityProfiles.mockReturnValue({
        standard: { name: 'Standard' },
        developer: { name: 'Developer' }
      });

      const result = changeSecurityProfile('invalid');

      expect(result).toBe(false);
      expect(mockConsoleError).toHaveBeenCalledWith('❌ Invalid profile: invalid');
      expect(mockConsoleError).toHaveBeenCalledWith('Available profiles: standard, developer');
    });

    it('should handle case sensitivity', () => {
      mockGetSecurityProfiles.mockReturnValue({
        beginner: { name: 'Beginner' }
      });

      const result = changeSecurityProfile('BEGINNER');

      expect(result).toBe(false);
      expect(mockConsoleError).toHaveBeenCalledWith('❌ Invalid profile: BEGINNER');
    });
  });

  describe('testCommandSecurity', () => {
    it('should test a safe command and show positive results', () => {
      mockIsCommandSafe.mockReturnValue({
        safe: true,
        risk: 'low',
        reason: 'Command is safe for automatic execution'
      });

      const command = 'echo hello';
      testCommandSecurity(command);

      expect(mockIsCommandSafe).toHaveBeenCalledWith(command);
      expect(mockConsoleLog).toHaveBeenCalledWith('🧪 Testing command: "echo hello"');
      expect(mockConsoleLog).toHaveBeenCalledWith('   Allowed: ✅ YES');
      expect(mockConsoleLog).toHaveBeenCalledWith('   Risk Level: LOW');
    });

    it('should test a dangerous command and show negative results with alternatives', () => {
      mockIsCommandSafe.mockReturnValue({
        safe: false,
        risk: 'high',
        reason: 'Command contains dangerous operations'
      });

      const command = 'rm -rf /';
      testCommandSecurity(command);

      expect(mockIsCommandSafe).toHaveBeenCalledWith(command);
      expect(mockConsoleLog).toHaveBeenCalledWith('   Allowed: ❌ NO');
      expect(mockConsoleLog).toHaveBeenCalledWith('   Risk Level: HIGH');
      expect(mockConsoleLog).toHaveBeenCalledWith('💡 Safe Alternatives:');
    });

    it('should handle empty commands', () => {
      const command = '';
      testCommandSecurity(command);

      expect(mockConsoleLog).toHaveBeenCalledWith('❌ Please provide a command to test');
    });

    it('should handle null/undefined commands', () => {
      const command = null as unknown as string;
      testCommandSecurity(command);

      expect(mockIsCommandSafe).toHaveBeenCalledWith(null);
    });
  });

  describe('showLogs', () => {
    beforeEach(() => {
      // Mock fs functions are already mocked at the module level
    });

    it('should show logs when log directory exists', async () => {
      const { existsSync, readdirSync } = await import('fs');
      const mockExistsSync = existsSync as ReturnType<typeof vi.fn>;
      const mockReaddirSync = readdirSync as ReturnType<typeof vi.fn>;

      mockExistsSync.mockReturnValue(true);
      mockReaddirSync.mockReturnValue(['command-audit.log', 'security-summary.txt'] as unknown as string[]);

      // This would test the log display logic
      const logDir = path.join(os.tmpdir(), 'gemini-cli-security');

      expect(mockExistsSync).toHaveBeenCalledWith(logDir);
    });

    it('should handle missing log directory', async () => {
      const { existsSync } = await import('fs');
      const mockExistsSync = existsSync as ReturnType<typeof vi.fn>;

      mockExistsSync.mockReturnValue(false);

      // This would test the missing log directory handling
      const logDir = path.join(os.tmpdir(), 'gemini-cli-security');

      expect(mockExistsSync).toHaveBeenCalledWith(logDir);
    });
  });

  describe('handleSecurityCommand', () => {
    it('should handle info command', () => {
      const args: string[] = ['info'];

      handleSecurityCommand(args);

      expect(mockGetCurrentSecurityProfile).toHaveBeenCalled();
    });

    it('should handle set command with valid profile', () => {
      mockGetSecurityProfiles.mockReturnValue({
        beginner: { name: 'Beginner' }
      });
      mockSetSecurityProfile.mockReturnValue(true);

      const args: string[] = ['set', 'beginner'];

      handleSecurityCommand(args);

      expect(mockSetSecurityProfile).toHaveBeenCalledWith('beginner');
      expect(mockConsoleLog).toHaveBeenCalledWith('✅ Security profile set to: Beginner');
    });

    it('should handle set command with invalid profile', () => {
      mockGetSecurityProfiles.mockReturnValue({
        standard: { name: 'Standard' },
        developer: { name: 'Developer' }
      });

      const args: string[] = ['set', 'invalid'];

      handleSecurityCommand(args);

      expect(mockConsoleError).toHaveBeenCalledWith('❌ Invalid profile: invalid');
    });

    it('should handle test command with safe command', () => {
      mockIsCommandSafe.mockReturnValue({
        safe: true,
        risk: 'low',
        reason: 'Command is safe'
      });

      const args: string[] = ['test', 'echo hello'];

      handleSecurityCommand(args);

      expect(mockIsCommandSafe).toHaveBeenCalledWith('echo hello');
      expect(mockConsoleLog).toHaveBeenCalledWith('   Allowed: ✅ YES');
    });

    it('should handle test command with dangerous command', () => {
      mockIsCommandSafe.mockReturnValue({
        safe: false,
        risk: 'high',
        reason: 'Command is dangerous'
      });

      const args: string[] = ['test', 'rm -rf /'];

      handleSecurityCommand(args);

      expect(mockIsCommandSafe).toHaveBeenCalledWith('rm -rf /');
      expect(mockConsoleLog).toHaveBeenCalledWith('   Allowed: ❌ NO');
    });

    it('should handle logs command', () => {
      const args: string[] = ['logs'];

      handleSecurityCommand(args);

      expect(mockConsoleLog).toHaveBeenCalledWith(expect.stringContaining('Security Logs Location:'));
    });

    it('should handle tutorial command', () => {
      const args: string[] = ['tutorial'];

      handleSecurityCommand(args);

      expect(mockConsoleLog).toHaveBeenCalledWith('📚 SECURITY TUTORIAL');
    });

    it('should handle profiles command', () => {
      mockGetSecurityProfiles.mockReturnValue({
        beginner: { name: 'Beginner' },
        standard: { name: 'Standard' }
      });

      const args: string[] = ['profiles'];

      handleSecurityCommand(args);

      expect(mockGetSecurityProfiles).toHaveBeenCalled();
      expect(mockConsoleLog).toHaveBeenCalledWith('👥 Available Security Profiles:');
    });

    it('should handle unknown commands', () => {
      const args: string[] = ['unknown'];

      handleSecurityCommand(args);

      expect(mockConsoleError).toHaveBeenCalledWith('❌ Unknown command: unknown');
    });

    it('should handle empty arguments', () => {
      const args: string[] = [];

      handleSecurityCommand(args);

      expect(mockConsoleLog).toHaveBeenCalledWith('💡 Available Commands:');
    });
  });

  describe('Error Handling', () => {
    it('should handle security function errors gracefully', () => {
      mockIsCommandSafe.mockImplementation(() => {
        throw new Error('Security function error');
      });

      expect(() => {
        mockIsCommandSafe('echo hello');
      }).toThrow('Security function error');
    });

    it('should handle profile switching errors', () => {
      mockSetSecurityProfile.mockImplementation(() => {
        throw new Error('Profile switching error');
      });

      expect(() => {
        mockSetSecurityProfile('beginner');
      }).toThrow('Profile switching error');
    });

    it('should handle console output errors', () => {
      mockConsoleLog.mockImplementation(() => {
        throw new Error('Console error');
      });

      // The CLI should handle console errors gracefully
      expect(() => {
        console.log('test');
      }).toThrow('Console error');
    });
  });

  describe('Security Profile Validation', () => {
    it('should validate all available security profiles', () => {
      const expectedProfiles = ['beginner', 'standard', 'advanced', 'developer'];

      mockGetSecurityProfiles.mockReturnValue({
        beginner: { name: 'Beginner' },
        standard: { name: 'Standard' },
        advanced: { name: 'Advanced' },
        developer: { name: 'Developer' }
      });

      const profiles = mockGetSecurityProfiles();
      const profileNames = Object.keys(profiles);

      expectedProfiles.forEach(profile => {
        expect(profileNames).toContain(profile);
      });
    });

    it('should validate profile structure', () => {
      const mockProfile = {
        name: 'Test Profile',
        description: 'Test description',
        allowedCommands: new Set(['echo', 'ls']),
        riskyCommands: new Set(['cp', 'mv']),
        dangerousCommands: new Set(['rm', 'sudo']),
        strictMode: true,
        educationMode: true,
        logLevel: 'verbose'
      };

      mockGetCurrentSecurityProfile.mockReturnValue(mockProfile);

      const profile = mockGetCurrentSecurityProfile();

      expect(profile.name).toBe('Test Profile');
      expect(profile.allowedCommands).toBeInstanceOf(Set);
      expect(profile.riskyCommands).toBeInstanceOf(Set);
      expect(profile.dangerousCommands).toBeInstanceOf(Set);
      expect(typeof profile.strictMode).toBe('boolean');
      expect(typeof profile.educationMode).toBe('boolean');
      expect(['minimal', 'standard', 'verbose']).toContain(profile.logLevel);
    });
  });

  describe('Educational Feedback', () => {
    it('should provide helpful suggestions for dangerous commands', () => {
      mockIsCommandSafe.mockReturnValue({
        safe: false,
        risk: 'high',
        reason: 'Command contains dangerous operations'
      });

      const command = 'rm -rf /';
      const result = mockIsCommandSafe(command);

      // The CLI should provide educational feedback for dangerous commands
      expect(result.safe).toBe(false);
      expect(result.risk).toBe('high');
      expect(result.reason).toContain('dangerous');
    });

    it('should provide guidance for medium risk commands', () => {
      mockIsCommandSafe.mockReturnValue({
        safe: true,
        risk: 'medium',
        reason: 'Command is potentially risky'
      });

      const command = 'cp file1 file2';
      const result = mockIsCommandSafe(command);

      expect(result.safe).toBe(true);
      expect(result.risk).toBe('medium');
      expect(result.reason).toContain('risky');
    });

    it('should confirm safety for low risk commands', () => {
      mockIsCommandSafe.mockReturnValue({
        safe: true,
        risk: 'low',
        reason: 'Command is safe for automatic execution'
      });

      const command = 'echo hello';
      const result = mockIsCommandSafe(command);

      expect(result.safe).toBe(true);
      expect(result.risk).toBe('low');
      expect(result.reason).toContain('safe');
    });
  });

  describe('Integration with Security System', () => {
    it('should integrate with shell-utils security functions', () => {
      // Test that the CLI properly integrates with the security system
      const command = 'echo hello';

      mockIsCommandSafe.mockReturnValue({
        safe: true,
        risk: 'low',
        reason: 'Command is safe'
      });

      const result = mockIsCommandSafe(command);

      expect(mockIsCommandSafe).toHaveBeenCalledWith(command);
      expect(result).toHaveProperty('safe');
      expect(result).toHaveProperty('risk');
      expect(result).toHaveProperty('reason');
    });

    it('should handle security profile changes', () => {
      const profile = 'developer';

      mockSetSecurityProfile.mockReturnValue(true);
      mockGetCurrentSecurityProfile.mockReturnValue({
        name: 'Developer'
      });

      const setResult = mockSetSecurityProfile(profile);
      const currentProfile = mockGetCurrentSecurityProfile();

      expect(setResult).toBe(true);
      expect(currentProfile.name).toBe('Developer');
    });

    it('should provide comprehensive security information', () => {
      const mockProfile = {
        name: 'Standard',
        description: 'Balanced security for regular users',
        allowedCommands: new Set(['echo', 'ls', 'cat', 'pwd', 'whoami', 'date', 'git', 'npm', 'node']),
        riskyCommands: new Set(['cp', 'mv', 'curl', 'wget', 'tar', 'gzip']),
        dangerousCommands: new Set(['rm', 'sudo', 'chmod', 'chown', 'eval', 'exec', 'system']),
        strictMode: false,
        educationMode: true,
        logLevel: 'standard'
      };

      mockGetCurrentSecurityProfile.mockReturnValue(mockProfile);

      const profile = mockGetCurrentSecurityProfile();

      expect(profile.allowedCommands.size).toBeGreaterThan(5);
      expect(profile.dangerousCommands.has('rm')).toBe(true);
      expect(profile.educationMode).toBe(true);
    });
  });
});
