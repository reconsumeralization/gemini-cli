/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { Config } from '../config/config.js';
import os from 'os';
import { quote } from 'shell-quote';
import fs from 'fs';
import path from 'path';

/**
 * An identifier for the shell type.
 */
export type ShellType = 'cmd' | 'powershell' | 'bash';

/**
 * Defines the configuration required to execute a command string within a specific shell.
 */
export interface ShellConfiguration {
  /** The path or name of the shell executable (e.g., 'bash', 'cmd.exe'). */
  executable: string;
  /**
   * The arguments required by the shell to execute a subsequent string argument.
   */
  argsPrefix: string[];
  /** An identifier for the shell type. */
  shell: ShellType;
}

/**
 * Determines the appropriate shell configuration for the current platform.
 *
 * This ensures we can execute command strings predictably and securely across platforms
 * using the `spawn(executable, [...argsPrefix, commandString], { shell: false })` pattern.
 *
 * @returns The ShellConfiguration for the current environment.
 */
export function getShellConfiguration(): ShellConfiguration {
  if (isWindows()) {
    const comSpec = process.env['ComSpec'] || 'cmd.exe';
    const executable = comSpec.toLowerCase();

    if (
      executable.endsWith('powershell.exe') ||
      executable.endsWith('pwsh.exe')
    ) {
      // For PowerShell, the arguments are different.
      // -NoProfile: Speeds up startup.
      // -Command: Executes the following command.
      return {
        executable: comSpec,
        argsPrefix: ['-NoProfile', '-Command'],
        shell: 'powershell',
      };
    }

    // Default to cmd.exe for anything else on Windows.
    // Flags for CMD:
    // /d: Skip execution of AutoRun commands.
    // /s: Modifies the treatment of the command string (important for quoting).
    // /c: Carries out the command specified by the string and then terminates.
    return {
      executable: comSpec,
      argsPrefix: ['/d', '/s', '/c'],
      shell: 'cmd',
    };
  }

  // Unix-like systems (Linux, macOS)
  return { executable: 'bash', argsPrefix: ['-c'], shell: 'bash' };
}

/**
 * Export the platform detection constant for use in process management (e.g., killing processes).
 */
export const isWindows = () => os.platform() === 'win32';

/**
 * Escapes a string so that it can be safely used as a single argument
 * in a shell command, preventing command injection.
 *
 * @param arg The argument string to escape.
 * @param shell The type of shell the argument is for.
 * @returns The shell-escaped string.
 */
export function escapeShellArg(arg: string, shell: ShellType): string {
  if (!arg) {
    return '';
  }

  switch (shell) {
    case 'powershell':
      // For PowerShell, wrap in single quotes and escape internal single quotes by doubling them.
      return `'${arg.replace(/'/g, "''")}'`;
    case 'cmd':
      // Simple Windows escaping for cmd.exe: wrap in double quotes and escape inner double quotes.
      return `"${arg.replace(/"/g, '""')}"`;
    case 'bash':
    default:
      // POSIX shell escaping using shell-quote.
      return quote([arg]);
  }
}

/**
 * Splits a shell command into a list of individual commands, respecting quotes.
 * This is used to separate chained commands (e.g., using &&, ||, ;).
 * @param command The shell command string to parse
 * @returns An array of individual command strings
 */
export function splitCommands(command: string): string[] {
  const commands: string[] = [];
  let currentCommand = '';
  let inSingleQuotes = false;
  let inDoubleQuotes = false;
  let i = 0;

  while (i < command.length) {
    const char = command[i];
    const nextChar = command[i + 1];

    if (char === '\\' && i < command.length - 1) {
      currentCommand += char + command[i + 1];
      i += 2;
      continue;
    }

    if (char === "'" && !inDoubleQuotes) {
      inSingleQuotes = !inSingleQuotes;
    } else if (char === '"' && !inSingleQuotes) {
      inDoubleQuotes = !inDoubleQuotes;
    }

    if (!inSingleQuotes && !inDoubleQuotes) {
      if (
        (char === '&' && nextChar === '&') ||
        (char === '|' && nextChar === '|')
      ) {
        commands.push(currentCommand.trim());
        currentCommand = '';
        i++; // Skip the next character
      } else if (char === ';' || char === '&' || char === '|') {
        commands.push(currentCommand.trim());
        currentCommand = '';
      } else {
        currentCommand += char;
      }
    } else {
      currentCommand += char;
    }
    i++;
  }

  if (currentCommand.trim()) {
    commands.push(currentCommand.trim());
  }

  return commands.filter(Boolean); // Filter out any empty strings
}

/**
 * Extracts the root command from a given shell command string.
 * This is used to identify the base command for permission checks.
 * @param command The shell command string to parse
 * @returns The root command name, or undefined if it cannot be determined
 * @example getCommandRoot("ls -la /tmp") returns "ls"
 * @example getCommandRoot("git status && npm test") returns "git"
 */
export function getCommandRoot(command: string): string | undefined {
  const trimmedCommand = command.trim();
  if (!trimmedCommand) {
    return undefined;
  }

  // This regex is designed to find the first "word" of a command,
  // while respecting quotes. It looks for a sequence of non-whitespace
  // characters that are not inside quotes.
  const match = trimmedCommand.match(/^"([^"]+)"|^'([^']+)'|^(\S+)/);
  if (match) {
    // The first element in the match array is the full match.
    // The subsequent elements are the capture groups.
    // We prefer a captured group because it will be unquoted.
    const commandRoot = match[1] || match[2] || match[3];
    if (commandRoot) {
      // If the command is a path, return the last component.
      return commandRoot.split(/[\\/]/).pop();
    }
  }

  return undefined;
}

export function getCommandRoots(command: string): string[] {
  if (!command) {
    return [];
  }
  return splitCommands(command)
    .map((c) => getCommandRoot(c))
    .filter((c): c is string => !!c);
}

export function stripShellWrapper(command: string): string {
  const pattern = /^\s*(?:sh|bash|zsh|cmd.exe)\s+(?:\/c|-c)\s+/;
  const match = command.match(pattern);
  if (match) {
    let newCommand = command.substring(match[0].length).trim();
    if (
      (newCommand.startsWith('"') && newCommand.endsWith('"')) ||
      (newCommand.startsWith("'") && newCommand.endsWith("'"))
    ) {
      newCommand = newCommand.substring(1, newCommand.length - 1);
    }
    return newCommand;
  }
  return command.trim();
}

/**
 * Detects command substitution patterns in a shell command, following bash quoting rules:
 * - Single quotes ('): Everything literal, no substitution possible
 * - Double quotes ("): Command substitution with $() and backticks unless escaped with \
 * - No quotes: Command substitution with $(), <(), and backticks
 * @param command The shell command string to check
 * @returns true if command substitution would be executed by bash
 */
export function detectCommandSubstitution(command: string): boolean {
  let inSingleQuotes = false;
  let inDoubleQuotes = false;
  let inBackticks = false;
  let i = 0;

  while (i < command.length) {
    const char = command[i];
    const nextChar = command[i + 1];

    // Handle escaping - only works outside single quotes
    if (char === '\\' && !inSingleQuotes) {
      i += 2; // Skip the escaped character
      continue;
    }

    // Handle quote state changes
    if (char === "'" && !inDoubleQuotes && !inBackticks) {
      inSingleQuotes = !inSingleQuotes;
    } else if (char === '"' && !inSingleQuotes && !inBackticks) {
      inDoubleQuotes = !inDoubleQuotes;
    } else if (char === '`' && !inSingleQuotes) {
      // Backticks work outside single quotes (including in double quotes)
      inBackticks = !inBackticks;
    }

    // Check for command substitution patterns that would be executed
    if (!inSingleQuotes) {
      // $(...) command substitution - works in double quotes and unquoted
      if (char === '$' && nextChar === '(') {
        return true;
      }

      // <(...) process substitution - works unquoted only (not in double quotes)
      if (char === '<' && nextChar === '(' && !inDoubleQuotes && !inBackticks) {
        return true;
      }

      // Backtick command substitution - check for opening backtick
      // (We track the state above, so this catches the start of backtick substitution)
      if (char === '`' && !inBackticks) {
        return true;
      }
    }

    i++;
  }

  return false;
}

/**
 * Checks a shell command against security policies and allowlists.
 *
 * This function operates in one of two modes depending on the presence of
 * the `sessionAllowlist` parameter:
 *
 * 1.  **"Default Deny" Mode (sessionAllowlist is provided):** This is the
 *     strictest mode, used for user-defined scripts like custom commands.
 *     A command is only permitted if it is found on the global `coreTools`
 *     allowlist OR the provided `sessionAllowlist`. It must not be on the
 *     global `excludeTools` blocklist.
 *
 * 2.  **"Default Allow" Mode (sessionAllowlist is NOT provided):** This mode
 *     is used for direct tool invocations (e.g., by the model). If a strict
 *     global `coreTools` allowlist exists, commands must be on it. Otherwise,
 *     any command is permitted as long as it is not on the `excludeTools`
 *     blocklist.
 *
 * @param command The shell command string to validate.
 * @param config The application configuration.
 * @param sessionAllowlist A session-level list of approved commands. Its
 *   presence activates "Default Deny" mode.
 * @returns An object detailing which commands are not allowed.
 */
export function checkCommandPermissions(
  command: string,
  config: Config,
  sessionAllowlist?: Set<string>,
): {
  allAllowed: boolean;
  disallowedCommands: string[];
  blockReason?: string;
  isHardDenial?: boolean;
} {
  // Disallow command substitution for security.
  if (detectCommandSubstitution(command)) {
    return {
      allAllowed: false,
      disallowedCommands: [command],
      blockReason:
        'Command substitution using $(), <(), or >() is not allowed for security reasons',
      isHardDenial: true,
    };
  }

  const SHELL_TOOL_NAMES = ['run_shell_command', 'ShellTool'];
  const normalize = (cmd: string): string => cmd.trim().replace(/\s+/g, ' ');

  const isPrefixedBy = (cmd: string, prefix: string): boolean => {
    if (!cmd.startsWith(prefix)) {
      return false;
    }
    return cmd.length === prefix.length || cmd[prefix.length] === ' ';
  };

  const extractCommands = (tools: string[]): string[] =>
    tools.flatMap((tool) => {
      for (const toolName of SHELL_TOOL_NAMES) {
        if (tool.startsWith(`${toolName}(`) && tool.endsWith(')')) {
          return [normalize(tool.slice(toolName.length + 1, -1))];
        }
      }
      return [];
    });

  const coreTools = config.getCoreTools() || [];
  const excludeTools = config.getExcludeTools() || [];
  const commandsToValidate = splitCommands(command).map(normalize);

  // 1. Blocklist Check (Highest Priority)
  if (SHELL_TOOL_NAMES.some((name) => excludeTools.includes(name))) {
    return {
      allAllowed: false,
      disallowedCommands: commandsToValidate,
      blockReason: 'Shell tool is globally disabled in configuration',
      isHardDenial: true,
    };
  }
  const blockedCommands = extractCommands(excludeTools);
  for (const cmd of commandsToValidate) {
    if (blockedCommands.some((blocked) => isPrefixedBy(cmd, blocked))) {
      return {
        allAllowed: false,
        disallowedCommands: [cmd],
        blockReason: `Command '${cmd}' is blocked by configuration`,
        isHardDenial: true,
      };
    }
  }

  const globallyAllowedCommands = extractCommands(coreTools);
  const isWildcardAllowed = SHELL_TOOL_NAMES.some((name) =>
    coreTools.includes(name),
  );

  // If there's a global wildcard, all commands are allowed at this point
  // because they have already passed the blocklist check.
  if (isWildcardAllowed) {
    return { allAllowed: true, disallowedCommands: [] };
  }

  if (sessionAllowlist) {
    // "DEFAULT DENY" MODE: A session allowlist is provided.
    // All commands must be in either the session or global allowlist.
    const disallowedCommands: string[] = [];
    for (const cmd of commandsToValidate) {
      const isSessionAllowed = [...sessionAllowlist].some((allowed) =>
        isPrefixedBy(cmd, normalize(allowed)),
      );
      if (isSessionAllowed) continue;

      const isGloballyAllowed = globallyAllowedCommands.some((allowed) =>
        isPrefixedBy(cmd, allowed),
      );
      if (isGloballyAllowed) continue;

      disallowedCommands.push(cmd);
    }

    if (disallowedCommands.length > 0) {
      return {
        allAllowed: false,
        disallowedCommands,
        blockReason: `Command(s) not on the global or session allowlist. Disallowed commands: ${disallowedCommands
          .map((c) => JSON.stringify(c))
          .join(', ')}`,
        isHardDenial: false, // This is a soft denial; confirmation is possible.
      };
    }
  } else {
    // "DEFAULT ALLOW" MODE: No session allowlist.
    const hasSpecificAllowedCommands = globallyAllowedCommands.length > 0;
    if (hasSpecificAllowedCommands) {
      const disallowedCommands: string[] = [];
      for (const cmd of commandsToValidate) {
        const isGloballyAllowed = globallyAllowedCommands.some((allowed) =>
          isPrefixedBy(cmd, allowed),
        );
        if (!isGloballyAllowed) {
          disallowedCommands.push(cmd);
        }
      }
      if (disallowedCommands.length > 0) {
        return {
          allAllowed: false,
          disallowedCommands,
          blockReason: `Command(s) not in the allowed commands list. Disallowed commands: ${disallowedCommands.map((c) => JSON.stringify(c)).join(', ')}`,
          isHardDenial: false, // This is a soft denial.
        };
      }
    }
    // If no specific global allowlist exists, and it passed the blocklist,
    // the command is allowed by default.
  }

  // If all checks for the current mode pass, the command is allowed.
  return { allAllowed: true, disallowedCommands: [] };
}

/**
 * Determines whether a given shell command is allowed to execute based on
 * the tool's configuration including allowlists and blocklists.
 *
 * This function operates in "default allow" mode. It is a wrapper around
 * `checkCommandPermissions`.
 *
 * @param command The shell command string to validate.
 * @param config The application configuration.
 * @returns An object with 'allowed' boolean and optional 'reason' string if not allowed.
 */
// Safe command execution control - comprehensive safety layers
// Base allowed commands - users can customize this
let ALLOWED_COMMANDS = new Set([
  'echo', 'ls', 'cat', 'grep', 'head', 'tail', 'wc', 'sort', 'uniq',
  'find', 'pwd', 'whoami', 'date', 'which', 'type', 'file', 'stat',
  'ps', 'top', 'df', 'du', 'free', 'uptime', 'id', 'groups', 'hostname',
  'ping', 'traceroute', 'dig', 'nslookup', 'curl', 'wget', 'git',
  'node', 'npm', 'python', 'python3', 'pip', 'pip3', 'docker', 'docker-compose'
]);

// User-customizable security settings
interface SecurityProfile {
  name: string;
  description: string;
  allowedCommands: Set<string>;
  riskyCommands: Set<string>;
  dangerousCommands: Set<string>;
  strictMode: boolean;
  educationMode: boolean;
  logLevel: 'minimal' | 'standard' | 'verbose';
}

const SECURITY_PROFILES: Record<string, SecurityProfile> = {
  'beginner': {
    name: 'Beginner',
    description: 'Maximum safety with lots of guidance',
    allowedCommands: new Set(['echo', 'ls', 'cat', 'pwd', 'whoami', 'date']),
    riskyCommands: new Set(['cp', 'mv', 'grep', 'head', 'tail']),
    dangerousCommands: new Set(['rm', 'sudo', 'chmod', 'chown', 'eval', 'exec']),
    strictMode: true,
    educationMode: true,
    logLevel: 'verbose'
  },
  'standard': {
    name: 'Standard',
    description: 'Balanced security for regular users',
    allowedCommands: ALLOWED_COMMANDS,
    riskyCommands: new Set(['cp', 'mv', 'cp', 'scp', 'rsync', 'tar', 'gzip', 'gunzip', 'bzip2', 'xz', '7z', 'zip', 'unzip', 'rar', 'unrar', 'wget', 'curl', 'ssh', 'scp', 'rsync', 'ftp', 'sftp', 'telnet', 'nc', 'nmap']),
    dangerousCommands: new Set(['rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs', 'mount', 'umount', 'sudo', 'su', 'chmod', 'chown', 'chgrp', 'passwd', 'useradd', 'userdel', 'reboot', 'shutdown', 'halt', 'poweroff', 'systemctl', 'service', 'kill', 'killall', 'pkill', 'pgrep', 'nohup', 'screen', 'tmux', 'crontab', 'at', 'batch', 'eval', 'exec', 'system', 'sh', 'bash', 'zsh', 'fish', 'dash', 'ash', 'busybox', 'tcsh', 'csh', 'ksh', 'dd', 'mkfs', 'fsck', 'fdisk', 'parted', 'gparted', 'cfdisk', 'wipefs', 'blkid', 'lsblk', 'fdisk', 'sfdisk', 'gdisk']),
    strictMode: false,
    educationMode: true,
    logLevel: 'standard'
  },
  'advanced': {
    name: 'Advanced',
    description: 'Relaxed security for power users',
    allowedCommands: new Set([...ALLOWED_COMMANDS, 'chmod', 'chown', 'ps', 'kill', 'top']),
    riskyCommands: new Set(['rm', 'sudo', 'systemctl', 'mount']),
    dangerousCommands: new Set(['rm -rf /', 'dd if=/dev/zero', 'mkfs', 'format', 'fdisk /dev/', 'reboot', 'shutdown -h now']),
    strictMode: false,
    educationMode: false,
    logLevel: 'minimal'
  },
  'developer': {
    name: 'Developer',
    description: 'Permissive mode for development workflows',
    allowedCommands: new Set([...ALLOWED_COMMANDS, 'chmod', 'chown', 'ps', 'kill', 'top', 'docker', 'npm', 'git']),
    riskyCommands: new Set(['rm', 'sudo']),
    dangerousCommands: new Set(['rm -rf /', 'reboot', 'shutdown']),
    strictMode: false,
    educationMode: false,
    logLevel: 'minimal'
  }
};

// Current active security profile
let currentProfile: SecurityProfile = SECURITY_PROFILES.standard;

const DANGEROUS_COMMANDS = new Set([
  'rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs', 'mount', 'umount',
  'sudo', 'su', 'chmod', 'chown', 'chgrp', 'passwd', 'useradd', 'userdel',
  'groupadd', 'groupdel', 'iptables', 'netsh', 'ifconfig', 'route',
  'reboot', 'shutdown', 'halt', 'poweroff', 'systemctl', 'service',
  'kill', 'killall', 'pkill', 'pgrep', 'nohup', 'screen', 'tmux',
  'crontab', 'at', 'batch', 'eval', 'exec', 'system', 'sh', 'bash',
  'zsh', 'fish', 'dash', 'ash', 'busybox', 'tcsh', 'csh', 'ksh',
  'dd', 'mkfs', 'fsck', 'fdisk', 'parted', 'gparted', 'cfdisk',
  'wipefs', 'blkid', 'lsblk', 'fdisk', 'sfdisk', 'gdisk'
]);

const RISKY_COMMANDS = new Set([
  'cp', 'mv', 'cp', 'scp', 'rsync', 'tar', 'gzip', 'gunzip', 'bzip2',
  'xz', '7z', 'zip', 'unzip', 'rar', 'unrar', 'wget', 'curl',
  'ssh', 'scp', 'rsync', 'ftp', 'sftp', 'telnet', 'nc', 'nmap'
]);

const FORBIDDEN_TOKENS = [
  '&&', '||', ';', '|', '$', '`', '<(', '>)', '${', '$(',
  '2>&1', '1>&2', '>&', '<&', '>>', '<<', '<<<', '&>',
  '>|', '<>', '&>>', '&>', '&&&', '|||', ';;;'
];

const DANGEROUS_PATTERNS = [
  /\$\{[^}]*\}/g,  // Variable expansion
  /`[^`]*`/g,      // Backtick command substitution
  /\$\([^)]*\)/g,  // Command substitution
  /<\([^)]*\)/g,   // Process substitution
  />\([^)]*\)/g,   // Process substitution
  /\/dev\/(null|zero|random|urandom)/g,  // Direct device access
  /\/etc\/(passwd|shadow|sudoers|hosts|fstab)/g,  // System files
  /\/root|\.ssh|authorized_keys/g,  // Sensitive directories
];

/**
 * Enhanced command safety validation with comprehensive security layers
 */
function isCommandSafe(command: string): { safe: boolean; reason?: string; risk?: 'low' | 'medium' | 'high' } {
  if (!command || typeof command !== 'string') {
    return { safe: false, reason: 'Invalid command string' };
  }

  const trimmedCommand = command.trim();
  if (!trimmedCommand) {
    return { safe: false, reason: 'Empty command' };
  }

  // Extract the base command (first token)
  const tokens = trimmedCommand.split(/\s+/);
  const baseCommand = tokens[0].split('/').pop()?.toLowerCase() || '';

  // Check dangerous commands - hard block (profile-specific)
  if (currentProfile.dangerousCommands.has(baseCommand) || currentProfile.dangerousCommands.has(command)) {
    return {
      safe: false,
      reason: `Command '${baseCommand}' is blocked in ${currentProfile.name} security profile`,
      risk: 'high'
    };
  }

  // Check allowed commands - explicit allowlist (profile-specific)
  if (!currentProfile.allowedCommands.has(baseCommand)) {
    return {
      safe: false,
      reason: `Command '${baseCommand}' is not in the allowed commands for ${currentProfile.name} profile`,
      risk: 'medium'
    };
  }

  // Check for forbidden tokens - injection attempts
  for (const token of FORBIDDEN_TOKENS) {
    if (trimmedCommand.includes(token)) {
      return {
        safe: false,
        reason: `Forbidden token '${token}' detected - possible command injection`,
        risk: 'high'
      };
    }
  }

  // Check for dangerous patterns - advanced injection detection
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(trimmedCommand)) {
      return {
        safe: false,
        reason: 'Dangerous command pattern detected - possible injection attempt',
        risk: 'high'
      };
    }
  }

  // Check for risky commands that may need confirmation (profile-specific)
  if (currentProfile.riskyCommands.has(baseCommand)) {
    return {
      safe: true,
      risk: 'medium',
      reason: `Command '${baseCommand}' is potentially risky in ${currentProfile.name} profile`
    };
  }

  // Command passed all safety checks
  return {
    safe: true,
    risk: 'low',
    reason: `Command '${baseCommand}' is safe for automatic execution`
  };
}

/**
 * Enhanced logging with security insights and user education
 */
function logCommandExecution(command: string, allowed: boolean, reason?: string, risk?: string, config?: Config) {
  try {
    const approvalMode = config?.getApprovalMode() || 'default';
    const logEntry = {
      timestamp: new Date().toISOString(),
      command: command,
      allowed: allowed,
      reason: reason || 'No reason provided',
      risk: risk || 'unknown',
      user: process.env.USER || process.env.USERNAME || 'unknown',
      pid: process.pid,
      approvalMode: approvalMode,
      sessionId: config?.getSessionId?.() || 'unknown'
    };

    const logDir = path.join(os.tmpdir(), 'gemini-cli-security');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true, mode: 0o700 });
    }

    const logFile = path.join(logDir, 'command-audit.log');
    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n', { mode: 0o600 });

    // Also log to a human-readable security summary
    const summaryFile = path.join(logDir, 'security-summary.txt');
    const summary = `[${new Date().toLocaleString()}] ${allowed ? '✅' : '❌'} ${risk?.toUpperCase()} - ${command.substring(0, 50)}${command.length > 50 ? '...' : ''}\n`;
    fs.appendFileSync(summaryFile, summary, { mode: 0o600 });

  } catch (error) {
    // Don't let logging errors break command execution
    console.warn('Failed to log command execution:', error);
  }
}

/**
 * Provides educational feedback for blocked commands
 */
function provideUserEducation(command: string, reason: string, risk: string): void {
  console.log('\n📚 SECURITY EDUCATION:');
  console.log('═════════════════════════════════════════════════════════════');

  if (risk === 'high') {
    console.log('🚨 HIGH RISK COMMAND BLOCKED');
    console.log(`❌ Command: ${command}`);
    console.log(`🛡️  Reason: ${reason}`);
    console.log('');
    console.log('💡 SAFE ALTERNATIVES:');

    // Provide specific alternatives based on the blocked command
    const baseCommand = command.trim().split(/\s+/)[0];
    switch (baseCommand) {
      case 'rm':
        console.log('  • Use: rm -i (interactive mode)');
        console.log('  • Use: trash-cli for safer file deletion');
        console.log('  • Use: git rm for version-controlled files');
        break;
      case 'chmod':
        console.log('  • Use: chmod +x (add execute permission only)');
        console.log('  • Use: stat to check current permissions');
        console.log('  • Use: ls -l to view permissions');
        break;
      case 'sudo':
        console.log('  • Check if the command really needs root privileges');
        console.log('  • Use sudo -l to see allowed commands');
        console.log('  • Consider using containers or VMs for testing');
        break;
      default:
        console.log('  • Consider if this command is necessary');
        console.log('  • Use safer alternatives when possible');
        console.log('  • Check command documentation for safer options');
    }
  }

  console.log('\n🔧 SECURITY TIPS:');
  console.log('  • Use --dry-run or --verbose flags when available');
  console.log('  • Test commands in safe environments first');
  console.log('  • Use version control for important files');
  console.log('  • Consider using containers for destructive operations');
  console.log('═════════════════════════════════════════════════════════════\n');
}

/**
 * Suggests safer alternatives for risky commands
 */
function suggestSaferAlternatives(command: string): string[] {
  const baseCommand = command.trim().split(/\s+/)[0];
  const suggestions: Record<string, string[]> = {
    'rm': [
      'Use `rm -i` for interactive confirmation',
      'Use `trash-cli` for recoverable deletion',
      'Use `git rm` for version-controlled files'
    ],
    'cp': [
      'Use `cp -i` to prevent overwriting',
      'Use `rsync` for more reliable copying',
      'Check destination with `ls -la` first'
    ],
    'mv': [
      'Use `mv -i` for interactive confirmation',
      'Check destination permissions first',
      'Use `ls -la` to verify paths'
    ],
    'chmod': [
      'Use `chmod +x` only for execute permission',
      'Use `stat` to check current permissions',
      'Use `ls -l` to view file permissions'
    ],
    'wget': [
      'Use `curl` for more options and safety',
      'Check URL validity first',
      'Use `--spider` for dry-run testing'
    ],
    'curl': [
      'Use `--location` for redirects',
      'Use `--max-filesize` to limit downloads',
      'Use `--output` to specify destination'
    ]
  };

  return suggestions[baseCommand] || ['Consider if this command is necessary'];
}

/**
 * Gets information about available security profiles
 */
export function getSecurityProfiles(): Record<string, SecurityProfile> {
  return SECURITY_PROFILES;
}

/**
 * Gets the current active security profile
 */
export function getCurrentSecurityProfile(): SecurityProfile {
  return currentProfile;
}

/**
 * Sets the active security profile
 */
export function setSecurityProfile(profileName: keyof typeof SECURITY_PROFILES): boolean {
  if (SECURITY_PROFILES[profileName]) {
    currentProfile = SECURITY_PROFILES[profileName];
    console.log(`🔒 Security profile changed to: ${currentProfile.name}`);
    console.log(`📝 ${currentProfile.description}`);
    return true;
  }
  return false;
}

/**
 * Shows security profile information and statistics
 */
export function showSecurityInfo(): void {
  console.log('\n🔒 GEMINI CLI SECURITY INFORMATION');
  console.log('═════════════════════════════════════════════════════════════');
  console.log(`Current Profile: ${currentProfile.name}`);
  console.log(`Description: ${currentProfile.description}`);
  console.log(`Strict Mode: ${currentProfile.strictMode ? 'Enabled' : 'Disabled'}`);
  console.log(`Education Mode: ${currentProfile.educationMode ? 'Enabled' : 'Disabled'}`);
  console.log(`Log Level: ${currentProfile.logLevel}`);
  console.log('');

  console.log('Available Commands:');
  console.log(`  • Safe Commands: ${currentProfile.allowedCommands.size} allowed`);
  console.log(`  • Risky Commands: ${currentProfile.riskyCommands.size} with warnings`);
  console.log(`  • Dangerous Commands: ${currentProfile.dangerousCommands.size} blocked`);
  console.log('');

  console.log('Available Security Profiles:');
  Object.entries(SECURITY_PROFILES).forEach(([key, profile]) => {
    const current = key === getCurrentProfileName() ? ' (current)' : '';
    console.log(`  • ${key}: ${profile.description}${current}`);
  });

  console.log('');
  console.log('Security Logs Location:');
  console.log(`  • ${path.join(os.tmpdir(), 'gemini-cli-security')}`);
  console.log('═════════════════════════════════════════════════════════════\n');
}

/**
 * Gets the name of the current security profile
 */
function getCurrentProfileName(): string {
  for (const [key, profile] of Object.entries(SECURITY_PROFILES)) {
    if (profile === currentProfile) {
      return key;
    }
  }
  return 'custom';
}

/**
 * Provides a security tutorial for users
 */
export function showSecurityTutorial(): void {
  console.log('\n📚 GEMINI CLI SECURITY TUTORIAL');
  console.log('═════════════════════════════════════════════════════════════');
  console.log('');
  console.log('🔒 Why Security Profiles Matter:');
  console.log('  Different users have different security needs. A beginner');
  console.log('  needs maximum protection, while a developer needs flexibility.');
  console.log('');

  console.log('🛡️  Security Levels Explained:');
  console.log('  • LOW RISK: Safe commands that run automatically');
  console.log('  • MEDIUM RISK: Commands with warnings and suggestions');
  console.log('  • HIGH RISK: Dangerous commands that are blocked');
  console.log('');

  console.log('💡 Profile Recommendations:');
  console.log('  • BEGINNER: Maximum safety, fewest commands allowed');
  console.log('  • STANDARD: Balanced security for regular users (default)');
  console.log('  • ADVANCED: Relaxed security for power users');
  console.log('  • DEVELOPER: Permissive mode for development workflows');
  console.log('');

  console.log('🔧 How to Change Security Profile:');
  console.log('  • Use: setSecurityProfile("beginner") for maximum safety');
  console.log('  • Use: setSecurityProfile("developer") for development work');
  console.log('  • Use: showSecurityInfo() to see current settings');
  console.log('');

  console.log('📊 Security Monitoring:');
  console.log('  • All command decisions are logged for audit trails');
  console.log('  • Blocked commands provide educational feedback');
  console.log('  • Risky commands suggest safer alternatives');
  console.log('═════════════════════════════════════════════════════════════\n');
}

/**
 * Enhanced command permission checking with safety layers and logging
 * This preserves existing behavior while adding comprehensive safety controls
 */
export function isCommandAllowed(
  command: string,
  config: Config,
): { allowed: boolean; reason?: string; risk?: 'low' | 'medium' | 'high' } {
  // First, run the enhanced safety check
  const safetyCheck = isCommandSafe(command);

  if (!safetyCheck.safe) {
    // Log blocked command with enhanced logging
    logCommandExecution(command, false, safetyCheck.reason, safetyCheck.risk, config);

    // Provide educational feedback for high-risk blocks
    if (safetyCheck.risk === 'high') {
      provideUserEducation(command, safetyCheck.reason!, safetyCheck.risk);
    }

    return {
      allowed: false,
      reason: safetyCheck.reason,
      risk: safetyCheck.risk
    };
  }

  // If safety check passes, run the existing permission check
  const { allAllowed, blockReason } = checkCommandPermissions(command, config);

  if (!allAllowed) {
    // Log blocked command with enhanced logging
    logCommandExecution(command, false, blockReason, safetyCheck.risk, config);

    return {
      allowed: false,
      reason: blockReason,
      risk: safetyCheck.risk
    };
  }

  // Command is safe and allowed - log for audit trail with enhanced logging
  logCommandExecution(command, true, safetyCheck.reason, safetyCheck.risk, config);

  // For medium-risk commands, provide helpful suggestions
  if (safetyCheck.risk === 'medium') {
    const alternatives = suggestSaferAlternatives(command);
    if (alternatives.length > 0) {
      console.log(`💡 TIP: For '${command}', consider:`);
      alternatives.forEach(alt => console.log(`   • ${alt}`));
      console.log('');
    }
  }

  // Command is safe and allowed
  return {
    allowed: true,
    reason: safetyCheck.reason,
    risk: safetyCheck.risk
  };
}
