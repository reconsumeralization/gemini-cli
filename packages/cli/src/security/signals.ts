/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Signal detection utilities for security analysis
export function detectSystemOverride(s: string): boolean {
  return /\b(ignore previous|system message|developer instruction|reset rules)\b/i.test(s);
}

export function detectToolCoercion(s: string, acl: string[]): boolean {
  const toolMention = /\b(run|execute|call|invoke|use)\s+([a-z0-9._-]+)\b/i.exec(s);
  if (!toolMention) return false;
  const name = toolMention[2].toLowerCase();
  return !acl.map((t) => t.toLowerCase()).includes(name);
}

export function detectObfuscation(s: string): boolean {
  return /[`]{3}|base64|rot13|&#|\\x[0-9a-f]{2}/i.test(s) ||
         /[A-Za-z0-9+/]{80,}={0,2}/.test(s) ||
         /[\u200B-\u200D\uFEFF]/.test(s); // Zero-width characters
}

export function detectInjectionAttempt(s: string): boolean {
  return /\b(prompt|instruction|override|ignore|system|developer)\b.*\b(and|then|also|with)\b.*\b(do|run|execute|call)\b/i.test(s) ||
         /[\n\r].*\b(ignore|override|reset)\b.*[\n\r]/i.test(s);
}

export function detectDataExfiltration(s: string): boolean {
  return /\b(send|upload|exfiltrate|leak)\s+(data|info|secrets|credentials)\b/i.test(s) ||
         /\b(base64|encode).*(data|info|secrets)\b/i.test(s);
}

export function detectPrivilegeEscalation(s: string): boolean {
  return /\b(sudo|su|admin|root|superuser|elevate)\b/i.test(s) ||
         /\b(setuid|setgid|chmod.*777|chown.*root)\b/i.test(s);
}

export function detectCommandInjection(s: string): boolean {
  return /[`$]\([^)]*\)/.test(s) || // Command substitution
         /;\s*(curl|wget|nc|netcat|bash|sh|python|perl|ruby)/i.test(s) || // Command chaining
         /\|.*(curl|wget|nc|netcat|bash|sh)/i.test(s); // Pipe to shell
}

export function detectPathTraversal(s: string): boolean {
  return /\.\.[\/\\]/.test(s) || // Directory traversal
         /\/etc\/passwd|\/etc\/shadow|\/etc\/hosts/i.test(s) || // Unix sensitive files
         /windows\\system32|c:\\windows\\system32/i.test(s); // Windows sensitive paths
}

// Combined threat detection
export function analyzeThreatLevel(text: string, acl: string[]): {
  level: 'low' | 'medium' | 'high' | 'critical';
  threats: string[];
  confidence: number;
} {
  const threats: string[] = [];
  let score = 0;

  if (detectSystemOverride(text)) {
    threats.push('system_override');
    score += 30;
  }

  if (detectToolCoercion(text, acl)) {
    threats.push('tool_coercion');
    score += 25;
  }

  if (detectInjectionAttempt(text)) {
    threats.push('injection_attempt');
    score += 20;
  }

  if (detectCommandInjection(text)) {
    threats.push('command_injection');
    score += 40;
  }

  if (detectDataExfiltration(text)) {
    threats.push('data_exfiltration');
    score += 35;
  }

  if (detectPrivilegeEscalation(text)) {
    threats.push('privilege_escalation');
    score += 45;
  }

  if (detectPathTraversal(text)) {
    threats.push('path_traversal');
    score += 30;
  }

  if (detectObfuscation(text)) {
    threats.push('obfuscation');
    score += 15;
  }

  // Determine threat level
  let level: 'low' | 'medium' | 'high' | 'critical';
  if (score >= 70) level = 'critical';
  else if (score >= 40) level = 'high';
  else if (score >= 20) level = 'medium';
  else level = 'low';

  return {
    level,
    threats,
    confidence: Math.min(score, 100)
  };
}
