/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Output guard for MCP server response sanitization
import type { ContextMeta, GuardResult } from './types';
import { sanitizeText } from './sanitizer';
import { detectSystemOverride, detectToolCoercion } from './signals';

export async function outputGuard(text: string, meta: ContextMeta): Promise<GuardResult> {
  const reasons: string[] = [];
  const tags: string[] = [];

  if (detectSystemOverride(text)) {
    reasons.push("reflected system override");
    tags.push("system-override");
  }

  if (detectToolCoercion(text, meta.toolAcl)) {
    reasons.push("reflected tool coercion");
    tags.push("tool-coercion");
  }

  // Check for sensitive information leakage
  if (containsSensitiveInfo(text)) {
    reasons.push("potential information leakage");
    tags.push("information-leakage");
  }

  // Check for malicious content in tool outputs
  if (containsMaliciousPatterns(text)) {
    reasons.push("malicious content detected");
    tags.push("malicious-content");
  }

  if (!reasons.length) {
    return { decision: "allow", reasons: [], tags: [] };
  }

  const sanitized = sanitizeText(text);
  return { decision: "allow_sanitized", sanitized, reasons, tags };
}

function containsSensitiveInfo(text: string): boolean {
  // Check for credentials, tokens, keys, etc.
  return /\b(password|secret|key|token|api_key|auth_token)\s*[:=]\s*\S+/i.test(text) ||
         /\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b/.test(text) || // Credit card pattern
         /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/.test(text); // JWT pattern
}

function containsMaliciousPatterns(text: string): boolean {
  // Check for potentially malicious patterns in output
  return /\b(eval|exec|spawn|fork|system|require|import)\s*\(/i.test(text) ||
         /\bjavascript:[^"'\s]+/i.test(text) || // JavaScript URLs
         /\bon\w+\s*=/i.test(text) || // Event handlers
         /<script[^>]*>[\s\S]*?<\/script>/i.test(text) || // Script tags
         /\bdata:[^;]+;base64,[A-Za-z0-9+/]+={0,2}\b/i.test(text); // Data URLs
}
