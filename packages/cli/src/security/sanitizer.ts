/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Text sanitization utilities for MCP server security
export function sanitizeText(s: string): string {
  // Central place for redactions; idempotent
  return s
    .replace(/[`]{3,}[^`]*[`]{3,}/g, "[code-block-redacted]")
    .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, "[base64-redacted]");
}

// Advanced sanitization for different content types
export function sanitizeByType(text: string, contentType: 'user_input' | 'tool_output' | 'rag_chunk'): string {
  let sanitized = text;

  switch (contentType) {
    case 'user_input':
      // Remove potentially dangerous commands and URLs from user input
      sanitized = sanitized
        .replace(/\b(eval|exec|spawn|fork|system)\s*\(/gi, "[blocked-function-call]")
        .replace(/\b(import|require)\s*\(['"`][^'"`]*['"`]\)/gi, "[blocked-import]");
      break;

    case 'tool_output':
      // Sanitize tool outputs to prevent information leakage
      sanitized = sanitized
        .replace(/\b(password|secret|key|token)\s*[:=]\s*\S+/gi, "[redacted-credential]")
        .replace(/\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b/g, "[redacted-card-number]");
      break;

    case 'rag_chunk':
      // Sanitize RAG chunks from potentially untrusted sources
      sanitized = sanitized
        .replace(/\bjavascript:[^"'\s]+/gi, "[blocked-js-url]")
        .replace(/\bon\w+\s*=/gi, "[blocked-event-handler]");
      break;
  }

  // Apply general sanitization
  return sanitizeText(sanitized);
}
