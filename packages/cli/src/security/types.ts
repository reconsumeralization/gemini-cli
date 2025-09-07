/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Shared types for MCP server security modules
export type GuardDecision = "allow" | "allow_sanitized" | "escalate" | "block";

export interface GuardResult {
  decision: GuardDecision;
  sanitized?: string;
  reasons: string[];
  tags: string[]; // e.g., ["system-override","tool-coercion","obfuscation"]
}

export interface ContextMeta {
  source: "user" | "rag" | "tool";
  userRole: "user" | "admin" | "service";
  toolAcl: string[];       // allowed tool names
  provenance?: string;     // URL/doc/tool name
  conversationId: string;  // for cross-turn auditing
}

export interface ServerOptions {
  port?: number;
  host?: string;
  policyPath?: string;
  testMode?: boolean; // enable fuzz harness
  enableSecurity?: boolean; // enable security middleware
  enableMetrics?: boolean; // enable real-time metrics
  metricsPort?: number; // port for metrics dashboard
}
