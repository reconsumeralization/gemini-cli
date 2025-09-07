/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Policy engine for MCP server tool access control
import type { ContextMeta } from './types.js';
import * as fs from 'fs';

export interface PolicyDecision {
  block: boolean;
  reasons: string[];
  maskedArgs?: Record<string, string>;
}

export interface PolicySpec {
  allowlist: {
    tools: string[];
    domains: string[];
  };
  denylist: {
    verbs: string[];
  };
  defaults: {
    toolAcl: string[];
    rateLimits: {
      user: number;
      admin: number;
      service: number;
    };
  };
}

export async function evaluatePolicy(req: Record<string, unknown>, meta: ContextMeta, policyPath?: string): Promise<PolicyDecision> {
  const spec = await loadPolicy(policyPath);
  const reasons: string[] = [];
  let block = false;

  // Example: disallow network/file tools unless in ACL
  const tool = extractToolName(req);
  if (tool && !spec.allowlist.tools.includes(tool)) {
    block = true;
    reasons.push(`tool ${tool} not in ACL`);
  }

  // Example: block untrusted provenance in RAG
  if (meta.source === "rag" && !isTrustedProvenance(meta.provenance, spec)) {
    block = true;
    reasons.push("untrusted provenance");
  }

  // Example: restrict admin tools to admin users
  if (tool?.startsWith('admin_') && meta.userRole !== 'admin') {
    block = true;
    reasons.push("insufficient privileges for admin tool");
  }

  // Example: rate limiting based on user role
  if (meta.userRole === 'service' && hasExceededRateLimit(meta)) {
    block = true;
    reasons.push("rate limit exceeded");
  }

  return { block, reasons };
}

function extractToolName(req: Record<string, unknown>): string | undefined {
  const params = req['params'] as Record<string, unknown> | undefined;
  const route = req['route'] as string | undefined;
  
  return (params?.['name'] as string) || route?.split('/').pop();
}

async function loadPolicy(policyPath?: string): Promise<PolicySpec> {
  if (policyPath && fs.existsSync(policyPath)) {
    try {
      const content = fs.readFileSync(policyPath, 'utf8');
      return JSON.parse(content) as PolicySpec;
    } catch (error) {
      console.warn('Failed to load policy file, using defaults:', error);
    }
  }

  // Default policy - load from config or use permissive defaults
  return {
    allowlist: {
      tools: [
        'get_project_context', 'analyze_project_health', 'validate_project_setup',
        'create_fuzzer_template', 'check_license_compliance', 'build_fuzzers_locally',
        'optimize_build_process', 'run_comprehensive_tests', 'debug_fuzzer_crash',
        'security_research_conduct', 'vulnerability_management', 'setup_cicd_pipeline',
        'run_fuzzer', 'list_fuzzers', 'get_fuzzer_stats', 'generate_seed_corpus'
      ],
      domains: ['githubusercontent.com', 'googleusercontent.com']
    },
    denylist: {
      verbs: ['shell.exec', 'net.http', 'fs.write']
    },
    defaults: {
      toolAcl: [
        'list_fuzzers', 'get_fuzzer_stats', 'get_project_context', 'analyze_project_health'
      ],
      rateLimits: {
        user: 100,
        admin: 1000,
        service: 10000
      }
    }
  };
}

function isTrustedProvenance(p?: string, spec?: PolicySpec): boolean {
  if (!p) return false;
  return !!spec?.allowlist?.domains?.some((d: string) => p.includes(d));
}

function hasExceededRateLimit(_meta: ContextMeta): boolean {
  // Simple rate limiting - in production, this would use Redis or similar
  // For now, return false (no rate limiting)
  return false;
}

export async function loadPolicySpec(policyPath?: string): Promise<PolicySpec> {
  return loadPolicy(policyPath);
}
