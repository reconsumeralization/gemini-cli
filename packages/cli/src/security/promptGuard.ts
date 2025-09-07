/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Prompt injection classifier for MCP server security
import type { ContextMeta, GuardResult, GuardDecision } from './types.js';
import { detectObfuscation, detectToolCoercion, detectSystemOverride } from './signals.js';

export async function classifyPrompt(text: string, meta: ContextMeta): Promise<GuardResult> {
  // Implementation here
  const reasons: string[] = [];
  const tags: string[] = [];

  if (detectSystemOverride(text)) {
    reasons.push("attempted system override");
    tags.push("system-override");
  }

  if (detectToolCoercion(text, meta.toolAcl)) {
    reasons.push("tool coercion");
    tags.push("tool-coercion");
  }

  if (detectObfuscation(text)) {
    reasons.push("obfuscation/encoding");
    tags.push("obfuscation");
  }

  if (!reasons.length) {
    return { decision: "allow", reasons: [], tags: [] };
  }

  // Simple policy: sanitize when possible, block if high-risk verbs outside ACL
  const sanitized = sanitizeHeuristics(text);
  const decision = tags.includes("tool-coercion") ? "allow_sanitized" : "allow_sanitized";

  return { decision, sanitized, reasons, tags };
}

// AI-enhanced threat analysis
export async function analyzeWithAI(text: string, meta: ContextMeta): Promise<{
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  reasoning: string;
  recommendedAction: GuardDecision; 
  confidence: number;
}> {
  // In production, this would call Gemini AI for intelligent analysis
  // For now, simulate AI analysis based on patterns

  const patterns = {
    systemOverride: /\b(ignore|override|reset|forget)\s+(all\s+)?previous\s+(instructions|rules|context)/i,
    toolCoercion: /\b(run|execute|invoke|call)\s+(secrets\.|admin\.|system\.|internal\.)/i,
    injection: /\b(eval|exec|require|import)\s*\(/i,
    obfuscation: /[\u200B-\u200D\uFEFF]|base64|rot13|javascript:/i,
    dataExfil: /\b(send|upload|exfiltrate)\s+(data|secrets|credentials)/i,
    privilegeEsc: /\b(sudo|su|root|admin|elevate)\b/i
  };

  let threatScore = 0;
  const detectedThreats: string[] = [];
  const reasoning: string[] = [];

  Object.entries(patterns).forEach(([threat, pattern]) => {
    if (pattern.test(text)) {
      detectedThreats.push(threat);
      threatScore += getThreatWeight(threat);
      reasoning.push(`${threat}: Pattern detected in input`);
    }
  });

  // Context-aware analysis
  if (meta.userRole === 'user' && detectedThreats.includes('systemOverride')) {
    threatScore += 20;
    reasoning.push('Context: User attempting system override');
  }

  if (meta.source === 'rag' && detectedThreats.includes('toolCoercion')) {
    threatScore += 15;
    reasoning.push('Context: RAG source attempting tool coercion');
  }

  // Determine threat level
  let threatLevel: 'low' | 'medium' | 'high' | 'critical';
  let recommendedAction: GuardDecision;
  let confidence: number;

  if (threatScore >= 70) {
    threatLevel = 'critical';
    recommendedAction = 'block';
    confidence = 95;
  } else if (threatScore >= 40) {
    threatLevel = 'high';
    recommendedAction = 'allow_sanitized';
    confidence = 85;
  } else if (threatScore >= 20) {
    threatLevel = 'medium';
    recommendedAction = 'allow_sanitized';
    confidence = 75;
  } else {
    threatLevel = 'low';
    recommendedAction = 'allow';
    confidence = 60;
  }

  return {
    threatLevel,
    reasoning: reasoning.join('; '),
    recommendedAction,
    confidence
  };
}

function getThreatWeight(threat: string): number {
  const weights: Record<string, number> = {
    systemOverride: 30,
    toolCoercion: 25,
    injection: 40,
    obfuscation: 15,
    dataExfil: 35,
    privilegeEsc: 45
  };
  return weights[threat] || 10;
}

// Heuristic sanitization; final pass happens in sanitizer module
function sanitizeHeuristics(s: string): string {
  // Strip URLs, shell verbs, and "ignore previous" phrases
  return s
    .replace(/\b(curl|wget|powershell|Invoke-WebRequest|rm|del|copy|scp)\b/gi, "[blocked-verb]")
    .replace(/\b(ignore (all )?previous (instructions|rules))\b/gi, "[blocked-override]")
    .replace(/\bhttps?:\/\/\S+/gi, "[url]");
}
