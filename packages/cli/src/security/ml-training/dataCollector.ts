/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// ML Training Data Collection System
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../../utils/logger.js';
import type { ContextMeta, GuardDecision } from '../types.js';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  input: string;
  output?: string;
  decision: GuardDecision;
  tags: string[];
  context: ContextMeta;
  confidence?: number;
  processingTime: number;
  source: 'fuzzer' | 'user' | 'test';
  labels: {
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    attackType: string[];
    bypassAttempt: boolean;
    successfulAttack: boolean;
  };
}

export interface TrainingDataset {
  events: SecurityEvent[];
  metadata: {
    collectedAt: string;
    totalEvents: number;
    labelDistribution: Record<string, number>;
    sourceDistribution: Record<string, number>;
    timeRange: {
      start: string;
      end: string;
    };
  };
  features: MLFeatures[];
}

export interface MLFeatures {
  eventId: string;
  // Text-based features
  textLength: number;
  wordCount: number;
  sentenceCount: number;
  avgWordLength: number;
  containsSpecialChars: boolean;
  containsUrls: boolean;
  containsCommands: boolean;
  containsSystemKeywords: boolean;

  // Pattern-based features
  base64PatternCount: number;
  hexPatternCount: number;
  scriptTagCount: number;
  overrideKeywordCount: number;

  // Context features
  userRole: 'user' | 'admin' | 'service';
  sourceType: 'user' | 'rag' | 'tool';
  toolAclSize: number;
  hasProvenance: boolean;

  // Behavioral features
  processingTime: number;
  retryCount: number;
  similarEventsCount: number;

  // Outcome features
  wasBlocked: boolean;
  wasSanitized: boolean;
  confidence: number;
  threatLevel: number; // 0-3 scale
}

class SecurityDataCollector {
  private static instance: SecurityDataCollector;
  private events: SecurityEvent[] = [];
  private maxEvents: number = 10000;
  private dataDir: string;

  static getInstance(): SecurityDataCollector {
    if (!SecurityDataCollector.instance) {
      SecurityDataCollector.instance = new SecurityDataCollector();
    }
    return SecurityDataCollector.instance;
  }

  private constructor() {
    this.dataDir = path.join(process.cwd(), 'security-training-data');
    this.ensureDataDirectory();
    this.loadExistingData();
  }

  private ensureDataDirectory(): void {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
      logger.info('📁 Created security training data directory', { path: this.dataDir });
    }
  }

  private loadExistingData(): void {
    try {
      const dataFile = path.join(this.dataDir, 'events.json');
      if (fs.existsSync(dataFile)) {
        const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
        this.events = data.events || [];
        logger.info('📦 Loaded existing training data', { eventCount: this.events.length });
      }
    } catch (error) {
      logger.warn('⚠️ Failed to load existing training data', { error: (error as Error).message });
    }
  }

  recordSecurityEvent(
    input: string,
    decision: GuardDecision,
    tags: string[],
    context: ContextMeta,
    options: {
      output?: string;
      confidence?: number;
      processingTime: number;
      source?: 'fuzzer' | 'user' | 'test';
      attackType?: string[];
      bypassAttempt?: boolean;
      successfulAttack?: boolean;
    } = { processingTime: 0 }
  ): void {
    const event: SecurityEvent = {
      id: `event_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      input,
      output: options.output,
      decision,
      tags,
      context,
      confidence: options.confidence,
      processingTime: options.processingTime,
      source: options.source || 'user',
      labels: {
        threatLevel: this.calculateThreatLevel(tags, decision),
        attackType: options.attackType || this.inferAttackType(tags),
        bypassAttempt: options.bypassAttempt || false,
        successfulAttack: options.successfulAttack || (decision === 'allow' && tags.length > 0)
      }
    };

    this.events.push(event);

    // Maintain max events limit
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(-this.maxEvents);
    }

    // Auto-save periodically
    if (this.events.length % 100 === 0) {
      this.saveData();
    }

    logger.debug('📝 Recorded security event', {
      id: event.id,
      decision,
      threatLevel: event.labels.threatLevel,
      source: event.source
    });
  }

  private calculateThreatLevel(tags: string[], decision: GuardDecision): 'low' | 'medium' | 'high' | 'critical' {
    const threatIndicators = [
      'system-override', 'tool-coercion', 'command-injection',
      'privilege-escalation', 'data-exfiltration', 'obfuscation'
    ];

    const threatCount = tags.filter(tag => threatIndicators.includes(tag)).length;

    if (decision === 'block' || threatCount >= 3) return 'critical';
    if (threatCount >= 2) return 'high';
    if (threatCount >= 1) return 'medium';
    return 'low';
  }

  private inferAttackType(tags: string[]): string[] {
    const attackMap: Record<string, string> = {
      'system-override': 'system_override',
      'tool-coercion': 'tool_coercion',
      'command-injection': 'injection',
      'obfuscation': 'obfuscation',
      'data-exfiltration': 'data_exfil',
      'privilege-escalation': 'privilege_esc'
    };

    return tags
      .map(tag => attackMap[tag])
      .filter(Boolean)
      .filter((value, index, self) => self.indexOf(value) === index);
  }

  generateTrainingDataset(): TrainingDataset {
    logger.info('🎯 Generating training dataset', { eventCount: this.events.length });

    const features = this.events.map(event => this.extractFeatures(event));

    const labelDistribution = this.events.reduce((acc, event) => {
      acc[event.labels.threatLevel] = (acc[event.labels.threatLevel] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const sourceDistribution = this.events.reduce((acc, event) => {
      acc[event.source] = (acc[event.source] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const timestamps = this.events.map(e => new Date(e.timestamp).getTime());
    const minTime = Math.min(...timestamps);
    const maxTime = Math.max(...timestamps);

    return {
      events: this.events,
      metadata: {
        collectedAt: new Date().toISOString(),
        totalEvents: this.events.length,
        labelDistribution,
        sourceDistribution,
        timeRange: {
          start: new Date(minTime).toISOString(),
          end: new Date(maxTime).toISOString()
        }
      },
      features
    };
  }

  private extractFeatures(event: SecurityEvent): MLFeatures {
    const text = event.input;

    // Text analysis
    const words = text.split(/\s+/).filter(w => w.length > 0);
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);

    return {
      eventId: event.id,
      textLength: text.length,
      wordCount: words.length,
      sentenceCount: sentences.length,
      avgWordLength: words.length > 0 ? words.reduce((sum, word) => sum + word.length, 0) / words.length : 0,
      containsSpecialChars: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(text),
      containsUrls: /https?:\/\/[^\s]+/.test(text),
      containsCommands: /\b(curl|wget|bash|sh|python|perl|ruby|powershell)\b/i.test(text),
      containsSystemKeywords: /\b(ignore|override|system|admin|root|sudo)\b/i.test(text),
      base64PatternCount: (text.match(/[A-Za-z0-9+/]{20,}=*={0,2}/g) || []).length,
      hexPatternCount: (text.match(/\\[xX][0-9a-fA-F]{2}/g) || []).length,
      scriptTagCount: (text.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || []).length,
      overrideKeywordCount: (text.match(/\b(ignore|override|reset|forget)\b/gi) || []).length,
      userRole: event.context.userRole,
      sourceType: event.context.source,
      toolAclSize: event.context.toolAcl.length,
      hasProvenance: !!event.context.provenance,
      processingTime: event.processingTime,
      retryCount: 0, // Would be tracked separately
      similarEventsCount: 0, // Would be calculated based on text similarity
      wasBlocked: event.decision === 'block',
      wasSanitized: event.decision === 'allow_sanitized',
      confidence: event.confidence || 0,
      threatLevel: ['low', 'medium', 'high', 'critical'].indexOf(event.labels.threatLevel)
    };
  }

  saveData(): void {
    try {
      const dataFile = path.join(this.dataDir, 'events.json');
      const dataset = this.generateTrainingDataset();

      fs.writeFileSync(dataFile, JSON.stringify({
        events: this.events,
        metadata: dataset.metadata
      }, null, 2));

      logger.info('💾 Saved training data', {
        eventCount: this.events.length,
        file: dataFile
      });
    } catch (error) {
      logger.error('❌ Failed to save training data', { error: (error as Error).message });
    }
  }

  exportForTraining(): { features: MLFeatures[]; labels: number[] } {
    const dataset = this.generateTrainingDataset();

    return {
      features: dataset.features,
      labels: dataset.features.map(f => f.threatLevel)
    };
  }

  clearData(): void {
    this.events = [];
    logger.info('🗑️ Cleared training data');
  }

  getStats(): {
    totalEvents: number;
    recentEvents: number;
    threatDistribution: Record<string, number>;
    sourceDistribution: Record<string, number>;
  } {
    const last24h = Date.now() - (24 * 60 * 60 * 1000);
    const recentEvents = this.events.filter(e => new Date(e.timestamp).getTime() > last24h).length;

    const threatDistribution = this.events.reduce((acc, event) => {
      acc[event.labels.threatLevel] = (acc[event.labels.threatLevel] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const sourceDistribution = this.events.reduce((acc, event) => {
      acc[event.source] = (acc[event.source] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalEvents: this.events.length,
      recentEvents,
      threatDistribution,
      sourceDistribution
    };
  }
}

export const dataCollector = SecurityDataCollector.getInstance();
