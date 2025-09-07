/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Advanced Feature Extraction for ML Training
import type { SecurityEvent, MLFeatures } from './dataCollector.js';

export interface AdvancedFeatures extends MLFeatures {
  // Linguistic features
  lexicalDiversity: number;
  readabilityScore: number;
  sentimentScore: number;

  // Structural features
  bracketBalance: number;
  quoteBalance: number;
  indentationLevel: number;

  // Semantic features
  keywordDensity: Record<string, number>;
  ngramPatterns: Record<string, number>;
  semanticSimilarity: number;

  // Behavioral features
  inputFrequency: number;
  temporalPatterns: number[];
  userBehaviorScore: number;

  // Domain-specific features
  securityKeywordScore: number;
  injectionPatternScore: number;
  obfuscationComplexity: number;

  // Advanced ML features
  embeddings?: number[]; // Would be populated by actual embedding model
  attentionWeights?: number[];
}

export class AdvancedFeatureExtractor {
  private keywordLists: Record<string, string[]> = {
    security: ['password', 'secret', 'key', 'token', 'admin', 'root', 'sudo', 'system'],
    injection: ['eval', 'exec', 'require', 'import', 'curl', 'wget', 'bash', 'sh'],
    override: ['ignore', 'override', 'reset', 'forget', 'bypass', 'disable'],
    obfuscation: ['base64', 'rot13', 'hex', 'encode', 'decode', 'obfuscate']
  };

  private suspiciousPatterns: RegExp[] = [
    /\b(eval|exec|spawn|require|import)\s*\(/gi,
    /javascript:\s*[^"'\s]+/gi,
    /data:\s*[^;]+;base64,[A-Za-z0-9+/]+/gi,
    /<script[^>]*>[\s\S]*?<\/script>/gi,
    /\b(ignore|override)\s+(all\s+)?previous\s+(instructions?|rules)/gi,
    /\b(curl|wget)\s+-s\s+[^|&;]+/gi,
    /\\x[0-9a-fA-F]{2}/gi,
    /[\u200B-\u200D\uFEFF]/g // Zero-width characters
  ];

  extractAdvancedFeatures(event: SecurityEvent): AdvancedFeatures {
    const baseFeatures = this.extractBasicFeatures(event);

    return {
      ...baseFeatures,

      // Linguistic features
      lexicalDiversity: this.calculateLexicalDiversity(event.input),
      readabilityScore: this.calculateReadabilityScore(event.input),
      sentimentScore: this.calculateSentimentScore(event.input),

      // Structural features
      bracketBalance: this.calculateBracketBalance(event.input),
      quoteBalance: this.calculateQuoteBalance(event.input),
      indentationLevel: this.calculateIndentationLevel(event.input),

      // Semantic features
      keywordDensity: this.calculateKeywordDensity(event.input),
      ngramPatterns: this.extractNgramPatterns(event.input),
      semanticSimilarity: this.calculateSemanticSimilarity(event.input),

      // Behavioral features
      inputFrequency: this.calculateInputFrequency(event),
      temporalPatterns: this.extractTemporalPatterns(event),
      userBehaviorScore: this.calculateUserBehaviorScore(event),

      // Domain-specific features
      securityKeywordScore: this.calculateSecurityKeywordScore(event.input),
      injectionPatternScore: this.calculateInjectionPatternScore(event.input),
      obfuscationComplexity: this.calculateObfuscationComplexity(event.input),

      // Advanced ML features (placeholders for actual models)
      embeddings: undefined,
      attentionWeights: undefined
    };
  }

  private extractBasicFeatures(event: SecurityEvent): MLFeatures {
    const text = event.input;
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
      retryCount: 0,
      similarEventsCount: 0,
      wasBlocked: event.decision === 'block',
      wasSanitized: event.decision === 'allow_sanitized',
      confidence: event.confidence || 0,
      threatLevel: ['low', 'medium', 'high', 'critical'].indexOf(event.labels.threatLevel)
    };
  }

  private calculateLexicalDiversity(text: string): number {
    const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 2);
    const uniqueWords = new Set(words);
    return uniqueWords.size / Math.max(words.length, 1);
  }

  private calculateReadabilityScore(text: string): number {
    // Simplified Flesch Reading Ease score
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const words = text.split(/\s+/).filter(w => w.length > 0);
    const syllables = this.countSyllables(text);

    if (sentences.length === 0 || words.length === 0) return 0;

    const avgSentenceLength = words.length / sentences.length;
    const avgSyllablesPerWord = syllables / words.length;

    return 206.835 - (1.015 * avgSentenceLength) - (84.6 * avgSyllablesPerWord);
  }

  private countSyllables(text: string): number {
    // Simple syllable counting
    const words = text.toLowerCase().split(/\W+/);
    return words.reduce((count, word) => {
      const vowels = word.match(/[aeiouy]+/g);
      return count + (vowels ? vowels.length : 1);
    }, 0);
  }

  private calculateSentimentScore(text: string): number {
    // Simple sentiment analysis based on keyword matching
    const positiveWords = ['good', 'safe', 'normal', 'legitimate', 'valid'];
    const negativeWords = ['attack', 'malicious', 'dangerous', 'threat', 'bypass', 'exploit'];

    const positiveCount = positiveWords.reduce((count, word) =>
      count + (text.toLowerCase().match(new RegExp(`\\b${word}\\b`, 'g')) || []).length, 0);

    const negativeCount = negativeWords.reduce((count, word) =>
      count + (text.toLowerCase().match(new RegExp(`\\b${word}\\b`, 'g')) || []).length, 0);

    return (positiveCount - negativeCount) / Math.max(positiveCount + negativeCount, 1);
  }

  private calculateBracketBalance(text: string): number {
    let balance = 0;
    for (const char of text) {
      if (char === '(' || char === '[' || char === '{') balance++;
      if (char === ')' || char === ']' || char === '}') balance--;
    }
    return Math.abs(balance);
  }

  private calculateQuoteBalance(text: string): number {
    const singleQuotes = (text.match(/'/g) || []).length;
    const doubleQuotes = (text.match(/"/g) || []).length;
    const backticks = (text.match(/`/g) || []).length;

    return Math.abs(singleQuotes % 2) + Math.abs(doubleQuotes % 2) + Math.abs(backticks % 2);
  }

  private calculateIndentationLevel(text: string): number {
    const lines = text.split('\n');
    const indentedLines = lines.filter(line => line.match(/^\s+/));
    return indentedLines.length / Math.max(lines.length, 1);
  }

  private calculateKeywordDensity(text: string): Record<string, number> {
    const density: Record<string, number> = {};
    const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 2);

    for (const [category, keywords] of Object.entries(this.keywordLists)) {
      let count = 0;
      for (const keyword of keywords) {
        count += (text.toLowerCase().match(new RegExp(`\\b${keyword}\\b`, 'g')) || []).length;
      }
      density[category] = count / Math.max(words.length, 1);
    }

    return density;
  }

  private extractNgramPatterns(text: string): Record<string, number> {
    const patterns: Record<string, number> = {};
    const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 0);

    // Extract bigrams
    for (let i = 0; i < words.length - 1; i++) {
      const bigram = `${words[i]}_${words[i + 1]}`;
      patterns[bigram] = (patterns[bigram] || 0) + 1;
    }

    // Extract trigrams
    for (let i = 0; i < words.length - 2; i++) {
      const trigram = `${words[i]}_${words[i + 1]}_${words[i + 2]}`;
      patterns[trigram] = (patterns[trigram] || 0) + 1;
    }

    return patterns;
  }

  private calculateSemanticSimilarity(text: string): number {
    // Placeholder for semantic similarity calculation
    // In a real implementation, this would use embeddings or semantic analysis
    const securityKeywords = this.keywordLists['security'];
    const injectionKeywords = this.keywordLists['injection'];

    const securityMatches = securityKeywords.reduce((count, keyword) =>
      count + (text.toLowerCase().match(new RegExp(`\\b${keyword}\\b`, 'g')) || []).length, 0);

    const injectionMatches = injectionKeywords.reduce((count, keyword) =>
      count + (text.toLowerCase().match(new RegExp(`\\b${keyword}\\b`, 'g')) || []).length, 0);

    return (securityMatches + injectionMatches) / Math.max(text.split(/\W+/).length, 1);
  }

  private calculateInputFrequency(_event: SecurityEvent): number {
    // Placeholder - would track how often similar inputs are seen
    return Math.random(); // Replace with actual frequency calculation
  }

  private extractTemporalPatterns(event: SecurityEvent): number[] {
    // Extract time-based patterns (hour of day, day of week, etc.)
    const date = new Date(event.timestamp);
    return [
      date.getHours() / 24, // Hour of day (0-1)
      date.getDay() / 7,    // Day of week (0-1)
      date.getDate() / 31,  // Day of month (0-1)
    ];
  }

  private calculateUserBehaviorScore(_event: SecurityEvent): number {
    // Calculate user behavior anomaly score
    // This would analyze patterns like request frequency, unusual timing, etc.
    return Math.random(); // Replace with actual behavior analysis
  }

  private calculateSecurityKeywordScore(text: string): number {
    const securityWords = this.keywordLists['security'];
    const matches = securityWords.reduce((count, word) =>
      count + (text.toLowerCase().match(new RegExp(`\\b${word}\\b`, 'g')) || []).length, 0);

    return matches / Math.max(text.split(/\W+/).length, 1);
  }

  private calculateInjectionPatternScore(text: string): number {
    let score = 0;
    for (const pattern of this.suspiciousPatterns) {
      const matches = text.match(pattern);
      if (matches) {
        score += matches.length;
      }
    }
    return score;
  }

  private calculateObfuscationComplexity(text: string): number {
    // Calculate complexity based on encoding patterns, unusual characters, etc.
    let complexity = 0;

    // Base64-like patterns
    complexity += (text.match(/[A-Za-z0-9+/]{10,}/g) || []).length;

    // Hex encoding
    complexity += (text.match(/\\[xX][0-9a-fA-F]{2}/g) || []).length * 2;

    // Unusual character sequences
    complexity += (text.match(/[^\x20-\x7E]{3,}/g) || []).length * 3;

    // Zero-width characters
    complexity += (text.match(/[\u200B-\u200D\uFEFF]/g) || []).length * 5;

    return complexity;
  }
}

export const featureExtractor = new AdvancedFeatureExtractor();
