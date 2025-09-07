/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Advanced Rate Limiting with Multiple Strategies and Adaptive Behavior
import { logger } from './logger.js';

export interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per window
  strategy: 'fixed' | 'sliding' | 'token_bucket' | 'leaky_bucket' | 'adaptive';
  burstLimit?: number; // Allow burst requests
  refillRate?: number; // Tokens per second (for token bucket)
  capacity?: number; // Bucket capacity (for token/leaky bucket)
  adaptive?: {
    enabled: boolean;
    increaseThreshold: number; // CPU/memory usage threshold to increase limits
    decreaseThreshold: number; // CPU/memory usage threshold to decrease limits
    adjustmentFactor: number; // How much to adjust limits (0.1 = 10% change)
  };
  penalties?: {
    enabled: boolean;
    violationPenalty: number; // Extra delay for violations
    progressiveDelay: boolean; // Increase delay with repeated violations
    maxPenaltyDelay: number; // Maximum penalty delay
  };
}

export interface RateLimitEntry {
  identifier: string;
  requests: number[];
  tokens: number;
  lastRefill: number;
  violations: number;
  blockedUntil?: number;
  metadata: {
    userAgent?: string;
    ipAddress?: string;
    userId?: string;
    sessionId?: string;
  };
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
  limit: number;
  burstRemaining?: number;
}

export interface RateLimitMetrics {
  totalRequests: number;
  allowedRequests: number;
  blockedRequests: number;
  averageRequestRate: number;
  peakRequestRate: number;
  currentActiveUsers: number;
  topIdentifiers: Array<{ identifier: string; requests: number }>;
}

class RateLimiter {
  private config: RateLimitConfig;
  private entries = new Map<string, RateLimitEntry>();
  private metrics: RateLimitMetrics;
  private cleanupInterval: NodeJS.Timeout;
  private adaptiveInterval?: NodeJS.Timeout;

  constructor(config: RateLimitConfig) {
    this.config = config;
    this.metrics = this.initializeMetrics();
    this.startCleanup();
    if (config.adaptive?.enabled) {
      this.startAdaptiveAdjustment();
    }
  }

  private initializeMetrics(): RateLimitMetrics {
    return {
      totalRequests: 0,
      allowedRequests: 0,
      blockedRequests: 0,
      averageRequestRate: 0,
      peakRequestRate: 0,
      currentActiveUsers: 0,
      topIdentifiers: []
    };
  }

  async checkLimit(
    identifier: string,
    metadata?: RateLimitEntry['metadata']
  ): Promise<RateLimitResult> {
    this.metrics.totalRequests++;
    this.metrics.currentActiveUsers = this.entries.size;

    let entry = this.entries.get(identifier);
    if (!entry) {
      entry = this.createEntry(identifier, metadata);
    }

    const now = Date.now();

    // Check if currently blocked
    if (entry.blockedUntil && now < entry.blockedUntil) {
      this.metrics.blockedRequests++;
      return {
        allowed: false,
        remaining: 0,
        resetTime: entry.blockedUntil,
        retryAfter: Math.ceil((entry.blockedUntil - now) / 1000),
        limit: this.config.maxRequests
      };
    }

    let allowed = false;
    let remaining = 0;
    let resetTime = now + this.config.windowMs;

    switch (this.config.strategy) {
      case 'fixed':
        allowed = this.checkFixedWindow(entry, now);
        remaining = Math.max(0, this.config.maxRequests - entry.requests.length);
        break;

      case 'sliding':
        allowed = this.checkSlidingWindow(entry, now);
        remaining = this.calculateSlidingRemaining(entry, now);
        break;

      case 'token_bucket':
        allowed = this.checkTokenBucket(entry, now);
        remaining = Math.floor(entry.tokens);
        break;

      case 'leaky_bucket':
        allowed = this.checkLeakyBucket(entry, now);
        remaining = Math.max(0, (this.config.capacity || this.config.maxRequests) - entry.requests.length);
        break;

      case 'adaptive':
        allowed = this.checkAdaptive(entry, now);
        remaining = this.calculateAdaptiveRemaining(entry, now);
        break;
    }

    if (allowed) {
      this.metrics.allowedRequests++;
      entry.requests.push(now);

      // Keep only requests within the current window
      const cutoff = now - this.config.windowMs;
      entry.requests = entry.requests.filter(time => time > cutoff);

      // Update peak rate tracking
      const currentRate = entry.requests.length / (this.config.windowMs / 1000);
      if (currentRate > this.metrics.peakRequestRate) {
        this.metrics.peakRequestRate = currentRate;
      }
    } else {
      entry.violations++;
      this.metrics.blockedRequests++;

      // Apply penalties if configured
      if (this.config.penalties?.enabled) {
        this.applyPenalty(entry);
      }

      logger.warn('🚫 Rate limit exceeded', {
        identifier,
        violations: entry.violations,
        strategy: this.config.strategy
      });
    }

    // Update top identifiers
    this.updateTopIdentifiers();

    return {
      allowed,
      remaining,
      resetTime,
      limit: this.config.maxRequests,
      burstRemaining: this.config.burstLimit ? this.calculateBurstRemaining(entry) : undefined
    };
  }

  private createEntry(identifier: string, metadata?: RateLimitEntry['metadata']): RateLimitEntry {
    const entry: RateLimitEntry = {
      identifier,
      requests: [],
      tokens: this.config.capacity || this.config.maxRequests,
      lastRefill: Date.now(),
      violations: 0,
      metadata: metadata || {}
    };

    this.entries.set(identifier, entry);
    return entry;
  }

  private checkFixedWindow(entry: RateLimitEntry, now: number): boolean {
    const windowStart = now - this.config.windowMs;
    entry.requests = entry.requests.filter(time => time > windowStart);

    return entry.requests.length < this.config.maxRequests;
  }

  private checkSlidingWindow(entry: RateLimitEntry, now: number): boolean {
    const windowStart = now - this.config.windowMs;
    entry.requests = entry.requests.filter(time => time > windowStart);

    // Allow burst if configured
    const effectiveLimit = this.config.burstLimit || this.config.maxRequests;
    return entry.requests.length < effectiveLimit;
  }

  private checkTokenBucket(entry: RateLimitEntry, now: number): boolean {
    // Refill tokens based on time passed
    const timePassed = now - entry.lastRefill;
    const tokensToAdd = (timePassed / 1000) * (this.config.refillRate || 1);
    entry.tokens = Math.min(
      (this.config.capacity || this.config.maxRequests),
      entry.tokens + tokensToAdd
    );
    entry.lastRefill = now;

    if (entry.tokens >= 1) {
      entry.tokens -= 1;
      return true;
    }

    return false;
  }

  private checkLeakyBucket(entry: RateLimitEntry, now: number): boolean {
    const capacity = this.config.capacity || this.config.maxRequests;

    // Remove old requests (simulate leaking)
    const windowStart = now - this.config.windowMs;
    entry.requests = entry.requests.filter(time => time > windowStart);

    return entry.requests.length < capacity;
  }

  private checkAdaptive(entry: RateLimitEntry, now: number): boolean {
    // Start with sliding window logic, then apply adaptive adjustments
    const baseAllowed = this.checkSlidingWindow(entry, now);

    if (!this.config.adaptive?.enabled) {
      return baseAllowed;
    }

    // Get current system metrics (simplified)
    const systemLoad = this.getSystemLoad();

    if (systemLoad > this.config.adaptive.increaseThreshold) {
      // System is under load, be more restrictive
      return baseAllowed && entry.requests.length < (this.config.maxRequests * 0.7);
    } else if (systemLoad < this.config.adaptive.decreaseThreshold) {
      // System has capacity, be more permissive
      return entry.requests.length < (this.config.maxRequests * 1.3);
    }

    return baseAllowed;
  }

  private calculateSlidingRemaining(entry: RateLimitEntry, now: number): number {
    const windowStart = now - this.config.windowMs;
    const validRequests = entry.requests.filter(time => time > windowStart).length;
    return Math.max(0, this.config.maxRequests - validRequests);
  }

  private calculateAdaptiveRemaining(entry: RateLimitEntry, now: number): number {
    const baseRemaining = this.calculateSlidingRemaining(entry, now);

    if (!this.config.adaptive?.enabled) {
      return baseRemaining;
    }

    const systemLoad = this.getSystemLoad();
    let adjustmentFactor = 1;

    if (systemLoad > this.config.adaptive.increaseThreshold) {
      adjustmentFactor = 1 - this.config.adaptive.adjustmentFactor;
    } else if (systemLoad < this.config.adaptive.decreaseThreshold) {
      adjustmentFactor = 1 + this.config.adaptive.adjustmentFactor;
    }

    return Math.floor(baseRemaining * adjustmentFactor);
  }

  private calculateBurstRemaining(entry: RateLimitEntry): number {
    if (!this.config.burstLimit) return 0;

    const recentRequests = entry.requests.filter(
      time => Date.now() - time < 10000 // Last 10 seconds
    ).length;

    return Math.max(0, this.config.burstLimit - recentRequests);
  }

  private applyPenalty(entry: RateLimitEntry): void {
    if (!this.config.penalties) return;

    let penaltyDelay = this.config.penalties.violationPenalty;

    if (this.config.penalties.progressiveDelay) {
      penaltyDelay *= Math.min(entry.violations, 5); // Cap at 5x penalty
    }

    penaltyDelay = Math.min(penaltyDelay, this.config.penalties.maxPenaltyDelay);

    entry.blockedUntil = Date.now() + penaltyDelay;

    logger.info('⚠️ Rate limit penalty applied', {
      identifier: entry.identifier,
      violations: entry.violations,
      penaltyDelay
    });
  }

  private getSystemLoad(): number {
    // Simplified system load calculation
    // In production, this would use actual system metrics
    return Math.random() * 100; // Placeholder
  }

  private updateTopIdentifiers(): void {
    const sortedEntries = Array.from(this.entries.entries())
      .map(([identifier, entry]) => ({
        identifier,
        requests: entry.requests.length
      }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 10);

    this.metrics.topIdentifiers = sortedEntries;
  }

  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.performCleanup();
    }, this.config.windowMs / 4); // Cleanup 4 times per window
  }

  private performCleanup(): void {
    const now = Date.now();
    const cutoff = now - this.config.windowMs;

    for (const [identifier, entry] of this.entries) {
      // Remove old requests
      entry.requests = entry.requests.filter(time => time > cutoff);

      // Remove entries with no recent activity
      if (entry.requests.length === 0 && !entry.blockedUntil) {
        this.entries.delete(identifier);
      }
    }
  }

  private startAdaptiveAdjustment(): void {
    if (!this.config.adaptive?.enabled) return;

    this.adaptiveInterval = setInterval(() => {
      this.performAdaptiveAdjustment();
    }, 60000); // Adjust every minute
  }

  private performAdaptiveAdjustment(): void {
    const systemLoad = this.getSystemLoad();
    const currentRate = this.metrics.totalRequests / (this.config.windowMs / 1000);

    if (systemLoad > this.config.adaptive.increaseThreshold) {
      // Reduce limits
      this.config.maxRequests = Math.floor(this.config.maxRequests * (1 - this.config.adaptive.adjustmentFactor));
      logger.info('📉 Adaptive rate limiting: Reduced limits due to high system load', {
        newLimit: this.config.maxRequests,
        systemLoad
      });
    } else if (systemLoad < this.config.adaptive.decreaseThreshold && currentRate < this.config.maxRequests * 0.5) {
      // Increase limits
      this.config.maxRequests = Math.floor(this.config.maxRequests * (1 + this.config.adaptive.adjustmentFactor));
      logger.info('📈 Adaptive rate limiting: Increased limits due to low system load', {
        newLimit: this.config.maxRequests,
        systemLoad
      });
    }
  }

  // Public API methods
  getMetrics(): RateLimitMetrics {
    return { ...this.metrics };
  }

  getEntry(identifier: string): RateLimitEntry | undefined {
    return this.entries.get(identifier);
  }

  reset(identifier?: string): void {
    if (identifier) {
      this.entries.delete(identifier);
    } else {
      this.entries.clear();
      this.metrics = this.initializeMetrics();
    }
  }

  updateConfig(newConfig: Partial<RateLimitConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info('⚙️ Rate limiter configuration updated', { config: this.config });
  }

  getConfig(): RateLimitConfig {
    return { ...this.config };
  }

  getAllEntries(): Map<string, RateLimitEntry> {
    return new Map(this.entries);
  }

  // Health monitoring
  getHealthStatus(): {
    status: 'healthy' | 'warning' | 'critical';
    activeEntries: number;
    blockedEntries: number;
    violationRate: number;
    averageRequestRate: number;
    issues: string[];
  } {
    const issues: string[] = [];
    let status: 'healthy' | 'warning' | 'critical' = 'healthy';

    const blockedEntries = Array.from(this.entries.values())
      .filter(entry => entry.blockedUntil && Date.now() < entry.blockedUntil).length;

    const totalViolations = Array.from(this.entries.values())
      .reduce((sum, entry) => sum + entry.violations, 0);

    const violationRate = this.metrics.totalRequests > 0 ?
      (totalViolations / this.metrics.totalRequests) * 100 : 0;

    if (blockedEntries > this.entries.size * 0.1) {
      issues.push(`High number of blocked entries: ${blockedEntries}`);
      status = 'warning';
    }

    if (violationRate > 5) {
      issues.push(`High violation rate: ${violationRate.toFixed(1)}%`);
      status = 'warning';
    }

    if (this.entries.size > 10000) {
      issues.push(`High number of tracked entries: ${this.entries.size}`);
      status = 'warning';
    }

    return {
      status,
      activeEntries: this.entries.size,
      blockedEntries,
      violationRate,
      averageRequestRate: this.metrics.averageRequestRate,
      issues
    };
  }

  async shutdown(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    if (this.adaptiveInterval) {
      clearInterval(this.adaptiveInterval);
    }
    this.entries.clear();
    logger.info('🔌 Rate limiter shutdown');
  }
}

// Factory functions for common rate limiting configurations
export function createAPIProtectionLimiter(): RateLimiter {
  return new RateLimiter({
    windowMs: 60000, // 1 minute
    maxRequests: 100,
    strategy: 'sliding',
    burstLimit: 150,
    penalties: {
      enabled: true,
      violationPenalty: 30000, // 30 seconds
      progressiveDelay: true,
      maxPenaltyDelay: 300000 // 5 minutes
    }
  });
}

export function createUserActionLimiter(): RateLimiter {
  return new RateLimiter({
    windowMs: 300000, // 5 minutes
    maxRequests: 50,
    strategy: 'token_bucket',
    capacity: 100,
    refillRate: 1, // 1 token per second
    adaptive: {
      enabled: true,
      increaseThreshold: 80,
      decreaseThreshold: 30,
      adjustmentFactor: 0.2
    }
  });
}

export function createBruteForceProtectionLimiter(): RateLimiter {
  return new RateLimiter({
    windowMs: 900000, // 15 minutes
    maxRequests: 5,
    strategy: 'fixed',
    penalties: {
      enabled: true,
      violationPenalty: 1800000, // 30 minutes
      progressiveDelay: true,
      maxPenaltyDelay: 3600000 // 1 hour
    }
  });
}

export function createResourceProtectionLimiter(): RateLimiter {
  return new RateLimiter({
    windowMs: 3600000, // 1 hour
    maxRequests: 1000,
    strategy: 'leaky_bucket',
    capacity: 2000,
    adaptive: {
      enabled: true,
      increaseThreshold: 90,
      decreaseThreshold: 20,
      adjustmentFactor: 0.15
    }
  });
}

// Registry for managing multiple rate limiters
export class RateLimiterRegistry {
  private static instance: RateLimiterRegistry;
  private limiters = new Map<string, RateLimiter>();

  static getInstance(): RateLimiterRegistry {
    if (!RateLimiterRegistry.instance) {
      RateLimiterRegistry.instance = new RateLimiterRegistry();
    }
    return RateLimiterRegistry.instance;
  }

  register(name: string, limiter: RateLimiter): void {
    this.limiters.set(name, limiter);
  }

  get(name: string): RateLimiter | undefined {
    return this.limiters.get(name);
  }

  getAll(): Map<string, RateLimiter> {
    return new Map(this.limiters);
  }

  getHealthStatus(): {
    overallStatus: 'healthy' | 'warning' | 'critical';
    limiterStatuses: Record<string, ReturnType<RateLimiter['getHealthStatus']>>;
    issues: string[];
  } {
    const limiterStatuses: Record<string, any> = {};
    let overallStatus: 'healthy' | 'warning' | 'critical' = 'healthy';
    const issues: string[] = [];

    for (const [name, limiter] of this.limiters) {
      const status = limiter.getHealthStatus();
      limiterStatuses[name] = status;

      if (status.status === 'critical') {
        overallStatus = 'critical';
      } else if (status.status === 'warning' && overallStatus === 'healthy') {
        overallStatus = 'warning';
      }

      if (status.issues.length > 0) {
        issues.push(`${name}: ${status.issues.join(', ')}`);
      }
    }

    return {
      overallStatus,
      limiterStatuses,
      issues
    };
  }

  async shutdown(): Promise<void> {
    for (const limiter of this.limiters.values()) {
      await limiter.shutdown();
    }
    logger.info('🔌 Rate Limiter Registry shutdown');
  }
}

export const rateLimiterRegistry = RateLimiterRegistry.getInstance();

// Initialize common rate limiters
rateLimiterRegistry.register('api_protection', createAPIProtectionLimiter());
rateLimiterRegistry.register('user_actions', createUserActionLimiter());
rateLimiterRegistry.register('brute_force', createBruteForceProtectionLimiter());
rateLimiterRegistry.register('resource_protection', createResourceProtectionLimiter());
