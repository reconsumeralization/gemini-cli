/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Advanced Caching System for MCP Server Performance Optimization
import * as crypto from 'crypto';
import { logger } from '../utils/logger.js';

export interface CacheEntry<T = any> {
  key: string;
  value: T;
  timestamp: number;
  ttl: number;
  accessCount: number;
  lastAccessed: number;
  size: number;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface CacheConfig {
  maxSize: number; // Maximum cache size in bytes
  defaultTTL: number; // Default TTL in milliseconds
  cleanupInterval: number; // Cleanup interval in milliseconds
  compressionThreshold: number; // Compress entries larger than this (bytes)
  enableMetrics: boolean;
}

export interface CacheMetrics {
  totalEntries: number;
  totalSize: number;
  hitRate: number;
  missRate: number;
  evictionCount: number;
  compressionSavings: number;
  averageAccessTime: number;
  cacheUtilization: number;
}

export type CacheStrategy = 'lru' | 'lfu' | 'ttl' | 'size' | 'adaptive';

class CacheManager {
  private static instance: CacheManager;
  private cache: Map<string, CacheEntry> = new Map();
  private config: CacheConfig;
  private metrics: CacheMetrics;
  private cleanupInterval: NodeJS.Timeout;
  private accessTimes: number[] = [];

  // Specialized caches for different data types
  private responseCache: Map<string, CacheEntry> = new Map();
  private analyticsCache: Map<string, CacheEntry> = new Map();
  private securityCache: Map<string, CacheEntry> = new Map();
  private mlCache: Map<string, CacheEntry> = new Map();

  static getInstance(): CacheManager {
    if (!CacheManager.instance) {
      CacheManager.instance = new CacheManager();
    }
    return CacheManager.instance;
  }

  private constructor() {
    this.config = this.loadCacheConfig();
    this.metrics = this.initializeMetrics();
    this.startCleanupProcess();
  }

  private loadCacheConfig(): CacheConfig {
    return {
      maxSize: parseInt(process.env.CACHE_MAX_SIZE || '1073741824'), // 1GB default
      defaultTTL: parseInt(process.env.CACHE_DEFAULT_TTL || '3600000'), // 1 hour default
      cleanupInterval: parseInt(process.env.CACHE_CLEANUP_INTERVAL || '300000'), // 5 minutes
      compressionThreshold: parseInt(process.env.CACHE_COMPRESSION_THRESHOLD || '10240'), // 10KB
      enableMetrics: process.env.CACHE_ENABLE_METRICS !== 'false'
    };
  }

  private initializeMetrics(): CacheMetrics {
    return {
      totalEntries: 0,
      totalSize: 0,
      hitRate: 0,
      missRate: 0,
      evictionCount: 0,
      compressionSavings: 0,
      averageAccessTime: 0,
      cacheUtilization: 0
    };
  }

  async get<T>(key: string, namespace: string = 'default'): Promise<T | null> {
    const startTime = Date.now();
    const cache = this.getCacheByNamespace(namespace);
    const entry = cache.get(key);

    if (!entry) {
      this.recordMiss();
      return null;
    }

    // Check TTL
    if (Date.now() > entry.timestamp + entry.ttl) {
      cache.delete(key);
      this.recordMiss();
      this.updateMetrics();
      return null;
    }

    // Update access statistics
    entry.accessCount++;
    entry.lastAccessed = Date.now();

    // Record access time
    const accessTime = Date.now() - startTime;
    this.accessTimes.push(accessTime);
    if (this.accessTimes.length > 1000) {
      this.accessTimes = this.accessTimes.slice(-1000);
    }

    this.recordHit();
    this.updateMetrics();

    logger.debug('📋 Cache hit', { key, namespace, accessTime });

    return this.decompressIfNeeded(entry.value);
  }

  async set<T>(
    key: string,
    value: T,
    options: {
      ttl?: number;
      namespace?: string;
      tags?: string[];
      metadata?: Record<string, unknown>;
    } = {}
  ): Promise<void> {
    const ttl = options.ttl || this.config.defaultTTL;
    const namespace = options.namespace || 'default';
    const cache = this.getCacheByNamespace(namespace);

    // Check if we need to evict entries to make room
    const entrySize = this.calculateEntrySize(value);
    await this.ensureCapacity(entrySize, cache);

    const entry: CacheEntry<T> = {
      key,
      value: this.compressIfNeeded(value),
      timestamp: Date.now(),
      ttl,
      accessCount: 0,
      lastAccessed: Date.now(),
      size: entrySize,
      tags: options.tags,
      metadata: options.metadata
    };

    cache.set(key, entry);
    this.updateMetrics();

    logger.debug('💾 Cache set', { key, namespace, size: entrySize, ttl });
  }

  async invalidate(pattern: string, namespace: string = 'default'): Promise<number> {
    const cache = this.getCacheByNamespace(namespace);
    let invalidatedCount = 0;

    // Simple pattern matching (could be enhanced with regex)
    for (const [key, entry] of cache) {
      if (key.includes(pattern) || (entry.tags && entry.tags.some(tag => tag.includes(pattern)))) {
        cache.delete(key);
        invalidatedCount++;
      }
    }

    if (invalidatedCount > 0) {
      this.updateMetrics();
      logger.info('🗑️ Cache entries invalidated', { pattern, namespace, count: invalidatedCount });
    }

    return invalidatedCount;
  }

  async clear(namespace?: string): Promise<void> {
    if (namespace) {
      const cache = this.getCacheByNamespace(namespace);
      const clearedCount = cache.size;
      cache.clear();
      logger.info('🧹 Cache namespace cleared', { namespace, clearedCount });
    } else {
      // Clear all caches
      this.cache.clear();
      this.responseCache.clear();
      this.analyticsCache.clear();
      this.securityCache.clear();
      this.mlCache.clear();
      logger.info('🧹 All caches cleared');
    }

    this.updateMetrics();
  }

  getStats(namespace?: string): CacheMetrics & {
    entriesByNamespace: Record<string, number>;
    topAccessedKeys: Array<{ key: string; accessCount: number }>;
    cacheEfficiency: number;
  } {
    const stats = { ...this.metrics };

    if (namespace) {
      const cache = this.getCacheByNamespace(namespace);
      stats.totalEntries = cache.size;
      stats.totalSize = Array.from(cache.values()).reduce((sum, entry) => sum + entry.size, 0);
    }

    return {
      ...stats,
      entriesByNamespace: {
        default: this.cache.size,
        response: this.responseCache.size,
        analytics: this.analyticsCache.size,
        security: this.securityCache.size,
        ml: this.mlCache.size
      },
      topAccessedKeys: this.getTopAccessedKeys(),
      cacheEfficiency: this.calculateCacheEfficiency()
    };
  }

  // Specialized caching methods for MCP operations
  async cacheMCPResponse(
    toolName: string,
    params: Record<string, unknown>,
    response: any,
    ttl?: number
  ): Promise<void> {
    const cacheKey = this.generateMCPResponseKey(toolName, params);
    await this.set(cacheKey, response, {
      ttl: ttl || 300000, // 5 minutes default for MCP responses
      namespace: 'response',
      tags: ['mcp', toolName],
      metadata: { toolName, params }
    });
  }

  async getMCPResponse(
    toolName: string,
    params: Record<string, unknown>
  ): Promise<any | null> {
    const cacheKey = this.generateMCPResponseKey(toolName, params);
    return this.get(cacheKey, 'response');
  }

  async cacheAnalyticsReport(
    reportType: string,
    timeRange: { start: string; end: string },
    report: any
  ): Promise<void> {
    const cacheKey = `analytics_${reportType}_${timeRange.start}_${timeRange.end}`;
    await this.set(cacheKey, report, {
      ttl: 1800000, // 30 minutes for analytics reports
      namespace: 'analytics',
      tags: ['analytics', reportType],
      metadata: { reportType, timeRange }
    });
  }

  async getAnalyticsReport(
    reportType: string,
    timeRange: { start: string; end: string }
  ): Promise<any | null> {
    const cacheKey = `analytics_${reportType}_${timeRange.start}_${timeRange.end}`;
    return this.get(cacheKey, 'analytics');
  }

  async cacheSecurityAnalysis(
    input: string,
    analysis: any,
    ttl?: number
  ): Promise<void> {
    const cacheKey = crypto.createHash('sha256').update(input).digest('hex');
    await this.set(cacheKey, analysis, {
      ttl: ttl || 600000, // 10 minutes for security analysis
      namespace: 'security',
      tags: ['security', 'analysis'],
      metadata: { inputLength: input.length }
    });
  }

  async getSecurityAnalysis(input: string): Promise<any | null> {
    const cacheKey = crypto.createHash('sha256').update(input).digest('hex');
    return this.get(cacheKey, 'security');
  }

  async cacheMLPrediction(
    modelId: string,
    input: any,
    prediction: any
  ): Promise<void> {
    const cacheKey = `ml_${modelId}_${JSON.stringify(input)}`;
    await this.set(cacheKey, prediction, {
      ttl: 900000, // 15 minutes for ML predictions
      namespace: 'ml',
      tags: ['ml', modelId],
      metadata: { modelId, inputType: typeof input }
    });
  }

  async getMLPrediction(modelId: string, input: any): Promise<any | null> {
    const cacheKey = `ml_${modelId}_${JSON.stringify(input)}`;
    return this.get(cacheKey, 'ml');
  }

  private getCacheByNamespace(namespace: string): Map<string, CacheEntry> {
    switch (namespace) {
      case 'response': return this.responseCache;
      case 'analytics': return this.analyticsCache;
      case 'security': return this.securityCache;
      case 'ml': return this.mlCache;
      default: return this.cache;
    }
  }

  private generateMCPResponseKey(toolName: string, params: Record<string, unknown>): string {
    // Create a deterministic key based on tool name and parameters
    const paramString = JSON.stringify(params, Object.keys(params).sort());
    return `mcp_${toolName}_${crypto.createHash('md5').update(paramString).digest('hex')}`;
  }

  private async ensureCapacity(requiredSize: number, cache: Map<string, CacheEntry>): Promise<void> {
    let currentSize = Array.from(cache.values()).reduce((sum, entry) => sum + entry.size, 0);

    while (currentSize + requiredSize > this.config.maxSize && cache.size > 0) {
      // Evict entries using LRU strategy
      const entries = Array.from(cache.entries());
      entries.sort(([, a], [, b]) => a.lastAccessed - b.lastAccessed);

      const [keyToEvict, entryToEvict] = entries[0];
      cache.delete(keyToEvict);
      currentSize -= entryToEvict.size;
      this.metrics.evictionCount++;
    }
  }

  private calculateEntrySize(value: any): number {
    // Rough estimation of memory usage
    const jsonString = JSON.stringify(value);
    return Buffer.byteLength(jsonString, 'utf8');
  }

  private compressIfNeeded(value: any): any {
    // Simple compression simulation - in production, use actual compression
    const size = this.calculateEntrySize(value);
    if (size > this.config.compressionThreshold) {
      // Simulate compression by storing as base64
      const compressed = Buffer.from(JSON.stringify(value)).toString('base64');
      this.metrics.compressionSavings += size - compressed.length;
      return { _compressed: true, data: compressed };
    }
    return value;
  }

  private decompressIfNeeded(value: any): any {
    if (value && typeof value === 'object' && value._compressed) {
      return JSON.parse(Buffer.from(value.data, 'base64').toString());
    }
    return value;
  }

  private recordHit(): void {
    this.metrics.hitRate = (this.metrics.hitRate + 1) / 2; // Moving average
  }

  private recordMiss(): void {
    this.metrics.missRate = (this.metrics.missRate + 1) / 2; // Moving average
  }

  private updateMetrics(): void {
    const allCaches = [this.cache, this.responseCache, this.analyticsCache, this.securityCache, this.mlCache];
    this.metrics.totalEntries = allCaches.reduce((sum, cache) => sum + cache.size, 0);
    this.metrics.totalSize = allCaches.reduce((sum, cache) =>
      sum + Array.from(cache.values()).reduce((cacheSum, entry) => cacheSum + entry.size, 0), 0
    );
    this.metrics.cacheUtilization = this.metrics.totalSize / this.config.maxSize;
    this.metrics.averageAccessTime = this.accessTimes.length > 0 ?
      this.accessTimes.reduce((a, b) => a + b, 0) / this.accessTimes.length : 0;
  }

  private getTopAccessedKeys(): Array<{ key: string; accessCount: number }> {
    const allEntries = [
      ...Array.from(this.cache.entries()),
      ...Array.from(this.responseCache.entries()),
      ...Array.from(this.analyticsCache.entries()),
      ...Array.from(this.securityCache.entries()),
      ...Array.from(this.mlCache.entries())
    ];

    return allEntries
      .map(([key, entry]) => ({ key, accessCount: entry.accessCount }))
      .sort((a, b) => b.accessCount - a.accessCount)
      .slice(0, 10);
  }

  private calculateCacheEfficiency(): number {
    if (this.metrics.hitRate + this.metrics.missRate === 0) return 0;
    return this.metrics.hitRate / (this.metrics.hitRate + this.metrics.missRate);
  }

  private startCleanupProcess(): void {
    this.cleanupInterval = setInterval(() => {
      this.performCleanup();
    }, this.config.cleanupInterval);
  }

  private performCleanup(): void {
    const now = Date.now();
    let cleanedCount = 0;

    const allCaches = [this.cache, this.responseCache, this.analyticsCache, this.securityCache, this.mlCache];

    for (const cache of allCaches) {
      for (const [key, entry] of cache) {
        if (now > entry.timestamp + entry.ttl) {
          cache.delete(key);
          cleanedCount++;
        }
      }
    }

    if (cleanedCount > 0) {
      this.updateMetrics();
      logger.info('🧹 Cache cleanup completed', { cleanedCount });
    }
  }

  // Advanced cache operations
  async warmCache(cacheKey: string, fetchFunction: () => Promise<any>, namespace: string = 'default'): Promise<void> {
    try {
      const existing = await this.get(cacheKey, namespace);
      if (!existing) {
        const value = await fetchFunction();
        await this.set(cacheKey, value, { namespace });
        logger.info('🔥 Cache warmed', { cacheKey, namespace });
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Cache warming failed', { cacheKey, namespace, error: errorMessage });
    }
  }

  async preloadCommonQueries(): Promise<void> {
    logger.info('🚀 Preloading common cache entries');

    // Preload frequently accessed analytics data
    try {
      await this.warmCache('analytics_security_recent', async () => {
        // This would call the analytics engine
        return { type: 'security', data: 'recent' };
      }, 'analytics');
    } catch (error) {
      logger.warn('⚠️ Failed to preload analytics cache', { error: error.message });
    }
  }

  // Cache invalidation patterns
  async invalidateByTags(tags: string[], namespace?: string): Promise<number> {
    let totalInvalidated = 0;

    const caches = namespace ? [this.getCacheByNamespace(namespace)] : [
      this.cache, this.responseCache, this.analyticsCache, this.securityCache, this.mlCache
    ];

    for (const cache of caches) {
      for (const [key, entry] of cache) {
        if (entry.tags && entry.tags.some(tag => tags.includes(tag))) {
          cache.delete(key);
          totalInvalidated++;
        }
      }
    }

    if (totalInvalidated > 0) {
      this.updateMetrics();
      logger.info('🏷️ Cache entries invalidated by tags', { tags, totalInvalidated });
    }

    return totalInvalidated;
  }

  async invalidateByMetadata(
    metadataFilter: (metadata: Record<string, unknown>) => boolean,
    namespace?: string
  ): Promise<number> {
    let totalInvalidated = 0;

    const caches = namespace ? [this.getCacheByNamespace(namespace)] : [
      this.cache, this.responseCache, this.analyticsCache, this.securityCache, this.mlCache
    ];

    for (const cache of caches) {
      for (const [key, entry] of cache) {
        if (entry.metadata && metadataFilter(entry.metadata)) {
          cache.delete(key);
          totalInvalidated++;
        }
      }
    }

    if (totalInvalidated > 0) {
      this.updateMetrics();
      logger.info('📊 Cache entries invalidated by metadata filter', { totalInvalidated });
    }

    return totalInvalidated;
  }

  // Health check and monitoring
  getHealthStatus(): {
    status: 'healthy' | 'warning' | 'critical';
    utilizationPercent: number;
    hitRatePercent: number;
    issues: string[];
  } {
    const issues: string[] = [];
    let status: 'healthy' | 'warning' | 'critical' = 'healthy';

    const utilizationPercent = (this.metrics.cacheUtilization * 100);
    const hitRatePercent = (this.metrics.hitRate * 100);

    if (utilizationPercent > 90) {
      issues.push(`High cache utilization: ${utilizationPercent.toFixed(1)}%`);
      status = 'warning';
    }

    if (hitRatePercent < 70) {
      issues.push(`Low cache hit rate: ${hitRatePercent.toFixed(1)}%`);
      status = status === 'critical' ? 'critical' : 'warning';
    }

    if (this.metrics.evictionCount > 1000) {
      issues.push(`High eviction rate: ${this.metrics.evictionCount} entries evicted`);
      status = 'warning';
    }

    return {
      status,
      utilizationPercent,
      hitRatePercent,
      issues
    };
  }

  // Export/import cache data for backup/restore
  exportCacheData(): {
    timestamp: number;
    config: CacheConfig;
    entries: Array<{ namespace: string; key: string; entry: CacheEntry }>;
  } {
    const entries: Array<{ namespace: string; key: string; entry: CacheEntry }> = [];

    const cacheMappings = [
      { namespace: 'default', cache: this.cache },
      { namespace: 'response', cache: this.responseCache },
      { namespace: 'analytics', cache: this.analyticsCache },
      { namespace: 'security', cache: this.securityCache },
      { namespace: 'ml', cache: this.mlCache }
    ];

    for (const { namespace, cache } of cacheMappings) {
      for (const [key, entry] of cache) {
        entries.push({ namespace, key, entry });
      }
    }

    return {
      timestamp: Date.now(),
      config: this.config,
      entries
    };
  }

  importCacheData(data: {
    timestamp: number;
    config: CacheConfig;
    entries: Array<{ namespace: string; key: string; entry: CacheEntry }>;
  }): void {
    logger.info('📥 Importing cache data', { entriesCount: data.entries.length });

    for (const { namespace, key, entry } of data.entries) {
      const cache = this.getCacheByNamespace(namespace);
      cache.set(key, entry);
    }

    this.updateMetrics();
    logger.info('✅ Cache data imported successfully');
  }
}

export const cacheManager = CacheManager.getInstance();
