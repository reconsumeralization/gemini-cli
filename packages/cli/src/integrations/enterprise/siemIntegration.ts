/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// SIEM Integration System for Enterprise Security Monitoring
import * as https from 'https';
import * as http from 'http';
import { logger } from '../../utils/logger.js';
import { AnomalyAlert } from '../../security/anomaly/anomalyDetector.js';

export interface SIEMConfig {
  enabled: boolean;
  provider: 'splunk' | 'elasticsearch' | 'sumologic' | 'datadog' | 'custom';
  endpoint: string;
  apiKey?: string;
  username?: string;
  password?: string;
  index?: string;
  sourceType?: string;
  batchSize: number;
  flushInterval: number;
  retryAttempts: number;
  retryDelay: number;
}

export interface SIEMEvent {
  timestamp: string;
  eventType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  message: string;
  userId?: string;
  sessionId?: string;
  resource: string;
  action: string;
  result: 'success' | 'failure' | 'blocked';
  metadata: Record<string, unknown>;
  correlationId?: string;
}

class SIEMIntegrationManager {
  private static instance: SIEMIntegrationManager;
  private config: SIEMConfig;
  private eventBuffer: SIEMEvent[] = [];
  private flushTimer: NodeJS.Timeout;
  private isInitialized = false;

  static getInstance(): SIEMIntegrationManager {
    if (!SIEMIntegrationManager.instance) {
      SIEMIntegrationManager.instance = new SIEMIntegrationManager();
    }
    return SIEMIntegrationManager.instance;
  }

  private constructor() {
    this.config = this.loadSIEMConfig();
    if (this.config.enabled) {
      this.initializeSIEM();
    }
  }

  private loadSIEMConfig(): SIEMConfig {
    return {
      enabled: process.env.SIEM_ENABLED === 'true',
      provider: (process.env.SIEM_PROVIDER as SIEMConfig['provider']) || 'splunk',
      endpoint: process.env.SIEM_ENDPOINT || '',
      apiKey: process.env.SIEM_API_KEY,
      username: process.env.SIEM_USERNAME,
      password: process.env.SIEM_PASSWORD,
      index: process.env.SIEM_INDEX || 'gemini-mcp-security',
      sourceType: process.env.SIEM_SOURCE_TYPE || 'mcp-security-events',
      batchSize: parseInt(process.env.SIEM_BATCH_SIZE || '100'),
      flushInterval: parseInt(process.env.SIEM_FLUSH_INTERVAL || '30000'), // 30 seconds
      retryAttempts: parseInt(process.env.SIEM_RETRY_ATTEMPTS || '3'),
      retryDelay: parseInt(process.env.SIEM_RETRY_DELAY || '5000') // 5 seconds
    };
  }

  private initializeSIEM(): void {
    if (!this.config.endpoint) {
      logger.warn('⚠️ SIEM integration enabled but no endpoint configured');
      return;
    }

    this.flushTimer = setInterval(() => {
      this.flushEvents();
    }, this.config.flushInterval);

    this.isInitialized = true;
    logger.info('🔗 SIEM integration initialized', {
      provider: this.config.provider,
      endpoint: this.config.endpoint
    });
  }

  async logEvent(event: Partial<SIEMEvent>): Promise<void> {
    if (!this.isInitialized) return;

    const siemEvent: SIEMEvent = {
      timestamp: event.timestamp || new Date().toISOString(),
      eventType: event.eventType || 'security_event',
      severity: event.severity || 'low',
      source: event.source || 'gemini-mcp',
      message: event.message || 'Security event',
      userId: event.userId,
      sessionId: event.sessionId,
      resource: event.resource || 'unknown',
      action: event.action || 'unknown',
      result: event.result || 'success',
      metadata: event.metadata || {},
      correlationId: event.correlationId
    };

    this.eventBuffer.push(siemEvent);

    // Flush immediately if buffer is full
    if (this.eventBuffer.length >= this.config.batchSize) {
      await this.flushEvents();
    }

    logger.debug('📝 SIEM event logged', {
      eventType: siemEvent.eventType,
      severity: siemEvent.severity
    });
  }

  async logSecurityEvent(
    eventType: string,
    severity: SIEMEvent['severity'],
    message: string,
    metadata: Record<string, unknown> = {}
  ): Promise<void> {
    await this.logEvent({
      eventType,
      severity,
      message,
      source: 'gemini-mcp-security',
      resource: 'security-system',
      action: eventType,
      metadata
    });
  }

  async logAuthenticationEvent(
    userId: string,
    action: 'login' | 'logout' | 'failed_login' | 'password_change',
    result: SIEMEvent['result'],
    metadata: Record<string, unknown> = {}
  ): Promise<void> {
    await this.logEvent({
      eventType: 'authentication',
      severity: action === 'failed_login' ? 'medium' : 'low',
      message: `User ${action}: ${userId}`,
      userId,
      resource: 'authentication',
      action,
      result,
      metadata
    });
  }

  async logAnomalyAlert(alert: AnomalyAlert): Promise<void> {
    await this.logEvent({
      eventType: 'anomaly_detected',
      severity: alert.severity,
      message: alert.description,
      resource: 'anomaly-detection',
      action: 'alert',
      result: 'success',
      metadata: {
        alertId: alert.id,
        confidence: alert.confidence,
        indicators: alert.indicators,
        affectedResources: alert.affectedResources,
        recommendedActions: alert.recommendedActions,
        ...alert.metadata
      }
    });
  }

  async logAPIRequest(
    method: string,
    path: string,
    statusCode: number,
    userId?: string,
    sessionId?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<void> {
    const severity: SIEMEvent['severity'] = statusCode >= 500 ? 'high' :
                                          statusCode >= 400 ? 'medium' : 'low';

    await this.logEvent({
      eventType: 'api_request',
      severity,
      message: `${method} ${path} - ${statusCode}`,
      userId,
      sessionId,
      resource: 'api',
      action: method.toLowerCase(),
      result: statusCode >= 400 ? 'failure' : 'success',
      metadata: {
        method,
        path,
        statusCode,
        responseTime: metadata.responseTime,
        userAgent: metadata.userAgent,
        ipAddress: metadata.ipAddress,
        ...metadata
      }
    });
  }

  async logDataAccess(
    userId: string,
    resource: string,
    action: 'read' | 'write' | 'delete' | 'execute',
    result: SIEMEvent['result'],
    metadata: Record<string, unknown> = {}
  ): Promise<void> {
    await this.logEvent({
      eventType: 'data_access',
      severity: result === 'failure' ? 'medium' : 'low',
      message: `Data access: ${action} on ${resource}`,
      userId,
      resource,
      action,
      result,
      metadata
    });
  }

  async logSystemEvent(
    component: string,
    event: string,
    severity: SIEMEvent['severity'],
    message: string,
    metadata: Record<string, unknown> = {}
  ): Promise<void> {
    await this.logEvent({
      eventType: 'system_event',
      severity,
      message,
      source: component,
      resource: 'system',
      action: event,
      result: 'success',
      metadata
    });
  }

  private async flushEvents(): Promise<void> {
    if (this.eventBuffer.length === 0) return;

    const eventsToSend = [...this.eventBuffer];
    this.eventBuffer = [];

    try {
      await this.sendEventsToSIEM(eventsToSend);
      logger.debug('📤 SIEM events flushed', { count: eventsToSend.length });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to flush SIEM events', { error: errorMessage });

      // Re-queue events for retry
      this.eventBuffer.unshift(...eventsToSend);
    }
  }

  private async sendEventsToSIEM(events: SIEMEvent[]): Promise<void> {
    const payload = this.formatEventsForProvider(events);

    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        await this.makeSIEMRequest(payload);
        return; // Success
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.warn(`⚠️ SIEM request attempt ${attempt} failed`, { error: errorMessage });

        if (attempt < this.config.retryAttempts) {
          await this.delay(this.config.retryDelay);
        } else {
          throw error;
        }
      }
    }
  }

  private formatEventsForProvider(events: SIEMEvent[]): any {
    switch (this.config.provider) {
      case 'splunk':
        return events.map(event => ({
          time: new Date(event.timestamp).getTime() / 1000,
          event,
          index: this.config.index,
          sourcetype: this.config.sourceType
        }));

      case 'elasticsearch':
        return {
          index: {
            _index: this.config.index || 'gemini-mcp-events',
            _type: '_doc'
          }
        };
        // Note: Elasticsearch bulk API requires alternating metadata and data lines

      case 'sumologic':
        return events.map(event => ({
          timestamp: event.timestamp,
          message: JSON.stringify(event),
          severity: event.severity,
          source: event.source
        }));

      case 'datadog':
        return {
          series: events.map(event => ({
            metric: 'gemini.mcp.security_event',
            points: [[new Date(event.timestamp).getTime() / 1000, 1]],
            tags: [
              `event_type:${event.eventType}`,
              `severity:${event.severity}`,
              `source:${event.source}`,
              `result:${event.result}`
            ],
            type: 'count'
          }))
        };

      default:
        return { events };
    }
  }

  private async makeSIEMRequest(payload: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = new URL(this.config.endpoint);
      const options: https.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': this.getAuthHeader()
        }
      };

      const req = (url.protocol === 'https:' ? https : http).request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            reject(new Error(`SIEM request failed: ${res.statusCode} ${data}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.write(JSON.stringify(payload));
      req.end();
    });
  }

  private getAuthHeader(): string {
    if (this.config.apiKey) {
      return `Bearer ${this.config.apiKey}`;
    }

    if (this.config.username && this.config.password) {
      const credentials = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
      return `Basic ${credentials}`;
    }

    return '';
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Query and analysis methods
  async queryEvents(
    query: string,
    timeRange: { start: string; end: string },
    limit: number = 100
  ): Promise<SIEMEvent[]> {
    // In a real implementation, this would query the SIEM system
    // For now, return mock results
    logger.info('🔍 Querying SIEM events', { query, timeRange, limit });
    return [];
  }

  async getSecurityMetrics(timeRange: { start: string; end: string }): Promise<{
    totalEvents: number;
    alertsBySeverity: Record<string, number>;
    topEventTypes: Array<{ type: string; count: number }>;
    unusualPatterns: string[];
  }> {
    // In a real implementation, this would aggregate metrics from SIEM
    logger.info('📊 Getting SIEM security metrics', { timeRange });
    return {
      totalEvents: 0,
      alertsBySeverity: {},
      topEventTypes: [],
      unusualPatterns: []
    };
  }

  // Health and status methods
  getStatus(): {
    enabled: boolean;
    initialized: boolean;
    provider: string;
    bufferSize: number;
    lastFlush: number;
    health: 'healthy' | 'warning' | 'error';
  } {
    return {
      enabled: this.config.enabled,
      initialized: this.isInitialized,
      provider: this.config.provider,
      bufferSize: this.eventBuffer.length,
      lastFlush: Date.now() - this.config.flushInterval,
      health: this.isInitialized ? 'healthy' : 'error'
    };
  }

  // Cleanup and shutdown
  async shutdown(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }

    // Flush remaining events
    if (this.eventBuffer.length > 0) {
      await this.flushEvents();
    }

    logger.info('🛑 SIEM integration shutdown');
  }
}

export const siemIntegration = SIEMIntegrationManager.getInstance();
