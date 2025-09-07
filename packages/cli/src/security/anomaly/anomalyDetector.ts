/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Advanced Anomaly Detection System for Proactive Security Monitoring
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../../utils/logger.js';
import { dataCollector } from '../ml-training/dataCollector.js';

export interface AnomalyAlert {
  id: string;
  timestamp: number;
  type: 'behavioral' | 'statistical' | 'pattern' | 'threshold' | 'predictive';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  description: string;
  indicators: string[];
  affectedResources: string[];
  recommendedActions: string[];
  metadata: Record<string, unknown>;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: number;
}

export interface AnomalyMetrics {
  requestRate: number;
  errorRate: number;
  responseTime: number;
  uniqueUsers: number;
  failedAuthentications: number;
  suspiciousPatterns: number;
  dataExfiltrationAttempts: number;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  type: 'threshold' | 'pattern' | 'statistical' | 'behavioral' | 'predictive';
  enabled: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  conditions: DetectionCondition[];
  cooldownPeriod: number; // milliseconds
  lastTriggered?: number;
}

export interface DetectionCondition {
  metric: string;
  operator: '>' | '<' | '>=' | '<=' | '==' | '!=' | 'contains' | 'matches';
  threshold: number | string | RegExp;
  window: number; // time window in milliseconds
}

export interface AnomalyReport {
  timestamp: number;
  period: { start: number; end: number };
  totalEvents: number;
  anomaliesDetected: number;
  falsePositives: number;
  alertsBySeverity: Record<string, number>;
  topIndicators: Array<{ indicator: string; count: number }>;
  trends: Array<{
    metric: string;
    trend: 'increasing' | 'decreasing' | 'stable';
    changePercent: number;
  }>;
  recommendations: string[];
}

class AnomalyDetector {
  private static instance: AnomalyDetector;
  private alerts: AnomalyAlert[] = [];
  private detectionRules: DetectionRule[] = [];
  private baselineMetrics: Map<string, number[]> = new Map();
  private monitoringInterval: NodeJS.Timeout;
  private alertCooldowns: Map<string, number> = new Map();

  // Statistical thresholds
  private readonly Z_SCORE_THRESHOLD = 3.0;
  private readonly CHANGE_PERCENT_THRESHOLD = 50;
  private readonly MIN_BASELINE_SAMPLES = 100;

  static getInstance(): AnomalyDetector {
    if (!AnomalyDetector.instance) {
      AnomalyDetector.instance = new AnomalyDetector();
    }
    return AnomalyDetector.instance;
  }

  private constructor() {
    this.initializeDetectionRules();
    this.loadBaselineData();
    this.startMonitoring();
  }

  private initializeDetectionRules(): void {
    this.detectionRules = [
      // Rate-based anomalies
      {
        id: 'high_request_rate',
        name: 'High Request Rate',
        description: 'Unusually high number of requests in a short period',
        type: 'threshold',
        enabled: true,
        severity: 'medium',
        conditions: [{
          metric: 'requestRate',
          operator: '>',
          threshold: 1000,
          window: 60000 // 1 minute
        }],
        cooldownPeriod: 300000 // 5 minutes
      },

      // Error rate anomalies
      {
        id: 'high_error_rate',
        name: 'High Error Rate',
        description: 'Elevated error rate indicating potential issues',
        type: 'threshold',
        enabled: true,
        severity: 'high',
        conditions: [{
          metric: 'errorRate',
          operator: '>',
          threshold: 0.1, // 10%
          window: 300000 // 5 minutes
        }],
        cooldownPeriod: 600000 // 10 minutes
      },

      // Authentication anomalies
      {
        id: 'failed_auth_spike',
        name: 'Authentication Failure Spike',
        description: 'Sudden increase in failed authentication attempts',
        type: 'statistical',
        enabled: true,
        severity: 'high',
        conditions: [{
          metric: 'failedAuthentications',
          operator: '>',
          threshold: this.Z_SCORE_THRESHOLD,
          window: 300000
        }],
        cooldownPeriod: 900000 // 15 minutes
      },

      // Pattern-based anomalies
      {
        id: 'suspicious_payload',
        name: 'Suspicious Payload Pattern',
        description: 'Detection of potentially malicious payload patterns',
        type: 'pattern',
        enabled: true,
        severity: 'high',
        conditions: [{
          metric: 'suspiciousPatterns',
          operator: '>',
          threshold: 5,
          window: 60000
        }],
        cooldownPeriod: 300000
      },

      // Behavioral anomalies
      {
        id: 'unusual_user_behavior',
        name: 'Unusual User Behavior',
        description: 'User behavior deviating from normal patterns',
        type: 'behavioral',
        enabled: true,
        severity: 'medium',
        conditions: [{
          metric: 'userBehaviorScore',
          operator: '>',
          threshold: 0.8,
          window: 3600000 // 1 hour
        }],
        cooldownPeriod: 1800000 // 30 minutes
      },

      // Data exfiltration attempts
      {
        id: 'data_exfiltration_attempt',
        name: 'Data Exfiltration Attempt',
        description: 'Potential attempt to extract sensitive data',
        type: 'pattern',
        enabled: true,
        severity: 'critical',
        conditions: [{
          metric: 'dataExfiltrationAttempts',
          operator: '>',
          threshold: 1,
          window: 60000
        }],
        cooldownPeriod: 600000
      },

      // System resource anomalies
      {
        id: 'resource_exhaustion',
        name: 'Resource Exhaustion',
        description: 'System resources being exhausted abnormally',
        type: 'threshold',
        enabled: true,
        severity: 'high',
        conditions: [{
          metric: 'responseTime',
          operator: '>',
          threshold: 5000, // 5 seconds
          window: 300000
        }],
        cooldownPeriod: 600000
      }
    ];

    logger.info('🛡️ Initialized anomaly detection rules', { count: this.detectionRules.length });
  }

  private loadBaselineData(): void {
    try {
      const baselinePath = path.join(process.cwd(), 'anomaly-baseline.json');
      if (fs.existsSync(baselinePath)) {
        const data = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
        this.baselineMetrics = new Map(Object.entries(data));
        logger.info('📊 Loaded anomaly baseline data', {
          metricsCount: this.baselineMetrics.size
        });
      } else {
        logger.info('📊 No existing baseline data found, will establish during monitoring');
      }
    } catch (error) {
      logger.warn('⚠️ Failed to load baseline data', { error: error.message });
    }
  }

  private startMonitoring(): void {
    // Monitor every 30 seconds
    this.monitoringInterval = setInterval(() => {
      this.performMonitoring();
    }, 30000);

    logger.info('🔍 Started anomaly monitoring');
  }

  private async performMonitoring(): Promise<void> {
    try {
      const currentMetrics = await this.collectCurrentMetrics();
      const anomalies = await this.detectAnomalies(currentMetrics);

      // Update baseline with current metrics
      this.updateBaseline(currentMetrics);

      // Process detected anomalies
      for (const anomaly of anomalies) {
        await this.processAnomaly(anomaly);
      }

      // Clean up old alerts
      this.cleanupOldAlerts();

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Anomaly monitoring failed', { error: errorMessage });
    }
  }

  private async collectCurrentMetrics(): Promise<AnomalyMetrics> {
    // Collect metrics from various sources
    const securityStats = dataCollector.getStats();

    return {
      requestRate: this.calculateRequestRate(),
      errorRate: 0.02, // Would be collected from actual error monitoring
      responseTime: 150, // Would be collected from actual response monitoring
      uniqueUsers: securityStats.totalEvents, // Approximation
      failedAuthentications: Math.floor(Math.random() * 10), // Would be collected from auth system
      suspiciousPatterns: Math.floor(Math.random() * 5), // Would be collected from pattern matching
      dataExfiltrationAttempts: Math.floor(Math.random() * 2) // Would be collected from data monitoring
    };
  }

  private calculateRequestRate(): number {
    // Calculate requests per minute over the last 5 minutes
    const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
    const recentEvents = dataCollector.getStats().totalEvents; // This is a simplification
    return recentEvents / 5; // requests per minute
  }

  private async detectAnomalies(metrics: AnomalyMetrics): Promise<AnomalyAlert[]> {
    const anomalies: AnomalyAlert[] = [];

    for (const rule of this.detectionRules.filter(r => r.enabled)) {
      // Check cooldown period
      const lastTriggered = this.alertCooldowns.get(rule.id);
      if (lastTriggered && Date.now() - lastTriggered < rule.cooldownPeriod) {
        continue;
      }

      const anomaly = await this.evaluateRule(rule, metrics);
      if (anomaly) {
        anomalies.push(anomaly);
        this.alertCooldowns.set(rule.id, Date.now());
        rule.lastTriggered = Date.now();
      }
    }

    return anomalies;
  }

  private async evaluateRule(rule: DetectionRule, metrics: AnomalyMetrics): Promise<AnomalyAlert | null> {
    for (const condition of rule.conditions) {
      const metricValue = this.getMetricValue(metrics, condition.metric);
      const isAnomaly = this.evaluateCondition(metricValue, condition);

      if (isAnomaly) {
        return {
          id: `anomaly_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: Date.now(),
          type: rule.type,
          severity: rule.severity,
          confidence: this.calculateConfidence(rule, metrics),
          description: rule.description,
          indicators: [condition.metric],
          affectedResources: ['mcp-server'],
          recommendedActions: this.generateRecommendations(rule, metrics),
          metadata: {
            ruleId: rule.id,
            metric: condition.metric,
            threshold: condition.threshold,
            actualValue: metricValue
          },
          acknowledged: false
        };
      }
    }

    return null;
  }

  private getMetricValue(metrics: AnomalyMetrics, metric: string): number {
    switch (metric) {
      case 'requestRate': return metrics.requestRate;
      case 'errorRate': return metrics.errorRate;
      case 'responseTime': return metrics.responseTime;
      case 'uniqueUsers': return metrics.uniqueUsers;
      case 'failedAuthentications': return metrics.failedAuthentications;
      case 'suspiciousPatterns': return metrics.suspiciousPatterns;
      case 'dataExfiltrationAttempts': return metrics.dataExfiltrationAttempts;
      case 'userBehaviorScore': return Math.random(); // Placeholder
      default: return 0;
    }
  }

  private evaluateCondition(value: number, condition: DetectionCondition): boolean {
    const threshold = typeof condition.threshold === 'number' ? condition.threshold : 0;

    switch (condition.operator) {
      case '>': return value > threshold;
      case '<': return value < threshold;
      case '>=': return value >= threshold;
      case '<=': return value <= threshold;
      case '==': return value === threshold;
      case '!=': return value !== threshold;
      default: return false;
    }
  }

  private calculateConfidence(rule: DetectionRule, metrics: AnomalyMetrics): number {
    // Calculate confidence based on multiple factors
    let confidence = 0.5; // Base confidence

    // Increase confidence based on severity and supporting evidence
    if (rule.severity === 'critical') confidence += 0.2;
    else if (rule.severity === 'high') confidence += 0.15;
    else if (rule.severity === 'medium') confidence += 0.1;

    // Increase confidence if multiple conditions are met
    if (rule.conditions.length > 1) confidence += 0.1;

    // Increase confidence based on baseline deviation
    for (const condition of rule.conditions) {
      const baselineDeviation = this.calculateBaselineDeviation(condition.metric, metrics);
      confidence += Math.min(baselineDeviation * 0.1, 0.2);
    }

    return Math.min(confidence, 1.0);
  }

  private calculateBaselineDeviation(metric: string, metrics: AnomalyMetrics): number {
    const baselineValues = this.baselineMetrics.get(metric);
    if (!baselineValues || baselineValues.length < this.MIN_BASELINE_SAMPLES) {
      return 0;
    }

    const currentValue = this.getMetricValue(metrics, metric);
    const mean = baselineValues.reduce((a, b) => a + b, 0) / baselineValues.length;
    const stdDev = Math.sqrt(
      baselineValues.reduce((sum, value) => sum + Math.pow(value - mean, 2), 0) / baselineValues.length
    );

    return stdDev > 0 ? Math.abs(currentValue - mean) / stdDev : 0;
  }

  private generateRecommendations(rule: DetectionRule, metrics: AnomalyMetrics): string[] {
    const recommendations: string[] = [];

    switch (rule.id) {
      case 'high_request_rate':
        recommendations.push('Consider implementing rate limiting');
        recommendations.push('Monitor for potential DDoS attacks');
        recommendations.push('Scale up server resources if needed');
        break;

      case 'high_error_rate':
        recommendations.push('Investigate error logs for root cause');
        recommendations.push('Check system resource utilization');
        recommendations.push('Review recent code deployments');
        break;

      case 'failed_auth_spike':
        recommendations.push('Enable additional authentication monitoring');
        recommendations.push('Consider temporary account lockouts');
        recommendations.push('Review authentication logs for patterns');
        break;

      case 'suspicious_payload':
        recommendations.push('Review input validation rules');
        recommendations.push('Update pattern matching signatures');
        recommendations.push('Enable additional payload inspection');
        break;

      default:
        recommendations.push('Review system logs for additional context');
        recommendations.push('Consider increasing monitoring frequency');
        recommendations.push('Evaluate security controls effectiveness');
    }

    return recommendations;
  }

  private async processAnomaly(alert: AnomalyAlert): Promise<void> {
    this.alerts.push(alert);

    logger.warn('🚨 Anomaly detected', {
      id: alert.id,
      type: alert.type,
      severity: alert.severity,
      confidence: alert.confidence,
      description: alert.description
    });

    // In production, this would:
    // 1. Send notifications to security team
    // 2. Trigger automated responses
    // 3. Log to SIEM system
    // 4. Update incident management system

    // For now, just log the alert
    await this.logAnomalyToFile(alert);
  }

  private async logAnomalyToFile(alert: AnomalyAlert): Promise<void> {
    try {
      const logPath = path.join(process.cwd(), 'anomaly-alerts.log');
      const logEntry = JSON.stringify({
        timestamp: new Date(alert.timestamp).toISOString(),
        ...alert
      }) + '\n';

      fs.appendFileSync(logPath, logEntry);
    } catch (error) {
      logger.error('❌ Failed to log anomaly', { error: error.message });
    }
  }

  private updateBaseline(metrics: AnomalyMetrics): void {
    const metricsToTrack = [
      'requestRate', 'errorRate', 'responseTime', 'uniqueUsers',
      'failedAuthentications', 'suspiciousPatterns', 'dataExfiltrationAttempts'
    ];

    for (const metricName of metricsToTrack) {
      const value = this.getMetricValue(metrics, metricName);
      const baselineValues = this.baselineMetrics.get(metricName) || [];

      baselineValues.push(value);

      // Keep only recent values (last 1000 samples)
      if (baselineValues.length > 1000) {
        baselineValues.shift();
      }

      this.baselineMetrics.set(metricName, baselineValues);
    }

    // Save baseline data periodically
    if (Math.random() < 0.1) { // 10% chance to save
      this.saveBaselineData();
    }
  }

  private saveBaselineData(): void {
    try {
      const baselinePath = path.join(process.cwd(), 'anomaly-baseline.json');
      const baselineData = Object.fromEntries(this.baselineMetrics);
      fs.writeFileSync(baselinePath, JSON.stringify(baselineData, null, 2));
    } catch (error) {
      logger.warn('⚠️ Failed to save baseline data', { error: error.message });
    }
  }

  private cleanupOldAlerts(): void {
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    this.alerts = this.alerts.filter(alert => alert.timestamp > oneWeekAgo);
  }

  // Public API methods
  getActiveAlerts(): AnomalyAlert[] {
    return this.alerts.filter(alert => !alert.acknowledged);
  }

  getAlertHistory(hours: number = 24): AnomalyAlert[] {
    const since = Date.now() - (hours * 60 * 60 * 1000);
    return this.alerts.filter(alert => alert.timestamp > since);
  }

  acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
      alert.acknowledgedBy = acknowledgedBy;
      alert.acknowledgedAt = Date.now();
      logger.info('✅ Alert acknowledged', { alertId, acknowledgedBy });
      return true;
    }
    return false;
  }

  getDetectionRules(): DetectionRule[] {
    return [...this.detectionRules];
  }

  updateDetectionRule(ruleId: string, updates: Partial<DetectionRule>): boolean {
    const rule = this.detectionRules.find(r => r.id === ruleId);
    if (rule) {
      Object.assign(rule, updates);
      logger.info('📝 Detection rule updated', { ruleId });
      return true;
    }
    return false;
  }

  async generateAnomalyReport(hours: number = 24): Promise<AnomalyReport> {
    const startTime = Date.now() - (hours * 60 * 60 * 1000);
    const periodAlerts = this.alerts.filter(alert => alert.timestamp > startTime);

    const alertsBySeverity = periodAlerts.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const topIndicators = periodAlerts
      .flatMap(alert => alert.indicators)
      .reduce((acc, indicator) => {
        acc[indicator] = (acc[indicator] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

    const topIndicatorsArray = Object.entries(topIndicators)
      .map(([indicator, count]) => ({ indicator, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      timestamp: Date.now(),
      period: { start: startTime, end: Date.now() },
      totalEvents: dataCollector.getStats().totalEvents,
      anomaliesDetected: periodAlerts.length,
      falsePositives: 0, // Would be calculated based on manual review
      alertsBySeverity,
      topIndicators: topIndicatorsArray,
      trends: [], // Would be calculated from historical data
      recommendations: this.generateReportRecommendations(periodAlerts)
    };
  }

  private generateReportRecommendations(alerts: AnomalyAlert[]): string[] {
    const recommendations: string[] = [];

    const criticalAlerts = alerts.filter(a => a.severity === 'critical');
    const highAlerts = alerts.filter(a => a.severity === 'high');

    if (criticalAlerts.length > 0) {
      recommendations.push('🚨 CRITICAL: Immediate attention required for critical alerts');
      recommendations.push('🔒 CRITICAL: Review security controls and incident response procedures');
    }

    if (highAlerts.length > 5) {
      recommendations.push('⚠️ HIGH: Implement additional monitoring for frequently triggered alerts');
      recommendations.push('🛡️ HIGH: Consider enhancing security measures');
    }

    if (alerts.length > 20) {
      recommendations.push('📊 Consider adjusting anomaly detection thresholds');
      recommendations.push('🔧 Review and optimize detection rules');
    }

    recommendations.push('📈 Continue monitoring and refining anomaly detection');
    recommendations.push('📋 Regular review of security alerts and response procedures');

    return recommendations;
  }

  getSystemHealth(): {
    status: 'healthy' | 'warning' | 'critical';
    activeRules: number;
    baselineMetrics: number;
    recentAlerts: number;
    issues: string[];
  } {
    const issues: string[] = [];
    let status: 'healthy' | 'warning' | 'critical' = 'healthy';

    // Check baseline data
    if (this.baselineMetrics.size < 5) {
      issues.push('Insufficient baseline data for effective anomaly detection');
      status = 'warning';
    }

    // Check recent alerts
    const recentAlerts = this.getActiveAlerts().length;
    if (recentAlerts > 10) {
      issues.push(`High number of active alerts: ${recentAlerts}`);
      status = 'warning';
    }

    // Check disabled rules
    const disabledRules = this.detectionRules.filter(r => !r.enabled).length;
    if (disabledRules > this.detectionRules.length * 0.5) {
      issues.push(`Many detection rules disabled: ${disabledRules}/${this.detectionRules.length}`);
      status = 'warning';
    }

    return {
      status,
      activeRules: this.detectionRules.filter(r => r.enabled).length,
      baselineMetrics: this.baselineMetrics.size,
      recentAlerts,
      issues
    };
  }
}

export const anomalyDetector = AnomalyDetector.getInstance();
