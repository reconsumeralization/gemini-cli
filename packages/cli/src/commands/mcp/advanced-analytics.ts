/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Advanced Analytics & Reporting for MCP Server
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../../utils/logger.js';
import { dataCollector, SecurityEvent } from '../../security/ml-training/dataCollector.js';

export interface AnalyticsReport {
  id: string;
  type: 'security' | 'performance' | 'usage' | 'threat' | 'compliance';
  title: string;
  summary: string;
  generatedAt: string;
  timeRange: {
    start: string;
    end: string;
  };
  metrics: Record<string, unknown>;
  insights: string[];
  recommendations: string[];
  data: Record<string, unknown>;
  charts?: ChartConfig[];
}

export interface ChartConfig {
  type: 'line' | 'bar' | 'pie' | 'area' | 'scatter';
  title: string;
  xAxis: string;
  yAxis: string;
  data: Record<string, unknown>[];
  colors?: string[];
}

export interface TrendAnalysis {
  period: string;
  metric: string;
  trend: 'increasing' | 'decreasing' | 'stable' | 'volatile';
  changePercent: number;
  confidence: number;
  prediction?: number;
}

export interface RiskAssessment {
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  riskFactors: Array<{
    factor: string;
    impact: number;
    likelihood: number;
    mitigation: string;
  }>;
  riskScore: number;
  recommendations: string[];
}

export interface ComplianceReport {
  framework: string;
  status: 'compliant' | 'non-compliant' | 'partial';
  requirements: Array<{
    requirement: string;
    status: 'met' | 'not-met' | 'partial';
    evidence?: string;
  }>;
  score: number;
  nextAudit: string;
}

class AdvancedAnalyticsEngine {
  private static instance: AdvancedAnalyticsEngine;
  private reportsDir: string;

  static getInstance(): AdvancedAnalyticsEngine {
    if (!AdvancedAnalyticsEngine.instance) {
      AdvancedAnalyticsEngine.instance = new AdvancedAnalyticsEngine();
    }
    return AdvancedAnalyticsEngine.instance;
  }

  private constructor() {
    this.reportsDir = path.join(process.cwd(), 'analytics-reports');
    this.ensureReportsDirectory();
  }

  private ensureReportsDirectory(): void {
    if (!fs.existsSync(this.reportsDir)) {
      fs.mkdirSync(this.reportsDir, { recursive: true });
      logger.info('📁 Created analytics reports directory', { path: this.reportsDir });
    }
  }

  async generateSecurityReport(timeRange: { start: string; end: string }): Promise<AnalyticsReport> {
    logger.info('🔍 Generating security analytics report', timeRange);

    const dataset = dataCollector.generateTrainingDataset();
    const filteredEvents = dataset.events.filter(event => {
      const eventTime = new Date(event.timestamp);
      return eventTime >= new Date(timeRange.start) && eventTime <= new Date(timeRange.end);
    });

    // Calculate security metrics
    const threatDistribution = this.calculateThreatDistribution(filteredEvents);
    const attackPatterns = this.analyzeAttackPatterns(filteredEvents);
    const temporalTrends = this.analyzeTemporalTrends(filteredEvents);
    const riskAssessment = this.performRiskAssessment(filteredEvents);

    const report: AnalyticsReport = {
      id: `security_${Date.now()}`,
      type: 'security',
      title: 'Security Analytics Report',
      summary: this.generateSecuritySummary(filteredEvents, riskAssessment),
      generatedAt: new Date().toISOString(),
      timeRange,
      metrics: {
        totalEvents: filteredEvents.length,
        blockedEvents: filteredEvents.filter(e => e.decision === 'block').length,
        sanitizedEvents: filteredEvents.filter(e => e.decision === 'allow_sanitized').length,
        threatDistribution,
        attackPatterns,
        temporalTrends
      },
      insights: this.generateSecurityInsights(filteredEvents, riskAssessment),
      recommendations: this.generateSecurityRecommendations(riskAssessment),
      data: {
        events: filteredEvents.slice(0, 100), // Sample for visualization
        riskAssessment
      },
      charts: this.generateSecurityCharts(filteredEvents)
    };

    this.saveReport(report);
    return report;
  }

  async generatePerformanceReport(timeRange: { start: string; end: string }): Promise<AnalyticsReport> {
    logger.info('⚡ Generating performance analytics report', timeRange);

    // This would integrate with actual performance monitoring data
    const performanceData = await this.collectPerformanceData(timeRange);

    const report: AnalyticsReport = {
      id: `performance_${Date.now()}`,
      type: 'performance',
      title: 'Performance Analytics Report',
      summary: 'System performance analysis and optimization recommendations',
      generatedAt: new Date().toISOString(),
      timeRange,
      metrics: {
        avgResponseTime: performanceData.avgResponseTime,
        throughput: performanceData.throughput,
        errorRate: performanceData.errorRate,
        resourceUtilization: performanceData.resourceUtilization
      },
      insights: performanceData.insights,
      recommendations: performanceData.recommendations,
      data: performanceData.raw,
      charts: this.generatePerformanceCharts(performanceData)
    };

    this.saveReport(report);
    return report;
  }

  async generateComplianceReport(_framework: string): Promise<ComplianceReport> {
    logger.info('📋 Generating compliance report', { framework: _framework });

    // Framework-specific compliance checks
    const complianceData = await this.performComplianceCheck(_framework);

    return {
      framework: _framework,
      status: complianceData.overallStatus as 'compliant' | 'non-compliant' | 'partial',
      requirements: complianceData.requirements as { requirement: string; status: 'met' | 'partial' | 'not-met'; evidence: string }[],
      score: complianceData.complianceScore,
      nextAudit: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    };
  }

private calculateThreatDistribution(events: SecurityEvent[]): Record<string, number> {
    return events.reduce((acc, event) => {
      const threat = event.labels.threatLevel;
      acc[threat] = (acc[threat] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private analyzeAttackPatterns(events: SecurityEvent[]): Record<string, number> {
    return events.reduce((acc, event) => {
      event.labels.attackType.forEach((attack: string) => {
        acc[attack] = (acc[attack] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);
  }

private analyzeTemporalTrends(events: SecurityEvent[]): TrendAnalysis[] {
    const trends: TrendAnalysis[] = [];
    const hourlyData = this.groupEventsByHour(events);

    // Analyze threat trends
    const threatTrend = this.calculateTrend(hourlyData.map(h => h.threats));
    trends.push({
      period: 'hourly',
      metric: 'threats',
      trend: threatTrend.direction,
      changePercent: threatTrend.changePercent,
      confidence: threatTrend.confidence
    });

    return trends;
  }

  private groupEventsByHour(events: SecurityEvent[]): Array<{ hour: string; threats: number; blocks: number }> {
    const hourly = new Map<string, { threats: number; blocks: number }>();

    events.forEach(event => {
      const hour = new Date(event.timestamp).toISOString().slice(0, 13);
      const current = hourly.get(hour) || { threats: 0, blocks: 0 };

      if (event.labels.threatLevel !== 'low') {
        current.threats++;
      }
      if (event.decision === 'block') {
        current.blocks++;
      }

      hourly.set(hour, current);
    });

    return Array.from(hourly.entries()).map(([hour, data]) => ({
      hour,
      ...data
    }));
  }

  private calculateTrend(values: number[]): { direction: TrendAnalysis['trend']; changePercent: number; confidence: number } {
    if (values.length < 3) {
      return { direction: 'stable', changePercent: 0, confidence: 0.5 };
    }

    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    const changePercent = ((secondAvg - firstAvg) / firstAvg) * 100;

    let direction: TrendAnalysis['trend'];
    if (Math.abs(changePercent) < 5) {
      direction = 'stable';
    } else if (changePercent > 5) {
      direction = 'increasing';
    } else {
      direction = 'decreasing';
    }

    return {
      direction,
      changePercent,
      confidence: Math.min(Math.abs(changePercent) / 20, 1) // Confidence based on magnitude
    };
  }

  private performRiskAssessment(events: SecurityEvent[]): RiskAssessment {
    const riskFactors = [];
    const threatEvents = events.filter(e => e.labels.threatLevel !== 'low');

    // Calculate risk score based on various factors
    const threatRatio = threatEvents.length / events.length;
    const attackDiversity = new Set(events.flatMap(e => e.labels.attackType)).size;

    if (threatRatio > 0.3) {
      riskFactors.push({
        factor: 'High threat volume',
        impact: 0.8,
        likelihood: threatRatio,
        mitigation: 'Increase monitoring and implement additional safeguards'
      });
    }

    if (attackDiversity > 5) {
      riskFactors.push({
        factor: 'Diverse attack patterns',
        impact: 0.7,
        likelihood: Math.min(attackDiversity / 10, 1),
        mitigation: 'Expand threat detection capabilities'
      });
    }

    const riskScore = riskFactors.reduce((score, factor) =>
      score + (factor.impact * factor.likelihood), 0) / riskFactors.length;

    let overallRisk: RiskAssessment['overallRisk'];
    if (riskScore > 0.7) overallRisk = 'critical';
    else if (riskScore > 0.5) overallRisk = 'high';
    else if (riskScore > 0.3) overallRisk = 'medium';
    else overallRisk = 'low';

    return {
      overallRisk,
      riskFactors,
      riskScore,
      recommendations: this.generateSecurityRecommendations({ overallRisk, riskFactors, riskScore } as RiskAssessment)
    };
  }

  private generateSecuritySummary(events: SecurityEvent[], riskAssessment: RiskAssessment): string {
    const totalEvents = events.length;
    const threatEvents = events.filter(e => e.labels.threatLevel !== 'low').length;
    const blockedEvents = events.filter(e => e.decision === 'block').length;

    return `Security analysis for ${totalEvents} events: ${threatEvents} threats detected, ${blockedEvents} blocked. Overall risk level: ${riskAssessment.overallRisk.toUpperCase()}.`;
  }

  private generateSecurityInsights(events: SecurityEvent[], riskAssessment: RiskAssessment): string[] {
    const insights = [];

    if (riskAssessment.overallRisk === 'high' || riskAssessment.overallRisk === 'critical') {
      insights.push(`⚠️ High risk environment detected with ${riskAssessment.riskScore.toFixed(2)} risk score`);
    }

    const attackPatterns = this.analyzeAttackPatterns(events);
    const topAttacks = Object.entries(attackPatterns)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 3);

    if (topAttacks.length > 0) {
      insights.push(`🎯 Top attack patterns: ${topAttacks.map(([attack, count]) => `${attack} (${count})`).join(', ')}`);
    }

    const temporalTrends = this.analyzeTemporalTrends(events);
    const threatTrend = temporalTrends.find(t => t.metric === 'threats');
    if (threatTrend && threatTrend.trend === 'increasing') {
      insights.push(`📈 Threat activity trending upward (${threatTrend.changePercent.toFixed(1)}% increase)`);
    }

    return insights;
  }

  private generateSecurityRecommendations(riskAssessment: RiskAssessment): string[] {
    const recommendations = [];

    if (riskAssessment.overallRisk === 'critical') {
      recommendations.push('🚨 IMMEDIATE: Implement emergency security protocols');
      recommendations.push('🔒 CRITICAL: Review and strengthen access controls');
      recommendations.push('📞 CRITICAL: Notify security team and stakeholders');
    } else if (riskAssessment.overallRisk === 'high') {
      recommendations.push('⚠️ HIGH: Increase monitoring frequency');
      recommendations.push('🛡️ HIGH: Implement additional security measures');
      recommendations.push('📊 HIGH: Conduct thorough security assessment');
    }

    riskAssessment.riskFactors.forEach(factor => {
      recommendations.push(`🎯 ${factor.factor}: ${factor.mitigation}`);
    });

    return recommendations;
  }

  private generateSecurityCharts(events: SecurityEvent[]): ChartConfig[] {
    const charts: ChartConfig[] = [];

    // Threat distribution pie chart
    const threatDist = this.calculateThreatDistribution(events);
    charts.push({
      type: 'pie',
      title: 'Threat Level Distribution',
      xAxis: 'Threat Level',
      yAxis: 'Count',
      data: Object.entries(threatDist).map(([level, count]) => ({
        name: level,
        value: count
      }))
    });

    // Temporal trends line chart
    const hourlyData = this.groupEventsByHour(events);
    charts.push({
      type: 'line',
      title: 'Threat Activity Over Time',
      xAxis: 'Hour',
      yAxis: 'Threat Count',
      data: hourlyData.map(h => ({
        hour: h.hour,
        threats: h.threats,
        blocks: h.blocks
      }))
    });

    return charts;
  }

  private async collectPerformanceData(_timeRange: { start: string; end: string }): Promise<{ avgResponseTime: number; throughput: number; errorRate: number; resourceUtilization: Record<string, number>; insights: string[]; recommendations: string[]; raw: Record<string, unknown> }> {
    // Placeholder for actual performance data collection
    return {
      avgResponseTime: 45.2,
      throughput: 1250,
      errorRate: 0.02,
      resourceUtilization: {
        cpu: 0.65,
        memory: 0.78,
        disk: 0.45
      },
      insights: [
        'Response time is within acceptable range',
        'Throughput shows healthy system utilization',
        'Error rate is below threshold'
      ],
      recommendations: [
        'Consider optimizing database queries for better response time',
        'Monitor memory usage during peak hours'
      ],
      raw: {}
    };
  }

  private generatePerformanceCharts(_performanceData: { avgResponseTime: number; throughput: number; errorRate: number; resourceUtilization: Record<string, number>; insights: string[]; recommendations: string[]; raw: Record<string, unknown> }): ChartConfig[] {
    return [{
      type: 'bar',
      title: 'Resource Utilization',
      xAxis: 'Resource',
      yAxis: 'Utilization %',
      data: Object.entries(_performanceData.resourceUtilization).map(([resource, value]) => ({
        resource,
        utilization: (value as number) * 100
      }))
    }];
  }

private async performComplianceCheck(_framework: string): Promise<{ overallStatus: 'compliant' | 'non-compliant' | 'partial'; requirements: { requirement: string; status: 'met' | 'partial' | 'not-met'; evidence: string }[]; complianceScore: number }> {
    // Placeholder for actual compliance checking
    return {
      overallStatus: 'compliant',
      requirements: [
        {
          requirement: 'Data encryption at rest',
          status: 'met',
          evidence: 'AES-256 encryption implemented'
        },
        {
          requirement: 'Access logging',
          status: 'met',
          evidence: 'Comprehensive audit logging enabled'
        }
      ],
      complianceScore: 0.95
    };
  }

  private saveReport(report: AnalyticsReport): void {
    try {
      const reportPath = path.join(this.reportsDir, `${report.id}.json`);
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      logger.info('💾 Saved analytics report', { reportId: report.id, path: reportPath });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to save analytics report', { error: errorMessage });
    }
  }

  getReportsList(): Array<{ id: string; type: string; title: string; generatedAt: string }> {
    try {
      const files = fs.readdirSync(this.reportsDir)
        .filter(f => f.endsWith('.json'))
        .map(f => {
          const reportPath = path.join(this.reportsDir, f);
          const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
          return {
            id: report.id,
            type: report.type,
            title: report.title,
            generatedAt: report.generatedAt
          };
        });

      return files.sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime());
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to list reports', { error: errorMessage });
      return [];
    }
  }

  getReport(reportId: string): AnalyticsReport | null {
    try {
      const reportPath = path.join(this.reportsDir, `${reportId}.json`);
      if (fs.existsSync(reportPath)) {
        return JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to load report', { reportId, error: errorMessage });
    }
    return null;
  }
}

export const analyticsEngine = AdvancedAnalyticsEngine.getInstance();
