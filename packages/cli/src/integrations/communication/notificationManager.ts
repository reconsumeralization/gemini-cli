/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Enterprise Communication Integration for Notifications and Alerts
import * as https from 'https';
import * as http from 'http';
import { logger } from '../../utils/logger.js';
import { AnomalyAlert } from '../../security/anomaly/anomalyDetector.js';

export interface NotificationConfig {
  enabled: boolean;
  providers: NotificationProvider[];
  defaultChannel: string;
  alertChannels: Record<string, string>; // severity -> channel mapping
  retryAttempts: number;
  retryDelay: number;
}

export interface NotificationProvider {
  name: string;
  type: 'slack' | 'teams' | 'discord' | 'webhook' | 'email';
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface NotificationMessage {
  id: string;
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info';
  channel?: string;
  recipients?: string[];
  metadata?: Record<string, unknown>;
  timestamp: number;
  correlationId?: string;
}

export interface AlertTemplate {
  name: string;
  severity: NotificationMessage['severity'];
  titleTemplate: string;
  messageTemplate: string;
  channel?: string;
  recipients?: string[];
}

class NotificationManager {
  private static instance: NotificationManager;
  private config: NotificationConfig;
  private templates: Map<string, AlertTemplate> = new Map();
  private isInitialized = false;

  static getInstance(): NotificationManager {
    if (!NotificationManager.instance) {
      NotificationManager.instance = new NotificationManager();
    }
    return NotificationManager.instance;
  }

  private constructor() {
    this.config = this.loadNotificationConfig();
    this.initializeTemplates();
    if (this.config.enabled) {
      this.initializeNotifications();
    }
  }

  private loadNotificationConfig(): NotificationConfig {
    const providers: NotificationProvider[] = [];

    // Slack configuration
    if (process.env.SLACK_WEBHOOK_URL) {
      providers.push({
        name: 'slack',
        type: 'slack',
        enabled: true,
        config: {
          webhookUrl: process.env.SLACK_WEBHOOK_URL,
          username: process.env.SLACK_USERNAME || 'Gemini MCP',
          iconEmoji: process.env.SLACK_ICON_EMOJI || ':shield:'
        }
      });
    }

    // Teams configuration
    if (process.env.TEAMS_WEBHOOK_URL) {
      providers.push({
        name: 'teams',
        type: 'teams',
        enabled: true,
        config: {
          webhookUrl: process.env.TEAMS_WEBHOOK_URL
        }
      });
    }

    // Discord configuration
    if (process.env.DISCORD_WEBHOOK_URL) {
      providers.push({
        name: 'discord',
        type: 'discord',
        enabled: true,
        config: {
          webhookUrl: process.env.DISCORD_WEBHOOK_URL,
          username: process.env.DISCORD_USERNAME || 'Gemini MCP',
          avatarUrl: process.env.DISCORD_AVATAR_URL
        }
      });
    }

    // Email configuration (placeholder)
    if (process.env.SMTP_HOST) {
      providers.push({
        name: 'email',
        type: 'email',
        enabled: true,
        config: {
          smtpHost: process.env.SMTP_HOST,
          smtpPort: parseInt(process.env.SMTP_PORT || '587'),
          smtpUser: process.env.SMTP_USER,
          smtpPass: process.env.SMTP_PASS,
          fromEmail: process.env.FROM_EMAIL || 'mcp@security.local'
        }
      });
    }

    return {
      enabled: process.env.NOTIFICATIONS_ENABLED === 'true',
      providers,
      defaultChannel: process.env.DEFAULT_NOTIFICATION_CHANNEL || '#security-alerts',
      alertChannels: {
        'low': process.env.LOW_SEVERITY_CHANNEL || '#security-info',
        'medium': process.env.MEDIUM_SEVERITY_CHANNEL || '#security-warnings',
        'high': process.env.HIGH_SEVERITY_CHANNEL || '#security-alerts',
        'critical': process.env.CRITICAL_SEVERITY_CHANNEL || '#security-emergency',
        'info': process.env.INFO_CHANNEL || '#security-info'
      },
      retryAttempts: parseInt(process.env.NOTIFICATION_RETRY_ATTEMPTS || '3'),
      retryDelay: parseInt(process.env.NOTIFICATION_RETRY_DELAY || '5000')
    };
  }

  private initializeTemplates(): void {
    this.templates.set('security_alert', {
      name: 'Security Alert',
      severity: 'high',
      titleTemplate: '🚨 SECURITY ALERT: {description}',
      messageTemplate: `
*Alert ID:* {alertId}
*Severity:* {severity}
*Confidence:* {confidence}%
*Type:* {type}

*Description:*
{description}

*Indicators:*
{indicators}

*Affected Resources:*
{affectedResources}

*Recommended Actions:*
{recommendedActions}

*Detection Time:* {timestamp}
      `.trim(),
      channel: this.config.alertChannels.high
    });

    this.templates.set('performance_issue', {
      name: 'Performance Issue',
      severity: 'medium',
      titleTemplate: '⚡ PERFORMANCE ISSUE: {issue}',
      messageTemplate: `
*Issue:* {issue}
*Severity:* {severity}
*Metrics:* {metrics}

*Detection Time:* {timestamp}
      `.trim(),
      channel: this.config.alertChannels.medium
    });

    this.templates.set('system_status', {
      name: 'System Status',
      severity: 'info',
      titleTemplate: '📊 SYSTEM STATUS: {status}',
      messageTemplate: `
*Status:* {status}
*Details:* {details}
*Timestamp:* {timestamp}
      `.trim(),
      channel: this.config.alertChannels.info
    });

    this.templates.set('maintenance_notification', {
      name: 'Maintenance Notification',
      severity: 'low',
      titleTemplate: '🔧 MAINTENANCE: {title}',
      messageTemplate: `
*Title:* {title}
*Description:* {description}
*Scheduled Time:* {scheduledTime}
*Expected Duration:* {duration}

*Impact:* {impact}
      `.trim(),
      channel: this.config.alertChannels.low
    });
  }

  private initializeNotifications(): void {
    if (this.config.providers.length === 0) {
      logger.warn('⚠️ Notifications enabled but no providers configured');
      return;
    }

    this.isInitialized = true;
    logger.info('📢 Notification system initialized', {
      providers: this.config.providers.length,
      defaultChannel: this.config.defaultChannel
    });
  }

  async sendSecurityAlert(alert: AnomalyAlert): Promise<void> {
    if (!this.isInitialized) return;

    const template = this.templates.get('security_alert');
    if (!template) return;

    const message: NotificationMessage = {
      id: `alert_${alert.id}_${Date.now()}`,
      title: this.interpolateTemplate(template.titleTemplate, {
        description: alert.description,
        alertId: alert.id,
        severity: alert.severity,
        confidence: (alert.confidence * 100).toFixed(1),
        type: alert.type
      }),
      message: this.interpolateTemplate(template.messageTemplate, {
        alertId: alert.id,
        severity: alert.severity.toUpperCase(),
        confidence: (alert.confidence * 100).toFixed(1),
        type: alert.type,
        description: alert.description,
        indicators: alert.indicators.map(i => `• ${i}`).join('\n'),
        affectedResources: alert.affectedResources.map(r => `• ${r}`).join('\n'),
        recommendedActions: alert.recommendedActions.map(a => `• ${a}`).join('\n'),
        timestamp: new Date(alert.timestamp).toISOString()
      }),
      severity: alert.severity,
      channel: template.channel,
      metadata: alert.metadata,
      timestamp: Date.now(),
      correlationId: alert.id
    };

    await this.sendNotification(message);
  }

  async sendPerformanceAlert(
    issue: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    metrics: Record<string, unknown>
  ): Promise<void> {
    if (!this.isInitialized) return;

    const template = this.templates.get('performance_issue');
    if (!template) return;

    const message: NotificationMessage = {
      id: `perf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      title: this.interpolateTemplate(template.titleTemplate, { issue }),
      message: this.interpolateTemplate(template.messageTemplate, {
        issue,
        severity: severity.toUpperCase(),
        metrics: Object.entries(metrics).map(([k, v]) => `${k}: ${v}`).join(', '),
        timestamp: new Date().toISOString()
      }),
      severity,
      channel: template.channel,
      metadata: metrics,
      timestamp: Date.now()
    };

    await this.sendNotification(message);
  }

  async sendSystemStatus(
    status: string,
    details: string,
    severity: NotificationMessage['severity'] = 'info'
  ): Promise<void> {
    if (!this.isInitialized) return;

    const template = this.templates.get('system_status');
    if (!template) return;

    const message: NotificationMessage = {
      id: `status_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      title: this.interpolateTemplate(template.titleTemplate, { status }),
      message: this.interpolateTemplate(template.messageTemplate, {
        status,
        details,
        timestamp: new Date().toISOString()
      }),
      severity,
      channel: template.channel,
      timestamp: Date.now()
    };

    await this.sendNotification(message);
  }

  async sendCustomNotification(
    title: string,
    message: string,
    severity: NotificationMessage['severity'] = 'info',
    channel?: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    if (!this.isInitialized) return;

    const notificationMessage: NotificationMessage = {
      id: `custom_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      title,
      message,
      severity,
      channel: channel || this.config.alertChannels[severity],
      metadata,
      timestamp: Date.now()
    };

    await this.sendNotification(notificationMessage);
  }

  private async sendNotification(message: NotificationMessage): Promise<void> {
    const promises = this.config.providers
      .filter(provider => provider.enabled)
      .map(provider => this.sendToProvider(provider, message));

    try {
      await Promise.allSettled(promises);
      logger.info('📢 Notification sent', {
        id: message.id,
        severity: message.severity,
        providers: this.config.providers.filter(p => p.enabled).length
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to send notification', {
        id: message.id,
        error: errorMessage
      });
    }
  }

  private async sendToProvider(provider: NotificationProvider, message: NotificationMessage): Promise<void> {
    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        const payload = this.formatMessageForProvider(provider, message);
        await this.makeProviderRequest(provider, payload);
        return; // Success
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.warn(`⚠️ Notification attempt ${attempt} failed for ${provider.name}`, {
          error: errorMessage,
          messageId: message.id
        });

        if (attempt < this.config.retryAttempts) {
          await this.delay(this.config.retryDelay);
        } else {
          throw error;
        }
      }
    }
  }

  private formatMessageForProvider(provider: NotificationProvider, message: NotificationMessage): any {
    const channel = message.channel || this.config.defaultChannel;

    switch (provider.type) {
      case 'slack':
        return {
          channel,
          username: provider.config.username,
          icon_emoji: provider.config.iconEmoji,
          attachments: [{
            color: this.getSeverityColor(message.severity),
            title: message.title,
            text: message.message,
            footer: 'Gemini MCP Security System',
            ts: message.timestamp / 1000
          }]
        };

      case 'teams':
        return {
          '@type': 'MessageCard',
          '@context': 'http://schema.org/extensions',
          themeColor: this.getSeverityColor(message.severity),
          title: message.title,
          text: message.message,
          sections: [{
            facts: [
              { name: 'Severity', value: message.severity },
              { name: 'Time', value: new Date(message.timestamp).toISOString() }
            ]
          }]
        };

      case 'discord':
        return {
          username: provider.config.username,
          avatar_url: provider.config.avatarUrl,
          embeds: [{
            color: parseInt(this.getSeverityColor(message.severity), 16),
            title: message.title,
            description: message.message,
            footer: {
              text: 'Gemini MCP Security System'
            },
            timestamp: new Date(message.timestamp).toISOString()
          }]
        };

      case 'webhook':
        return {
          event: 'notification',
          message,
          provider: provider.name,
          timestamp: message.timestamp
        };

      case 'email':
        return {
          to: message.recipients || [process.env.DEFAULT_EMAIL_RECIPIENT || 'security@company.com'],
          subject: message.title,
          html: this.formatEmailMessage(message),
          from: provider.config.fromEmail
        };

      default:
        return message;
    }
  }

  private getSeverityColor(severity: NotificationMessage['severity']): string {
    const colors: Record<NotificationMessage['severity'], string> = {
      'low': 'good', // green for Slack
      'medium': 'warning', // yellow
      'high': 'danger', // red
      'critical': '#FF0000', // bright red
      'info': '#36a64f' // green
    };
    return colors[severity] || colors.info;
  }

  private formatEmailMessage(message: NotificationMessage): string {
    const severityColors: Record<NotificationMessage['severity'], string> = {
      'low': '#28a745',
      'medium': '#ffc107',
      'high': '#dc3545',
      'critical': '#FF0000',
      'info': '#17a2b8'
    };

    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: ${severityColors[message.severity]}; color: white; padding: 20px; border-radius: 5px 5px 0 0;">
          <h2 style="margin: 0;">${message.title}</h2>
          <p style="margin: 5px 0 0 0;">Severity: ${message.severity.toUpperCase()}</p>
        </div>
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 0 0 5px 5px;">
          <div style="white-space: pre-line;">${message.message}</div>
          <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">
          <p style="color: #6c757d; font-size: 12px;">
            Generated by Gemini MCP Security System<br>
            Timestamp: ${new Date(message.timestamp).toISOString()}
          </p>
        </div>
      </div>
    `;
  }

  private async makeProviderRequest(provider: NotificationProvider, payload: any): Promise<void> {
    const config = provider.config as any;

    switch (provider.type) {
      case 'slack':
      case 'teams':
      case 'discord':
      case 'webhook':
        await this.makeWebhookRequest(config.webhookUrl, payload);
        break;

      case 'email':
        await this.sendEmail(config, payload);
        break;

      default:
        logger.warn(`⚠️ Unsupported provider type: ${provider.type}`);
    }
  }

  private async makeWebhookRequest(url: string, payload: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const options: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Gemini-MCP/1.0'
        }
      };

      const req = (parsedUrl.protocol === 'https:' ? https : http).request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            reject(new Error(`Webhook request failed: ${res.statusCode} ${data}`));
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

  private async sendEmail(config: any, payload: any): Promise<void> {
    // Placeholder for email sending implementation
    // In production, this would use nodemailer or similar
    logger.info('📧 Email notification would be sent', {
      to: payload.to,
      subject: payload.subject,
      smtpHost: config.smtpHost
    });
  }

  private interpolateTemplate(template: string, variables: Record<string, unknown>): string {
    return template.replace(/{(\w+)}/g, (match, key) => {
      return variables[key] !== undefined ? String(variables[key]) : match;
    });
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Template management
  addTemplate(template: AlertTemplate): void {
    this.templates.set(template.name.toLowerCase(), template);
    logger.info('📝 Notification template added', { name: template.name });
  }

  updateTemplate(name: string, updates: Partial<AlertTemplate>): boolean {
    const template = this.templates.get(name.toLowerCase());
    if (template) {
      Object.assign(template, updates);
      logger.info('📝 Notification template updated', { name });
      return true;
    }
    return false;
  }

  removeTemplate(name: string): boolean {
    const deleted = this.templates.delete(name.toLowerCase());
    if (deleted) {
      logger.info('🗑️ Notification template removed', { name });
    }
    return deleted;
  }

  getTemplates(): AlertTemplate[] {
    return Array.from(this.templates.values());
  }

  // Testing and validation
  async testNotification(providerName: string): Promise<boolean> {
    if (!this.isInitialized) return false;

    const provider = this.config.providers.find(p => p.name === providerName);
    if (!provider) return false;

    const testMessage: NotificationMessage = {
      id: `test_${Date.now()}`,
      title: '🧪 Test Notification',
      message: 'This is a test notification from Gemini MCP Security System.\n\nIf you received this, notifications are working correctly!',
      severity: 'info',
      timestamp: Date.now()
    };

    try {
      await this.sendToProvider(provider, testMessage);
      logger.info('✅ Test notification sent successfully', { provider: providerName });
      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Test notification failed', {
        provider: providerName,
        error: errorMessage
      });
      return false;
    }
  }

  getStatus(): {
    enabled: boolean;
    initialized: boolean;
    providers: string[];
    templates: number;
    health: 'healthy' | 'warning' | 'error';
  } {
    return {
      enabled: this.config.enabled,
      initialized: this.isInitialized,
      providers: this.config.providers.filter(p => p.enabled).map(p => p.name),
      templates: this.templates.size,
      health: this.isInitialized ? 'healthy' : 'error'
    };
  }

  async shutdown(): Promise<void> {
    this.isInitialized = false;
    logger.info('🛑 Notification system shutdown');
  }
}

export const notificationManager = NotificationManager.getInstance();
