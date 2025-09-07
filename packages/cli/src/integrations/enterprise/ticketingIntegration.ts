/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Enterprise Ticketing System Integration for Incident Management
import * as https from 'https';
import * as http from 'http';
import { logger } from '../../utils/logger.js';
import { AnomalyAlert } from '../../security/anomaly/anomalyDetector.js';

export interface TicketingConfig {
  enabled: boolean;
  provider: 'jira' | 'servicenow' | 'zendesk' | 'custom';
  endpoint: string;
  apiKey?: string;
  username?: string;
  password?: string;
  projectKey?: string;
  issueType?: string;
  customFields?: Record<string, string>;
  priorityMapping: Record<string, string>;
  labels: string[];
  autoAssign: boolean;
  assignee?: string;
}

export interface Ticket {
  id: string;
  key: string;
  title: string;
  description: string;
  status: 'open' | 'in_progress' | 'resolved' | 'closed';
  priority: 'low' | 'medium' | 'high' | 'critical';
  assignee?: string;
  reporter: string;
  createdAt: string;
  updatedAt: string;
  labels: string[];
  comments: TicketComment[];
  metadata: Record<string, unknown>;
}

export interface TicketComment {
  id: string;
  author: string;
  content: string;
  timestamp: string;
  isInternal: boolean;
}

export interface CreateTicketRequest {
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  labels?: string[];
  assignee?: string;
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

class TicketingIntegrationManager {
  private static instance: TicketingIntegrationManager;
  private config: TicketingConfig;
  private isInitialized = false;

  static getInstance(): TicketingIntegrationManager {
    if (!TicketingIntegrationManager.instance) {
      TicketingIntegrationManager.instance = new TicketingIntegrationManager();
    }
    return TicketingIntegrationManager.instance;
  }

  private constructor() {
    this.config = this.loadTicketingConfig();
    if (this.config.enabled) {
      this.initializeTicketing();
    }
  }

  private loadTicketingConfig(): TicketingConfig {
    return {
      enabled: process.env.TICKETING_ENABLED === 'true',
      provider: (process.env.TICKETING_PROVIDER as TicketingConfig['provider']) || 'jira',
      endpoint: process.env.TICKETING_ENDPOINT || '',
      apiKey: process.env.TICKETING_API_KEY,
      username: process.env.TICKETING_USERNAME,
      password: process.env.TICKETING_PASSWORD,
      projectKey: process.env.TICKETING_PROJECT_KEY || 'SEC',
      issueType: process.env.TICKETING_ISSUE_TYPE || 'Security Incident',
      customFields: this.parseCustomFields(process.env.TICKETING_CUSTOM_FIELDS),
      priorityMapping: {
        'low': 'Low',
        'medium': 'Medium',
        'high': 'High',
        'critical': 'Highest'
      },
      labels: ['security', 'automated', 'mcp-generated'],
      autoAssign: process.env.TICKETING_AUTO_ASSIGN === 'true',
      assignee: process.env.TICKETING_ASSIGNEE
    };
  }

  private parseCustomFields(customFieldsStr?: string): Record<string, string> {
    if (!customFieldsStr) return {};

    try {
      return JSON.parse(customFieldsStr);
    } catch {
      return {};
    }
  }

  private initializeTicketing(): void {
    if (!this.config.endpoint) {
      logger.warn('⚠️ Ticketing integration enabled but no endpoint configured');
      return;
    }

    this.isInitialized = true;
    logger.info('🎫 Ticketing integration initialized', {
      provider: this.config.provider,
      projectKey: this.config.projectKey
    });
  }

  async createSecurityIncident(alert: AnomalyAlert): Promise<Ticket | null> {
    if (!this.isInitialized) return null;

    const request: CreateTicketRequest = {
      title: `[SECURITY ALERT] ${alert.description}`,
      description: this.formatAlertDescription(alert),
      priority: alert.severity,
      labels: [...this.config.labels, 'security-incident', `severity-${alert.severity}`],
      assignee: this.config.autoAssign ? this.config.assignee : undefined,
      metadata: {
        alertId: alert.id,
        confidence: alert.confidence,
        indicators: alert.indicators,
        affectedResources: alert.affectedResources,
        correlationId: alert.id
      },
      correlationId: alert.id
    };

    try {
      const ticket = await this.createTicket(request);
      logger.info('🎫 Security incident ticket created', {
        alertId: alert.id,
        ticketId: ticket.id,
        ticketKey: ticket.key
      });

      // Add initial comment with detailed information
      await this.addComment(ticket.id, this.generateDetailedComment(alert));

      return ticket;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to create security incident ticket', {
        alertId: alert.id,
        error: errorMessage
      });
      return null;
    }
  }

  async createPerformanceIncident(
    issue: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    metrics: Record<string, unknown>
  ): Promise<Ticket | null> {
    if (!this.isInitialized) return null;

    const request: CreateTicketRequest = {
      title: `[PERFORMANCE] ${issue}`,
      description: this.formatPerformanceDescription(issue, metrics),
      priority: severity,
      labels: [...this.config.labels, 'performance-issue'],
      assignee: this.config.autoAssign ? this.config.assignee : undefined,
      metadata: {
        issue,
        metrics,
        type: 'performance'
      }
    };

    try {
      const ticket = await this.createTicket(request);
      logger.info('🎫 Performance incident ticket created', {
        issue,
        ticketId: ticket.id
      });
      return ticket;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to create performance incident ticket', { error: errorMessage });
      return null;
    }
  }

  async createGeneralTicket(
    title: string,
    description: string,
    priority: 'low' | 'medium' | 'high' | 'critical' = 'medium',
    labels: string[] = []
  ): Promise<Ticket | null> {
    if (!this.isInitialized) return null;

    const request: CreateTicketRequest = {
      title,
      description,
      priority,
      labels: [...this.config.labels, ...labels],
      assignee: this.config.autoAssign ? this.config.assignee : undefined
    };

    try {
      const ticket = await this.createTicket(request);
      logger.info('🎫 General ticket created', {
        title,
        ticketId: ticket.id
      });
      return ticket;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to create general ticket', { error: errorMessage });
      return null;
    }
  }

  private async createTicket(request: CreateTicketRequest): Promise<Ticket> {
    const payload = this.formatTicketForProvider(request);
    const response = await this.makeTicketingRequest('POST', '/issues', payload);

    return this.parseTicketResponse(response);
  }

  private formatTicketForProvider(request: CreateTicketRequest): any {
    switch (this.config.provider) {
      case 'jira':
        return {
          fields: {
            project: { key: this.config.projectKey },
            summary: request.title,
            description: request.description,
            issuetype: { name: this.config.issueType },
            priority: { name: this.config.priorityMapping[request.priority] },
            labels: request.labels,
            assignee: request.assignee ? { name: request.assignee } : undefined,
            ...this.config.customFields
          }
        };

      case 'servicenow':
        return {
          short_description: request.title,
          description: request.description,
          priority: this.mapPriorityToServiceNow(request.priority),
          assignment_group: request.assignee,
          labels: request.labels?.join(','),
          correlation_id: request.correlationId,
          ...this.config.customFields
        };

      case 'zendesk':
        return {
          ticket: {
            subject: request.title,
            description: request.description,
            priority: request.priority,
            tags: request.labels,
            assignee_id: request.assignee,
            custom_fields: this.formatCustomFieldsForZendesk(this.config.customFields),
            external_id: request.correlationId
          }
        };

      default:
        return request;
    }
  }

  private mapPriorityToServiceNow(priority: string): string {
    const mapping: Record<string, string> = {
      'critical': '1',
      'high': '2',
      'medium': '3',
      'low': '4'
    };
    return mapping[priority] || '3';
  }

  private formatCustomFieldsForZendesk(customFields?: Record<string, string>): Array<{ id: string; value: string }> {
    if (!customFields) return [];

    return Object.entries(customFields).map(([key, value]) => ({
      id: key,
      value
    }));
  }

  private parseTicketResponse(response: any): Ticket {
    switch (this.config.provider) {
      case 'jira':
        return {
          id: response.id,
          key: response.key,
          title: response.fields.summary,
          description: response.fields.description,
          status: this.mapJiraStatus(response.fields.status?.name),
          priority: this.mapJiraPriority(response.fields.priority?.name),
          assignee: response.fields.assignee?.displayName,
          reporter: 'gemini-mcp',
          createdAt: response.fields.created,
          updatedAt: response.fields.updated,
          labels: response.fields.labels || [],
          comments: [],
          metadata: {}
        };

      case 'servicenow':
        return {
          id: response.sys_id,
          key: response.number,
          title: response.short_description,
          description: response.description,
          status: this.mapServiceNowStatus(response.state),
          priority: this.mapServiceNowPriority(response.priority),
          assignee: response.assigned_to,
          reporter: 'gemini-mcp',
          createdAt: response.sys_created_on,
          updatedAt: response.sys_updated_on,
          labels: response.labels?.split(',') || [],
          comments: [],
          metadata: {}
        };

      case 'zendesk':
        return {
          id: response.ticket.id.toString(),
          key: response.ticket.id.toString(),
          title: response.ticket.subject,
          description: response.ticket.description,
          status: this.mapZendeskStatus(response.ticket.status),
          priority: response.ticket.priority,
          assignee: response.ticket.assignee_id?.toString(),
          reporter: 'gemini-mcp',
          createdAt: response.ticket.created_at,
          updatedAt: response.ticket.updated_at,
          labels: response.ticket.tags || [],
          comments: [],
          metadata: {}
        };

      default:
        return response;
    }
  }

  private mapJiraStatus(status: string): Ticket['status'] {
    const statusMapping: Record<string, Ticket['status']> = {
      'Open': 'open',
      'In Progress': 'in_progress',
      'Resolved': 'resolved',
      'Closed': 'closed'
    };
    return statusMapping[status] || 'open';
  }

  private mapJiraPriority(priority: string): Ticket['priority'] {
    const priorityMapping: Record<string, Ticket['priority']> = {
      'Lowest': 'low',
      'Low': 'low',
      'Medium': 'medium',
      'High': 'high',
      'Highest': 'critical'
    };
    return priorityMapping[priority] || 'medium';
  }

  private mapServiceNowStatus(state: string): Ticket['status'] {
    const statusMapping: Record<string, Ticket['status']> = {
      '1': 'open',
      '2': 'in_progress',
      '6': 'resolved',
      '7': 'closed'
    };
    return statusMapping[state] || 'open';
  }

  private mapServiceNowPriority(priority: string): Ticket['priority'] {
    const priorityMapping: Record<string, Ticket['priority']> = {
      '1': 'critical',
      '2': 'high',
      '3': 'medium',
      '4': 'low'
    };
    return priorityMapping[priority] || 'medium';
  }

  private mapZendeskStatus(status: string): Ticket['status'] {
    const statusMapping: Record<string, Ticket['status']> = {
      'new': 'open',
      'open': 'open',
      'pending': 'in_progress',
      'solved': 'resolved',
      'closed': 'closed'
    };
    return statusMapping[status] || 'open';
  }

  private formatAlertDescription(alert: AnomalyAlert): string {
    return `
🚨 **SECURITY ALERT DETECTED**

**Alert ID:** ${alert.id}
**Severity:** ${alert.severity.toUpperCase()}
**Confidence:** ${(alert.confidence * 100).toFixed(1)}%
**Type:** ${alert.type}

**Description:**
${alert.description}

**Indicators:**
${alert.indicators.map(indicator => `- ${indicator}`).join('\n')}

**Affected Resources:**
${alert.affectedResources.map(resource => `- ${resource}`).join('\n')}

**Recommended Actions:**
${alert.recommendedActions.map(action => `- ${action}`).join('\n')}

**Detection Time:** ${new Date(alert.timestamp).toISOString()}

**Metadata:**
${Object.entries(alert.metadata).map(([key, value]) => `- ${key}: ${value}`).join('\n')}

---
*This ticket was automatically generated by Gemini MCP Security System*
    `.trim();
  }

  private formatPerformanceDescription(issue: string, metrics: Record<string, unknown>): string {
    return `
⚡ **PERFORMANCE ISSUE DETECTED**

**Issue:** ${issue}

**Metrics:**
${Object.entries(metrics).map(([key, value]) => `- ${key}: ${value}`).join('\n')}

**Detection Time:** ${new Date().toISOString()}

---
*This ticket was automatically generated by Gemini MCP Performance Monitoring*
    `.trim();
  }

  private generateDetailedComment(alert: AnomalyAlert): string {
    return `
🔍 **DETAILED SECURITY ANALYSIS**

**Timeline:**
- Detected: ${new Date(alert.timestamp).toISOString()}
- Confidence Score: ${(alert.confidence * 100).toFixed(1)}%

**Technical Details:**
- Alert Type: ${alert.type}
- Severity Level: ${alert.severity}
- Correlation ID: ${alert.id}

**Investigation Notes:**
- Review system logs for the timeframe around detection
- Check for similar patterns in recent alerts
- Validate the affected resources listed above
- Assess the impact on business operations

**Immediate Actions Taken:**
- Alert logged to SIEM system
- Additional monitoring enabled for affected resources
- Automated response procedures initiated

**Next Steps:**
1. Acknowledge this ticket
2. Assign to appropriate security team member
3. Begin investigation using the indicators provided
4. Update ticket with findings and resolution steps

---
*Generated by Gemini MCP Automated Incident Response*
    `.trim();
  }

  async addComment(ticketId: string, comment: string, isInternal = false): Promise<void> {
    if (!this.isInitialized) return;

    try {
      const payload = this.formatCommentForProvider(comment, isInternal);
      await this.makeTicketingRequest('POST', `/issues/${ticketId}/comments`, payload);

      logger.debug('💬 Comment added to ticket', { ticketId });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to add comment to ticket', { ticketId, error: errorMessage });
    }
  }

  private formatCommentForProvider(comment: string, isInternal: boolean): any {
    switch (this.config.provider) {
      case 'jira':
        return {
          body: comment,
          properties: isInternal ? [{ key: 'sd.public.comment', value: 'internal' }] : []
        };

      case 'servicenow':
        return {
          element: 'comments',
          value: comment,
          is_internal: isInternal
        };

      case 'zendesk':
        return {
          comment: {
            body: comment,
            public: !isInternal
          }
        };

      default:
        return { comment, isInternal };
    }
  }

  async updateTicketStatus(ticketId: string, status: Ticket['status']): Promise<void> {
    if (!this.isInitialized) return;

    try {
      const payload = this.formatStatusUpdateForProvider(status);
      await this.makeTicketingRequest('PUT', `/issues/${ticketId}`, payload);

      logger.info('📝 Ticket status updated', { ticketId, status });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to update ticket status', { ticketId, status, error: errorMessage });
    }
  }

  private formatStatusUpdateForProvider(status: Ticket['status']): any {
    switch (this.config.provider) {
      case 'jira':
        return {
          fields: {
            status: { name: this.mapStatusToJira(status) }
          }
        };

      case 'servicenow':
        return {
          state: this.mapStatusToServiceNow(status)
        };

      case 'zendesk':
        return {
          ticket: {
            status: this.mapStatusToZendesk(status)
          }
        };

      default:
        return { status };
    }
  }

  private mapStatusToJira(status: Ticket['status']): string {
    const statusMapping: Record<Ticket['status'], string> = {
      'open': 'Open',
      'in_progress': 'In Progress',
      'resolved': 'Resolved',
      'closed': 'Closed'
    };
    return statusMapping[status] || 'Open';
  }

  private mapStatusToServiceNow(status: Ticket['status']): string {
    const statusMapping: Record<Ticket['status'], string> = {
      'open': '1',
      'in_progress': '2',
      'resolved': '6',
      'closed': '7'
    };
    return statusMapping[status] || '1';
  }

  private mapStatusToZendesk(status: Ticket['status']): string {
    const statusMapping: Record<Ticket['status'], string> = {
      'open': 'open',
      'in_progress': 'pending',
      'resolved': 'solved',
      'closed': 'closed'
    };
    return statusMapping[status] || 'open';
  }

  private async makeTicketingRequest(method: string, path: string, payload?: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const url = new URL(this.config.endpoint);
      const options: https.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${path}`.replace('//', '/'),
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': this.getAuthHeader(),
          'User-Agent': 'Gemini-MCP/1.0'
        }
      };

      const req = (url.protocol === 'https:' ? https : http).request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsedData = data ? JSON.parse(data) : {};
              resolve(parsedData);
            } catch (parseError) {
              resolve(data);
            }
          } else {
            reject(new Error(`Ticketing request failed: ${res.statusCode} ${data}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      if (payload) {
        req.write(JSON.stringify(payload));
      }

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

  async getTicket(ticketId: string): Promise<Ticket | null> {
    if (!this.isInitialized) return null;

    try {
      const response = await this.makeTicketingRequest('GET', `/issues/${ticketId}`);
      return this.parseTicketResponse(response);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to get ticket', { ticketId, error: errorMessage });
      return null;
    }
  }

  async getTicketsByStatus(status: Ticket['status'], limit = 50): Promise<Ticket[]> {
    if (!this.isInitialized) return [];

    try {
      // Implementation would vary by provider
      const query = this.buildStatusQuery(status);
      const response = await this.makeTicketingRequest('GET', `/issues?${query}&limit=${limit}`);
      return Array.isArray(response.issues) ? response.issues.map(this.parseTicketResponse) : [];
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to get tickets by status', { status, error: errorMessage });
      return [];
    }
  }

  private buildStatusQuery(status: Ticket['status']): string {
    switch (this.config.provider) {
      case 'jira':
        return `status="${this.mapStatusToJira(status)}"`;
      case 'servicenow':
        return `state=${this.mapStatusToServiceNow(status)}`;
      case 'zendesk':
        return `status=${this.mapStatusToZendesk(status)}`;
      default:
        return `status=${status}`;
    }
  }

  getStatus(): {
    enabled: boolean;
    initialized: boolean;
    provider: string;
    projectKey?: string;
    health: 'healthy' | 'warning' | 'error';
  } {
    return {
      enabled: this.config.enabled,
      initialized: this.isInitialized,
      provider: this.config.provider,
      projectKey: this.config.projectKey,
      health: this.isInitialized ? 'healthy' : 'error'
    };
  }

  async shutdown(): Promise<void> {
    this.isInitialized = false;
    logger.info('🛑 Ticketing integration shutdown');
  }
}

export const ticketingIntegration = TicketingIntegrationManager.getInstance();
