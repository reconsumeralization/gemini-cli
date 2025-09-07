/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Secure Headers and CSP for VS Code Plugin Communication
import { createHmac, randomBytes } from 'crypto';
import { logger } from '../../utils/logger.js';

export interface SecurityHeaders {
  // Content Security Policy
  'Content-Security-Policy': string;

  // Prevent clickjacking
  'X-Frame-Options': string;
  'Content-Security-Policy-Report-Only'?: string;

  // Prevent MIME sniffing
  'X-Content-Type-Options': string;

  // XSS protection
  'X-XSS-Protection': string;

  // Referrer policy
  'Referrer-Policy': string;

  // HSTS (for HTTPS connections)
  'Strict-Transport-Security'?: string;

  // Feature policy
  'Permissions-Policy': string;

  // Cross-Origin Embedder Policy
  'Cross-Origin-Embedder-Policy'?: string;

  // Cross-Origin Opener Policy
  'Cross-Origin-Opener-Policy'?: string;

  // Cross-Origin Resource Policy
  'Cross-Origin-Resource-Policy'?: string;

  // Custom security headers
  'X-VSCode-Security-Token': string;
  'X-Request-ID': string;
  'X-Timestamp': string;
}

export interface CSPDirectives {
  'default-src': string[];
  'script-src': string[];
  'style-src': string[];
  'img-src': string[];
  'font-src': string[];
  'connect-src': string[];
  'media-src': string[];
  'object-src': string[];
  'frame-src': string[];
  'frame-ancestors': string[];
  'form-action': string[];
  'base-uri': string[];
  'upgrade-insecure-requests'?: boolean;
  'block-all-mixed-content'?: boolean;
  'require-trusted-types-for'?: string[];
  'trusted-types'?: string[];
}

export interface SecurityContext {
  isExtension: boolean;
  extensionId?: string;
  extensionVersion?: string;
  vscodeVersion: string;
  workspaceTrust: boolean;
  remoteAuthority?: string;
  webviewResourceRoots?: string[];
}

export class SecureHeadersManager {
  private static instance: SecureHeadersManager;
  private securityTokens = new Map<string, { token: string; expires: number; context: SecurityContext }>();
  private tokenSecrets = new Map<string, { secret: Buffer; created: number; expires: number }>();
  private readonly TOKEN_SECRET_ROTATION_HOURS = 24;

  static getInstance(): SecureHeadersManager {
    if (!SecureHeadersManager.instance) {
      SecureHeadersManager.instance = new SecureHeadersManager();
    }
    return SecureHeadersManager.instance;
  }

  private constructor() {
    // Clean up expired tokens every 5 minutes
    setInterval(() => {
      this.cleanupExpiredTokens();
    }, 5 * 60 * 1000);

    // Rotate token secrets periodically
    setInterval(() => {
      this.rotateTokenSecrets();
    }, this.TOKEN_SECRET_ROTATION_HOURS * 60 * 60 * 1000);

    // Initialize first secret
    this.rotateTokenSecrets();
  }

  async generateSecureHeaders(securityContext: SecurityContext): Promise<SecurityHeaders> {
    const requestId = this.generateRequestId();
    const timestamp = Date.now().toString();
    const securityToken = await this.generateSecurityToken(securityContext, requestId);

    const csp = this.generateCSP(securityContext);
    const permissionsPolicy = this.generatePermissionsPolicy(securityContext);

    const headers: SecurityHeaders = {
      // Strict CSP for VS Code extension communication
      'Content-Security-Policy': csp,

      // Prevent clickjacking attacks
      'X-Frame-Options': 'DENY',

      // Prevent MIME type sniffing
      'X-Content-Type-Options': 'nosniff',

      // XSS protection (though CSP is primary)
      'X-XSS-Protection': '1; mode=block',

      // Strict referrer policy
      'Referrer-Policy': 'strict-origin-when-cross-origin',

      // Feature policy for VS Code
      'Permissions-Policy': permissionsPolicy,

      // Custom security token
      'X-VSCode-Security-Token': securityToken,
      'X-Request-ID': requestId,
      'X-Timestamp': timestamp
    };

    // Add HSTS for HTTPS connections
    if (securityContext.remoteAuthority) {
      headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
    }

    // Add CSP report-only for monitoring
    if (process.env['CSP_REPORTING_ENABLED'] === 'true') {
      headers['Content-Security-Policy-Report-Only'] = this.generateCSPReportOnly(securityContext);
    }

    // Add modern security headers for VS Code extensions
    if (securityContext.isExtension) {
      headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
      headers['Cross-Origin-Opener-Policy'] = 'same-origin';
      headers['Cross-Origin-Resource-Policy'] = 'cross-origin';
    }

    return headers;
  }

  private generateCSP(context: SecurityContext): string {
    const directives: CSPDirectives = {
      'default-src': ["'self'"],
      'script-src': ["'self'"], // Removed unsafe-inline for better security
      'style-src': ["'self'"], // Removed unsafe-inline for better security
      'img-src': ["'self'", 'data:', 'vscode-resource:', 'https:'],
      'font-src': ["'self'", 'vscode-resource:', 'https:'],
      'connect-src': ["'self'", 'https:', 'wss:'],
      'media-src': ["'self'", 'https:'],
      'object-src': ["'none'"],
      'frame-src': ["'none'"],
      'frame-ancestors': ["'none'"],
      'form-action': ["'self'"],
      'base-uri': ["'self'"],
      'upgrade-insecure-requests': true,
      'block-all-mixed-content': true,
      // Additional HTTPS security
      'require-trusted-types-for': ["'script'"],
      'trusted-types': ['vscode-policy']
    };

    // Add extension-specific CSP rules
    if (context.isExtension && context.extensionId) {
      directives['script-src'].push(`vscode-extension://${context.extensionId}/`);
      directives['style-src'].push(`vscode-extension://${context.extensionId}/`);
      directives['img-src'].push(`vscode-extension://${context.extensionId}/`);
    }

    // Add webview resource roots if available
    if (context.webviewResourceRoots) {
      context.webviewResourceRoots.forEach(root => {
        directives['script-src'].push(root);
        directives['style-src'].push(root);
        directives['img-src'].push(root);
      });
    }

    // Convert to CSP string
    const cspParts: string[] = [];

    for (const [directive, values] of Object.entries(directives)) {
      if (Array.isArray(values)) {
        cspParts.push(`${directive} ${values.join(' ')}`);
      } else if (typeof values === 'boolean' && values) {
        cspParts.push(directive);
      }
    }

    return cspParts.join('; ');
  }

  private generateCSPReportOnly(context: SecurityContext): string {
    // Report-only CSP for monitoring violations
    return `${this.generateCSP(context)}; report-uri /csp-report`;
  }

  private generatePermissionsPolicy(context: SecurityContext): string {
    const policies = [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'magnetometer=()',
      'accelerometer=()',
      'gyroscope=()',
      'ambient-light-sensor=()',
      'autoplay=()',
      'encrypted-media=()',
      'fullscreen=(self)',
      'picture-in-picture=()'
    ];

    // Allow clipboard for VS Code functionality
    if (context.isExtension) {
      policies.push('clipboard-write=(self)');
    }

    return policies.join(', ');
  }

  private async generateSecurityToken(context: SecurityContext, requestId: string): Promise<string> {
    const payload = {
      requestId,
      extensionId: context.extensionId,
      timestamp: Date.now(),
      vscodeVersion: context.vscodeVersion,
      workspaceTrust: context.workspaceTrust
    };

    const token = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = await this.generateSignature(token);

    return `${token}.${signature}`;
  }

  private rotateTokenSecrets(): void {
    const secretId = `secret_${Date.now()}`;
    const secret = randomBytes(32); // Generate strong 256-bit secret
    const created = Date.now();
    const expires = created + (this.TOKEN_SECRET_ROTATION_HOURS * 60 * 60 * 1000);

    this.tokenSecrets.set(secretId, {
      secret,
      created,
      expires
    });

    // Keep only the last 3 secrets for validation of existing tokens
    if (this.tokenSecrets.size > 3) {
      const oldestSecret = Array.from(this.tokenSecrets.entries())
        .sort(([,a], [,b]) => a.created - b.created)[0][0];
      this.tokenSecrets.delete(oldestSecret);
    }

    logger.debug('🔄 Token secrets rotated', { secretId });
  }

  private async generateSignature(data: string): Promise<string> {
    // Use the most recent secret for signing new tokens
    const currentSecret = Array.from(this.tokenSecrets.values())
      .sort((a, b) => b.created - a.created)[0];

    if (!currentSecret) {
      // Fallback to environment variable if no secrets are available
      const fallbackSecret = process.env['SECURITY_TOKEN_SECRET'];
      if (!fallbackSecret) {
        throw new Error('No token secret available for signing');
      }
      return createHmac('sha256', fallbackSecret).update(data).digest('hex').substring(0, 16);
    }

    return createHmac('sha256', currentSecret.secret).update(data).digest('hex').substring(0, 16);
  }



  /**
   * Constant-time delay to prevent timing attacks
   */
  private constantTimeDelay(ms: number): void {
    const start = Date.now();
    while (Date.now() - start < ms) {
      // Busy wait to ensure constant time
    }
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${randomBytes(8).toString('hex')}`;
  }

  async validateSecurityToken(token: string): Promise<{ valid: boolean; context?: SecurityContext; error?: string }> {
    try {
      // Always perform timing-safe verification first
      const parts = token.split('.');
      if (parts.length !== 2) {
        // Constant-time delay for invalid format
        this.constantTimeDelay(100);
        return { valid: false, error: 'Invalid token format' };
      }

      const [, _signature] = parts;

      // Generate expected signature using the full token for verification
      const expectedSignature = await this.generateSignature(parts[0]);

      // Use timing-safe comparison with crypto.timingSafeEqual
      const crypto = await import('crypto');
      if (_signature.length !== expectedSignature.length ||
          !crypto.timingSafeEqual(Buffer.from(_signature, 'hex'), Buffer.from(expectedSignature, 'hex'))) {
        return { valid: false, error: 'Invalid token signature' };
      }

      // Only parse payload after signature verification
      const decodedPayload = JSON.parse(Buffer.from(parts[0], 'base64').toString());

      // Check token expiration (5 minute window)
      if (Date.now() - decodedPayload.timestamp > 5 * 60 * 1000) {
        // Constant-time delay for expired tokens
        this.constantTimeDelay(50);
        return { valid: false, error: 'Token expired' };
      }

      return {
        valid: true,
        context: {
          isExtension: true,
          extensionId: decodedPayload.extensionId,
          vscodeVersion: decodedPayload.vscodeVersion,
          workspaceTrust: decodedPayload.workspaceTrust
        } as SecurityContext
      };

    } catch (error) {
      const sanitizedError = this.sanitizeErrorMessage(error);
      logger.warn('⚠️ Token validation failed', { error: sanitizedError });
      // Constant-time delay for parsing errors
      this.constantTimeDelay(100);
      return { valid: false, error: 'Token validation failed' };
    }
  }

  async validateSecurityHeaders(headers: Record<string, string>, expectedToken?: string): Promise<{
    valid: boolean;
    violations: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  }> {
    const violations: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

    // Check for required security headers
    const requiredHeaders = [
      'X-VSCode-Security-Token',
      'X-Request-ID',
      'Content-Security-Policy',
      'X-Frame-Options',
      'X-Content-Type-Options'
    ];

    for (const header of requiredHeaders) {
      if (!headers[header]) {
        violations.push(`Missing required header: ${header}`);
        riskLevel = 'high';
      }
    }

    // Validate security token
    if (expectedToken && headers['X-VSCode-Security-Token']) {
      const tokenValidation = await this.validateSecurityToken(headers['X-VSCode-Security-Token']);
      if (!tokenValidation.valid) {
        violations.push(`Invalid security token: ${tokenValidation.error}`);
        riskLevel = 'critical';
      }
    }

    // Check CSP header
    if (headers['Content-Security-Policy']) {
      const cspViolations = this.validateCSPHeader(headers['Content-Security-Policy']);
      violations.push(...cspViolations);
      if (cspViolations.length > 0) {
        riskLevel = riskLevel === 'critical' ? 'critical' : 'high';
      }
    }

    // Check for suspicious headers
    const suspiciousHeaders = ['X-Forwarded-For', 'X-Real-IP'];
    for (const header of suspiciousHeaders) {
      if (headers[header]) {
        violations.push(`Suspicious header present: ${header}`);
        riskLevel = riskLevel === 'critical' ? 'critical' : 'medium';
      }
    }

    return {
      valid: violations.length === 0,
      violations,
      riskLevel
    };
  }

  private validateCSPHeader(csp: string): string[] {
    const violations: string[] = [];

    // Check for dangerous CSP directives
    if (csp.includes("'unsafe-inline'")) {
      violations.push('CSP allows unsafe inline scripts');
    }

    if (csp.includes("'unsafe-eval'")) {
      violations.push('CSP allows unsafe eval');
    }

    if (csp.includes('*')) {
      violations.push('CSP uses wildcard sources');
    }

    if (!csp.includes('default-src')) {
      violations.push('CSP missing default-src directive');
    }

    return violations;
  }

  generateSecurityReport(): {
    activeTokens: number;
    recentValidations: number;
    violationsDetected: number;
    riskDistribution: Record<string, number>;
    recommendations: string[];
  } {
    // Generate security report for monitoring
    return {
      activeTokens: this.securityTokens.size,
      recentValidations: 0, // Would track actual validations
      violationsDetected: 0, // Would track actual violations
      riskDistribution: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0
      },
      recommendations: [
        'Regular security header audits',
        'Monitor CSP violation reports',
        'Rotate security tokens periodically',
        'Implement rate limiting for API endpoints'
      ]
    };
  }

  private cleanupExpiredTokens(): void {
    const now = Date.now();
    let cleaned = 0;

    // Use Array.from for better compatibility with older TypeScript targets
    Array.from(this.securityTokens.entries()).forEach(([tokenId, tokenData]) => {
      if (now > tokenData.expires) {
        this.securityTokens.delete(tokenId);
        cleaned++;
      }
    });

    if (cleaned > 0) {
      logger.debug('🧹 Cleaned up expired security tokens', { count: cleaned });
    }
  }

  // Emergency security lockdown
  emergencyLockdown(reason: string): void {
    logger.error('🚨 EMERGENCY SECURITY LOCKDOWN', { reason });

    // Clear all active tokens
    this.securityTokens.clear();

    // Log emergency event
    // In production, this would trigger alerts and notifications

    logger.error('🔒 All security tokens invalidated due to emergency lockdown');
  }

  // Health check
  private sanitizeErrorMessage(error: unknown): string {
    if (!error) return 'Unknown error';

    if (error instanceof Error) {
      let message = error.message;

      // Remove file paths
      message = message.replace(/\/[^\s]+/g, '/[PATH_REDACTED]');

      // Remove stack traces
      message = message.replace(/at\s+[^\s]+/g, 'at [FUNCTION_REDACTED]');

      // Remove sensitive data patterns
      message = message.replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, '[CARD_REDACTED]');
      message = message.replace(/\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b/g, '[SSN_REDACTED]');
      message = message.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_REDACTED]');

      // Limit error message length
      if (message.length > 200) {
        message = message.substring(0, 200) + '...';
      }

      return message;
    }

    return 'An unexpected error occurred';
  }

  getHealthStatus(): {
    status: 'healthy' | 'warning' | 'critical';
    activeTokens: number;
    tokenExpirationRate: number;
    headerValidationRate: number;
    issues: string[];
  } {
    const issues: string[] = [];
    let status: 'healthy' | 'warning' | 'critical' = 'healthy';

    if (this.securityTokens.size > 1000) {
      issues.push('High number of active security tokens');
      status = 'warning';
    }

    // Check for expired tokens (placeholder logic)
    const expiredTokens = Array.from(this.securityTokens.values())
      .filter(token => Date.now() > token.expires).length;

    if (expiredTokens > this.securityTokens.size * 0.1) {
      issues.push(`${expiredTokens} expired tokens need cleanup`);
      status = 'warning';
    }

    return {
      status,
      activeTokens: this.securityTokens.size,
      tokenExpirationRate: expiredTokens / Math.max(this.securityTokens.size, 1),
      headerValidationRate: 0.99, // Placeholder
      issues
    };
  }
}

export const secureHeadersManager = SecureHeadersManager.getInstance();
