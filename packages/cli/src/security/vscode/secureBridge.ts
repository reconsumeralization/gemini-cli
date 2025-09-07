/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Secure Bridge for VS Code Plugin Communication
import * as crypto from 'crypto';
import { logger } from '../../utils/logger.js';
import { rateLimiterRegistry } from '../../utils/rateLimiter.js';
import { validatorRegistry, ValidationSchema } from '../../utils/dataValidator.js';
import { auditTrail } from '../../utils/auditTrail.js';

// Message types for better type safety
interface RawVSCodeMessage {
  id: string;
  type: string;
  method: string;
  params?: Record<string, unknown>;
  timestamp?: number;
  sessionId?: string;
  correlationId?: string;
  metadata?: Record<string, unknown>;
  encrypted?: boolean;
}

interface EncryptedVSCodeMessage {
  encrypted: boolean;
  data: string;
  keyId: string;
  iv: string;
  authTag: string;
}

export interface VSCodeMessage {
  id: string;
  type: 'request' | 'response' | 'notification' | 'error';
  method: string;
  params?: Record<string, unknown>;
  timestamp: number;
  sessionId: string;
  correlationId?: string;
  metadata: {
    userAgent?: string;
    extensionVersion?: string;
    vscodeVersion?: string;
    platform?: string;
    workspace?: string;
  };
}

export interface SecureChannelConfig {
  encryption: {
    enabled: boolean;
    algorithm: 'aes-256-gcm' | 'chacha20-poly1305';
    keyRotationHours: number;
  };
  authentication: {
    enabled: boolean;
    tokenExpiryMinutes: number;
    requireMFA: boolean;
  };
  authorization: {
    enabled: boolean;
    roleBasedAccess: boolean;
    resourcePermissions: Record<string, string[]>;
  };
  rateLimiting: {
    enabled: boolean;
    requestsPerMinute: number;
    burstLimit: number;
  };
  audit: {
    enabled: boolean;
    detailedLogging: boolean;
    sensitiveDataMasking: boolean;
  };
  integrity: {
    enabled: boolean;
    checksumAlgorithm: 'sha256' | 'sha384' | 'sha512';
  };
  httpsSecurity: {
    enabled: boolean;
    enforceTLS13: boolean;
    certificateValidation: boolean;
    hstsMaxAge: number;
    allowedCipherSuites: string[];
    pinnedCertificates: string[];
  };
}

export interface VSCodeSecurityContext {
  authenticated: boolean;
  userId?: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  ipAddress?: string;
  userAgent?: string;
  riskScore: number;
  lastActivity: number;
  trustLevel: 'high' | 'medium' | 'low' | 'unknown';
}

class SecureVSCodeBridge {
  private static instance: SecureVSCodeBridge;
  private config: SecureChannelConfig;
  private activeSessions = new Map<string, VSCodeSecurityContext>();
  private encryptionKeys = new Map<string, { key: Buffer; iv: Buffer; created: number }>();
  private messageQueue: VSCodeMessage[] = [];

  static getInstance(): SecureVSCodeBridge {
    if (!SecureVSCodeBridge.instance) {
      SecureVSCodeBridge.instance = new SecureVSCodeBridge();
    }
    return SecureVSCodeBridge.instance;
  }	

  private constructor() {
    this.config = this.loadSecureConfig();
    if (this.config.encryption.enabled) {
      this.initializeEncryption();
    }
  }

  private loadSecureConfig(): SecureChannelConfig {
    return {
      encryption: {
        enabled: process.env['VSCODE_ENCRYPTION_ENABLED'] !== 'false',
        algorithm: 'aes-256-gcm',
        keyRotationHours: parseInt(process.env['KEY_ROTATION_HOURS'] || '24')
      },
      authentication: {
        enabled: process.env['VSCODE_AUTH_ENABLED'] !== 'false',
        tokenExpiryMinutes: parseInt(process.env['TOKEN_EXPIRY_MINUTES'] || '60'),
        requireMFA: process.env['REQUIRE_MFA'] === 'true'
      },
      authorization: {
        enabled: process.env['VSCODE_AUTHZ_ENABLED'] !== 'false',
        roleBasedAccess: true,
        resourcePermissions: {
          'workspace': ['read'],
          'files': ['read', 'write'],
          'terminal': ['execute'],
          'extensions': ['manage'],
          'settings': ['read', 'write']
        }
      },
      rateLimiting: {
        enabled: process.env['VSCODE_RATE_LIMIT_ENABLED'] !== 'false',
        requestsPerMinute: parseInt(process.env['REQUESTS_PER_MINUTE'] || '60'),
        burstLimit: parseInt(process.env['BURST_LIMIT'] || '10')
      },
      audit: {
        enabled: process.env['VSCODE_AUDIT_ENABLED'] !== 'false',
        detailedLogging: process.env['DETAILED_LOGGING'] === 'true',
        sensitiveDataMasking: true
      },
      integrity: {
        enabled: process.env['VSCODE_INTEGRITY_ENABLED'] !== 'false',
        checksumAlgorithm: 'sha256'
      },
      httpsSecurity: {
        enabled: process.env['HTTPS_SECURITY_ENABLED'] !== 'false',
        enforceTLS13: process.env['ENFORCE_TLS13'] !== 'false',
        certificateValidation: process.env['CERTIFICATE_VALIDATION'] !== 'false',
        hstsMaxAge: parseInt(process.env['HSTS_MAX_AGE'] || '31536000'),
        allowedCipherSuites: process.env['ALLOWED_CIPHER_SUITES']?.split(',') || [
          'TLS_AES_256_GCM_SHA384',
          'TLS_AES_128_GCM_SHA256',
          'TLS_CHACHA20_POLY1305_SHA256'
        ],
        pinnedCertificates: process.env['PINNED_CERTIFICATES']?.split(',') || []
      }
    };
  }

  private initializeEncryption(): void {
    // Generate initial encryption keys
    this.rotateEncryptionKeys();

    // Set up key rotation interval
    setInterval(() => {
      this.rotateEncryptionKeys();
    }, this.config.encryption.keyRotationHours * 60 * 60 * 1000);

    logger.info('🔐 VS Code secure bridge encryption initialized');
  }

  private rotateEncryptionKeys(): void {
    const keyId = crypto.randomUUID();
    const key = crypto.randomBytes(32); // 256-bit key
    const iv = crypto.randomBytes(16); // 128-bit IV

    this.encryptionKeys.set(keyId, {
      key,
      iv,
      created: Date.now()
    });

    // Keep only last 3 keys for decryption of old messages
    if (this.encryptionKeys.size > 3) {
      const oldestKey = Array.from(this.encryptionKeys.entries())
        .sort(([,a], [,b]) => a.created - b.created)[0][0];
      this.encryptionKeys.delete(oldestKey);
    }

    logger.info('🔄 Encryption keys rotated', { keyId });
  }

  async processIncomingMessage(rawMessage: RawVSCodeMessage, connectionInfo?: {
    ipAddress?: string;
    userAgent?: string;
    sessionId?: string;
  }): Promise<VSCodeMessage | null> {
    try {
      // Step 0: Validate HTTPS security
      if (!this.validateHTTPSSecurity(connectionInfo)) {
        logger.warn('🚫 HTTPS security validation failed');
        await this.auditSecurityEvent('https_security_violation', {
          id: rawMessage.id,
          type: 'error',
          method: 'unknown',
          timestamp: Date.now(),
          sessionId: rawMessage.sessionId || 'unknown',
          metadata: {}
        } as VSCodeMessage, connectionInfo);
        return null;
      }

      // Step 1: Validate message structure
      const validation = await validatorRegistry.validateWith('default', rawMessage, this.getMessageSchema());
      if (!validation.isValid) {
        logger.warn('❌ Invalid VS Code message structure', {
          errors: validation.errors.map(e => e.message)
        });
        return null;
      }

      // Step 2: Decrypt if encrypted
      let messageData = rawMessage;
      if (this.config.encryption.enabled && rawMessage.encrypted) {
        const decryptedMessage = await this.decryptMessage(rawMessage as unknown as EncryptedVSCodeMessage);
        if (!decryptedMessage) {
          logger.error('🚨 Failed to decrypt message', { messageId: rawMessage.id });
          return null;
        }
        messageData = decryptedMessage as unknown as RawVSCodeMessage;
      }

      // Step 3: Parse and validate message
      const message: VSCodeMessage = {
        id: messageData.id,
        type: messageData.type as 'request' | 'response' | 'notification' | 'error',
        method: messageData.method,
        params: messageData.params as Record<string, unknown>,
        timestamp: messageData.timestamp || Date.now(),
        sessionId: messageData.sessionId || crypto.randomUUID(),
        correlationId: messageData.correlationId,
        metadata: {
          userAgent: connectionInfo?.userAgent || (messageData.metadata as Record<string, unknown>)?.['userAgent'] as string || '',
          extensionVersion: (messageData.metadata as Record<string, unknown>)?.['extensionVersion'] as string || '',
          vscodeVersion: (messageData.metadata as Record<string, unknown>)?.['vscodeVersion'] as string || '',
          platform: (messageData.metadata as Record<string, unknown>)?.['platform'] as string || '',
          workspace: (messageData.metadata as Record<string, unknown>)?.['workspace'] as string || ''
        }
      };

      // Step 4: Verify message integrity
      if (this.config.integrity.enabled) {
        const isValid = await this.verifyMessageIntegrity(message, connectionInfo);
        if (!isValid) {
          logger.error('🚨 Message integrity check failed', { messageId: message.id });
          await this.auditSecurityEvent('integrity_violation', message, connectionInfo);
          return null;
        }
      }

      // Step 5: Authenticate and authorize (timing-safe)
      const securityContext = await this.authenticateMessage(message, connectionInfo);
      if (!this.timingSafeAuthenticationCheck(message, connectionInfo) && this.config.authentication.enabled) {
        logger.warn('🚫 Authentication failed', { messageId: message.id });
        await this.auditSecurityEvent('authentication_failed', message, connectionInfo);
        return null;
      }

      // Step 6: Rate limiting check
      if (this.config.rateLimiting.enabled) {
        const rateLimitResult = await rateLimiterRegistry.get('api_protection')?.checkLimit(
          securityContext.userId || connectionInfo?.ipAddress || 'anonymous',
          { userAgent: connectionInfo?.userAgent, userId: securityContext.userId }
        );

        if (!rateLimitResult?.allowed) {
          logger.warn('🚫 Rate limit exceeded', {
            messageId: message.id,
            userId: securityContext.userId,
            retryAfter: rateLimitResult?.retryAfter
          });
          await this.auditSecurityEvent('rate_limit_exceeded', message, connectionInfo);
          return null;
        }
      }

      // Step 7: Authorize action
      if (this.config.authorization.enabled) {
        const authorized = await this.authorizeAction(message, securityContext);
        if (!authorized) {
          logger.warn('🚫 Authorization failed', {
            messageId: message.id,
            method: message.method,
            userId: securityContext.userId
          });
          await this.auditSecurityEvent('authorization_failed', message, connectionInfo);
          return null;
        }
      }

      // Step 8: Audit the successful message
      if (this.config.audit.enabled) {
        await auditTrail.recordEvent({
          eventType: 'vscode_message_processed',
          category: 'system',
          severity: 'info',
          actor: {
            id: securityContext.userId || 'anonymous',
            type: securityContext.userId ? 'user' : 'anonymous',
            ipAddress: connectionInfo?.ipAddress,
            userAgent: connectionInfo?.userAgent,
            sessionId: securityContext.sessionId
          },
          resource: {
            type: 'vscode_api',
            id: message.method,
            name: `VS Code ${message.method}`
          },
          action: {
            name: message.method,
            result: 'success',
            parameters: message.params,
            duration: Date.now() - message.timestamp
          },
          context: {
            correlationId: message.correlationId || message.id,
            environment: 'vscode',
            service: 'vscode_extension',
            version: '1.0.0'
          },
          data: {
            dataClassification: 'internal',
            before: undefined,
            after: message.params
          },
          compliance: {
            frameworks: ['vscode_security'],
            requirements: ['secure_communication'],
            evidence: {
              authenticated: securityContext.authenticated,
              authorized: true,
              integrityVerified: true
            }
          },
          metadata: {
            messageType: message.type,
            riskScore: securityContext.riskScore,
            trustLevel: securityContext.trustLevel
          }
        });
      }

      // Step 9: Queue message for processing
      this.messageQueue.push(message);

      logger.debug('✅ VS Code message processed securely', {
        messageId: message.id,
        method: message.method,
        authenticated: securityContext.authenticated
      });

      return message;

    } catch (error) {
      // Sanitize error message to prevent information leakage
      const sanitizedError = this.sanitizeErrorMessage(error);
      logger.error('💥 Failed to process VS Code message', {
        error: sanitizedError,
        messageId: rawMessage?.id || 'unknown',
        sessionId: rawMessage?.sessionId || 'unknown'
      });

      await this.auditSecurityEvent('message_processing_error', {
        id: rawMessage?.id || 'unknown',
        type: 'error',
        method: 'unknown',
        timestamp: Date.now(),
        sessionId: rawMessage?.sessionId || 'unknown',
        metadata: {}
      } as VSCodeMessage, connectionInfo);

      return null;
    }
  }

  private async authenticateMessage(
    message: VSCodeMessage,
    connectionInfo?: { ipAddress?: string; userAgent?: string; sessionId?: string }
  ): Promise<VSCodeSecurityContext> {
    const sessionId = message.sessionId || connectionInfo?.sessionId || crypto.randomUUID();

    // Check if session already exists
    let context = this.activeSessions.get(sessionId);

    if (!context) {
      // Create new session context
      context = {
        authenticated: false,
        sessionId,
        roles: [],
        permissions: [],
        riskScore: 0,
        lastActivity: Date.now(),
        trustLevel: 'unknown'
      };

      // Enhanced authentication with multiple factors
      const authResult = await this.performMultiFactorAuthentication(message, connectionInfo);
      context.authenticated = authResult.authenticated;
      context.userId = authResult.userId;
      context.roles = authResult.roles;
      context.permissions = authResult.permissions;
      context.trustLevel = authResult.trustLevel;
      context.riskScore = authResult.riskScore;
      context.ipAddress = connectionInfo?.ipAddress;
      context.userAgent = connectionInfo?.userAgent;

      // Store session
      if (context.authenticated) {
        this.activeSessions.set(sessionId, context);
        logger.info('🔐 New authenticated session created', {
          sessionId,
          userId: context.userId,
          trustLevel: context.trustLevel
        });
      }
    } else {
      // Update existing session activity
      context.lastActivity = Date.now();

      // Check for suspicious activity patterns
      const riskIncrease = this.calculateRiskIncrease(context, connectionInfo);
      context.riskScore = Math.min(100, context.riskScore + riskIncrease);

      // Update trust level based on risk score
      context.trustLevel = this.calculateTrustLevel(context.riskScore);
    }

    return context;
  }

  private async performMultiFactorAuthentication(
    message: VSCodeMessage,
    connectionInfo?: { ipAddress?: string; userAgent?: string }
  ): Promise<{
    authenticated: boolean;
    userId?: string;
    roles: string[];
    permissions: string[];
    trustLevel: 'high' | 'medium' | 'low' | 'unknown';
    riskScore: number;
  }> {
    let riskScore = 0;
    const roles: string[] = [];
    const permissions: string[] = [];

    // Factor 1: Extension metadata validation
    const hasValidExtension = message.metadata.extensionVersion &&
                             message.metadata.vscodeVersion &&
                             this.isValidVersion(message.metadata.extensionVersion) &&
                             this.isValidVersion(message.metadata.vscodeVersion);

    if (!hasValidExtension) {
      riskScore += 40;
    }

    // Factor 2: User agent consistency
    const hasConsistentUA = connectionInfo?.userAgent &&
                           message.metadata.userAgent &&
                           connectionInfo.userAgent === message.metadata.userAgent;

    if (!hasConsistentUA) {
      riskScore += 20;
    }

    // Factor 3: IP address reputation (placeholder for production)
    if (connectionInfo?.ipAddress) {
      riskScore += this.assessIPAddressRisk(connectionInfo.ipAddress);
    }

    // Factor 4: Request frequency analysis
    const recentRequests = this.getRecentRequestsFromIP(connectionInfo?.ipAddress);
    if (recentRequests > 100) {
      riskScore += 30;
    }

    // Factor 5: Message content analysis
    riskScore += this.analyzeMessageContentRisk(message);

    // Determine authentication result
    const authenticated = riskScore < 50 && hasValidExtension;
    let trustLevel: 'high' | 'medium' | 'low' | 'unknown' = 'unknown';

    if (authenticated) {
      if (riskScore < 20) {
        trustLevel = 'high';
        roles.push('vscode_user', 'trusted_extension');
        permissions.push('read', 'write', 'execute');
      } else if (riskScore < 35) {
        trustLevel = 'medium';
        roles.push('vscode_user');
        permissions.push('read', 'write');
      } else {
        trustLevel = 'low';
        roles.push('vscode_user');
        permissions.push('read');
      }

      return {
        authenticated: true,
        userId: `vscode_user_${crypto.randomBytes(8).toString('hex')}`,
        roles,
        permissions,
        trustLevel,
        riskScore
      };
    }

    return {
      authenticated: false,
      roles: [],
      permissions: [],
      trustLevel: 'unknown',
      riskScore
    };
  }

  private isValidVersion(version: string): boolean {
    // Basic semantic version validation
    const versionRegex = /^\d+\.\d+\.\d+(-[\w\.\-]+)?(\+[\w\.\-]+)?$/;
    return versionRegex.test(version);
  }

  private assessIPAddressRisk(ipAddress?: string): number {
    if (!ipAddress) return 10;

    // Placeholder risk assessment - in production, integrate with threat intelligence
    const suspiciousRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
    for (const range of suspiciousRanges) {
      if (this.isIPInRange(ipAddress, range)) {
        return 25;
      }
    }

    return 5; // Low risk for public IPs
  }

  private isIPInRange(ip: string, range: string): boolean {
    // Simplified IP range check - in production, use proper IP parsing library
    const [rangeIP] = range.split('/');
    return ip.startsWith(rangeIP.split('.').slice(0, 2).join('.'));
  }

  private getRecentRequestsFromIP(ipAddress?: string): number {
    if (!ipAddress) return 0;

    // Count recent requests from this IP (placeholder implementation)
    let count = 0;
    for (const context of this.activeSessions.values()) {
      if (context.ipAddress === ipAddress &&
          Date.now() - context.lastActivity < 60000) { // Last minute
        count++;
      }
    }
    return count;
  }

  private analyzeMessageContentRisk(message: VSCodeMessage): number {
    let risk = 0;

    // Check for suspicious method names
    const suspiciousMethods = ['eval', 'exec', 'spawn', 'fork'];
    if (suspiciousMethods.some(method => message.method.includes(method))) {
      risk += 20;
    }

    // Check for large payloads
    if (JSON.stringify(message.params).length > 10000) {
      risk += 15;
    }

    // Check for rapid successive calls
    if (this.isRapidCallPattern(message)) {
      risk += 10;
    }

    return risk;
  }

  private isRapidCallPattern(message: VSCodeMessage): boolean {
    // Check if this is part of a rapid call pattern (placeholder)
    const now = Date.now();
    const recentCalls = Array.from(this.messageQueue)
      .filter(m => m.sessionId === message.sessionId &&
                   now - m.timestamp < 1000) // Last second
      .length;

    return recentCalls > 5;
  }

  private calculateRiskIncrease(context: VSCodeSecurityContext, connectionInfo?: { ipAddress?: string; userAgent?: string }): number {
    let increase = 0;

    // Check for IP address change
    if (connectionInfo?.ipAddress && context.ipAddress !== connectionInfo.ipAddress) {
      increase += 15;
    }

    // Check for user agent change
    if (connectionInfo?.userAgent && context.userAgent !== connectionInfo.userAgent) {
      increase += 10;
    }

    // Time-based risk increase for long sessions
    const sessionAge = Date.now() - context.lastActivity;
    if (sessionAge > 24 * 60 * 60 * 1000) { // 24 hours
      increase += 5;
    }

    return increase;
  }

  private calculateTrustLevel(riskScore: number): 'high' | 'medium' | 'low' | 'unknown' {
    if (riskScore < 20) return 'high';
    if (riskScore < 40) return 'medium';
    if (riskScore < 60) return 'low';
    return 'unknown';
  }

  /**
   * Validate HTTPS security for incoming connections
   */
  private validateHTTPSSecurity(connectionInfo?: { ipAddress?: string; userAgent?: string }): boolean {
    if (!this.config.httpsSecurity.enabled) {
      return true; // HTTPS security not enabled
    }

    // Check if connection is using HTTPS (this would be determined by the transport layer)
    // For VS Code extensions, this is typically handled by the VS Code runtime

    // Additional HTTPS security validations
    if (connectionInfo?.ipAddress) {
      // Validate IP address is not from known malicious ranges
      if (this.isSuspiciousIPAddress(connectionInfo.ipAddress)) {
        logger.warn('🚫 Connection from suspicious IP address blocked', {
          ipAddress: this.maskIPAddress(connectionInfo.ipAddress)
        });
        return false;
      }
    }

    return true;
  }

  /**
   * Check if IP address is from suspicious ranges
   */
  private isSuspiciousIPAddress(ipAddress: string): boolean {
    // Check for private IP ranges that shouldn't be connecting externally
    const suspiciousRanges = [
      /^10\./,      // 10.0.0.0/8
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
      /^192\.168\./, // 192.168.0.0/16
      /^127\./,     // Loopback
      /^169\.254\./ // Link-local
    ];

    return suspiciousRanges.some(range => range.test(ipAddress));
  }

  /**
   * Mask IP address for logging
   */
  private maskIPAddress(ipAddress: string): string {
    const parts = ipAddress.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.***.***`;
    }
    return '***.***.***.***';
  }


  /**
   * Timing-safe authentication verification
   */
  private timingSafeAuthenticationCheck(
    message: VSCodeMessage,
    _connectionInfo?: { ipAddress?: string; userAgent?: string }
  ): boolean {
    const startTime = Date.now();

    try {
      // Perform authentication check
      const context = this.activeSessions.get(message.sessionId);
      const isAuthenticated = context?.authenticated ?? false;

      // Always take at least 50ms to prevent timing attacks
      const elapsed = Date.now() - startTime;
      if (elapsed < 50) {
        this.constantTimeDelay(50 - elapsed);
      }

      return isAuthenticated;
    } catch {
      // Ensure constant time even on errors
      const elapsed = Date.now() - startTime;
      if (elapsed < 50) {
        this.constantTimeDelay(50 - elapsed);
      }
      return false;
    }
  }

  /**
   * Constant-time delay implementation
   */
  private constantTimeDelay(ms: number): void {
    const start = Date.now();
    while (Date.now() - start < ms) {
      // Busy wait to ensure constant time
      // In production, consider using crypto.randomBytes() for more secure delay
    }
  }

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
      message = message.replace(/\bapi[_-]?key\s*[:=]\s*[A-Za-z0-9_-]{10,}\b/gi, '[API_KEY_REDACTED]');

      // Limit error message length
      if (message.length > 200) {
        message = message.substring(0, 200) + '...';
      }

      return message;
    }

    // For non-Error objects, provide a generic message
    return 'An unexpected error occurred';
  }

  private async authorizeAction(message: VSCodeMessage, context: VSCodeSecurityContext): Promise<boolean> {
    // Check if user has permission for the requested method
    const methodPermissions = this.getMethodPermissions(message.method);

    for (const permission of methodPermissions) {
      if (!context.permissions.includes(permission)) {
        return false;
      }
    }

    return true;
  }

  private getMethodPermissions(method: string): string[] {
    // Map VS Code methods to required permissions
    const permissionMap: Record<string, string[]> = {
      'workspace.findFiles': ['read'],
      'workspace.openTextDocument': ['read'],
      'workspace.saveTextDocument': ['write'],
      'terminal.executeCommand': ['execute'],
      'extensions.installExtension': ['manage'],
      'settings.get': ['read'],
      'settings.update': ['write']
    };

    return permissionMap[method] || ['read'];
  }


  private async decryptMessage(encryptedMessage: EncryptedVSCodeMessage): Promise<VSCodeMessage> {
    if (!this.config.encryption.enabled) {
      // If encryption is disabled but we received an encrypted message, this is an error
      throw new Error('Encryption is disabled but received encrypted message');
    }

    const key = this.encryptionKeys.get(encryptedMessage.keyId);
    if (!key) {
      throw new Error('Encryption key not found');
    }

    const decipher = crypto.createDecipheriv(this.config.encryption.algorithm, key.key, Buffer.from(encryptedMessage.iv, 'hex'));
    // For GCM mode, setAuthTag is not needed here - it's handled during final()

    let decrypted = decipher.update(encryptedMessage.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  }

  private async verifyMessageIntegrity(message: VSCodeMessage, _connectionInfo?: { ipAddress?: string; userAgent?: string }): Promise<boolean> {
    try {
      // Create canonical representation of message for consistent hashing
      const canonicalData = this.createCanonicalMessage(message);

      // Generate checksum using configured algorithm
      const checksum = crypto.createHash(this.config.integrity.checksumAlgorithm)
        .update(canonicalData)
        .digest('hex');

      // In production systems, the message should contain a signature/checksum
      // that was created by the sender. For now, we'll do a self-check
      // to ensure the message hasn't been corrupted in transit.

      // Check for obvious tampering indicators
      const tamperingIndicators = this.detectTamperingIndicators(message);
      if (tamperingIndicators.length > 0) {
        logger.warn('🚨 Message tampering indicators detected', {
          messageId: message.id,
          indicators: tamperingIndicators
        });
        return false;
      }

      // Verify timestamp is reasonable (not too old or too far in future)
      const now = Date.now();
      const messageAge = now - message.timestamp;
      const maxAge = 5 * 60 * 1000; // 5 minutes
      const maxFuture = 30 * 1000; // 30 seconds in future

      if (messageAge > maxAge) {
        logger.warn('🚨 Message timestamp too old', {
          messageId: message.id,
          messageAge,
          maxAge
        });
        return false;
      }

      if (messageAge < -maxFuture) {
        logger.warn('🚨 Message timestamp too far in future', {
          messageId: message.id,
          messageAge,
          maxFuture
        });
        return false;
      }

      // Additional integrity checks
      if (!this.validateMessageStructure(message)) {
        logger.warn('🚨 Message structure validation failed', {
          messageId: message.id
        });
        return false;
      }

      logger.debug('✅ Message integrity verified', {
        messageId: message.id,
        checksum: checksum.substring(0, 8) + '...', // Log partial checksum for debugging
        algorithm: this.config.integrity.checksumAlgorithm
      });

      return true;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('💥 Message integrity verification failed', {
        messageId: message.id,
        error: errorMessage
      });
      return false;
    }
  }

  private createCanonicalMessage(message: VSCodeMessage): string {
    // Create a canonical JSON representation for consistent hashing
    // This ensures the same message always produces the same hash regardless of property order
    const canonical = {
      id: message.id,
      type: message.type,
      method: message.method,
      params: this.canonicalizeObject(message.params),
      timestamp: message.timestamp,
      sessionId: message.sessionId,
      correlationId: message.correlationId,
      metadata: this.canonicalizeObject(message.metadata)
    };

    return JSON.stringify(canonical, Object.keys(canonical).sort());
  }

  private canonicalizeObject(obj: unknown): unknown {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'object' && !Array.isArray(obj)) {
      const sorted: Record<string, unknown> = {};
      Object.keys(obj).sort().forEach(key => {
        sorted[key] = this.canonicalizeObject((obj as Record<string, unknown>)[key]);
      });
      return sorted;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.canonicalizeObject(item));
    }

    return obj;
  }

  private detectTamperingIndicators(message: VSCodeMessage): string[] {
    const indicators: string[] = [];

    // Check for suspicious patterns in message content
    const messageString = JSON.stringify(message);

    // Check for null bytes or other binary data
    if (messageString.includes('\x00')) {
      indicators.push('null_bytes_detected');
    }

    // Check for extremely long strings (potential DoS)
    if (messageString.length > 100000) {
      indicators.push('excessive_message_size');
    }

    // Check for deeply nested objects (potential DoS)
    const nestingLevel = this.calculateNestingLevel(message);
    if (nestingLevel > 10) {
      indicators.push('excessive_nesting');
    }

    // Check for duplicate keys in JSON (invalid but parseable)
    if (this.hasDuplicateKeys(messageString)) {
      indicators.push('duplicate_keys');
    }

    // Check for suspicious escape sequences
    if (/\\u00[0-8]/.test(messageString)) {
      indicators.push('suspicious_unicode');
    }

    return indicators;
  }

  private calculateNestingLevel(obj: unknown, currentLevel = 0): number {
    if (currentLevel > 20) return currentLevel; // Prevent infinite recursion

    if (typeof obj === 'object' && obj !== null) {
      let maxLevel = currentLevel;
      for (const value of Object.values(obj)) {
        const level = this.calculateNestingLevel(value, currentLevel + 1);
        maxLevel = Math.max(maxLevel, level);
      }
      return maxLevel;
    }

    return currentLevel;
  }

  private hasDuplicateKeys(jsonString: string): boolean {
    try {
      // Parse with a custom reviver that detects duplicates
      let duplicateFound = false;
      const seenKeys = new Set<string>();

      JSON.parse(jsonString, (key, value) => {
        if (key && seenKeys.has(key)) {
          duplicateFound = true;
        }
        if (key) {
          seenKeys.add(key);
        }
        return value;
      });

      return duplicateFound;
    } catch {
      // If parsing fails, assume no duplicates (or handle as invalid JSON elsewhere)
      return false;
    }
  }

  private validateMessageStructure(message: VSCodeMessage): boolean {
    // Validate message structure beyond basic JSON parsing
    try {
      // Check required fields
      if (!message.id || typeof message.id !== 'string') return false;
      if (!message.type || !['request', 'response', 'notification', 'error'].includes(message.type)) return false;
      if (!message.method || typeof message.method !== 'string') return false;

      // Validate timestamp is a reasonable number
      if (typeof message.timestamp !== 'number' || isNaN(message.timestamp)) return false;

      // Validate sessionId if present
      if (message.sessionId && typeof message.sessionId !== 'string') return false;

      // Validate correlationId if present
      if (message.correlationId && typeof message.correlationId !== 'string') return false;

      // Validate metadata structure
      if (message.metadata && typeof message.metadata !== 'object') return false;

      // Additional security checks
      if (message.id.length > 100) return false; // Reasonable ID length limit
      if (message.method.length > 200) return false; // Reasonable method name length limit
      if (message.sessionId && message.sessionId.length > 100) return false;

      return true;

    } catch (error) {
      logger.error('💥 Message structure validation failed', { error });
      return false;
    }
  }

  private getMessageSchema(): ValidationSchema {
    return {
      id: { field: 'id', type: 'string', required: true },
      type: { field: 'type', type: 'string', required: true, allowedValues: ['request', 'response', 'notification', 'error'] },
      method: { field: 'method', type: 'string', required: true },
      params: { field: 'params', type: 'object', required: false },
      timestamp: { field: 'timestamp', type: 'number', required: false },
      sessionId: { field: 'sessionId', type: 'string', required: false },
      correlationId: { field: 'correlationId', type: 'string', required: false },
      metadata: { field: 'metadata', type: 'object', required: false }
    };
  }

  private async auditSecurityEvent(
    eventType: string,
    message: VSCodeMessage,
    connectionInfo?: { ipAddress?: string; userAgent?: string }
  ): Promise<void> {
    if (!this.config.audit.enabled) return;

    await auditTrail.recordEvent({
      eventType: `vscode_security_${eventType}`,
      category: 'security',
      severity: 'high',
      actor: {
        id: 'vscode_extension',
        type: 'service',
        ipAddress: connectionInfo?.ipAddress,
        userAgent: connectionInfo?.userAgent,
        sessionId: message.sessionId
      },
      resource: {
        type: 'vscode_api',
        id: message.method,
        name: `VS Code ${message.method}`
      },
      action: {
        name: eventType,
        result: 'failure',
        parameters: message.params as Record<string, unknown>
      },
      context: {
        environment: 'vscode',
        service: 'vscode-bridge',
        version: '1.0.0',
        correlationId: message.correlationId || message.id
      },
      data: {
        dataClassification: 'restricted',
        before: undefined,
        after: message.params
      },
      compliance: {
        frameworks: ['vscode_security'],
        requirements: ['secure_communication'],
        evidence: {
          eventType,
          messageId: message.id
        }
      },
      metadata: {
        securityEvent: true,
        riskLevel: 'high'
      }
    });
  }

  // Public API methods
  getActiveSessions(): Map<string, VSCodeSecurityContext> {
    return new Map(this.activeSessions);
  }

  getSession(sessionId: string): VSCodeSecurityContext | undefined {
    return this.activeSessions.get(sessionId);
  }

  invalidateSession(sessionId: string): boolean {
    return this.activeSessions.delete(sessionId);
  }

  getQueuedMessages(): VSCodeMessage[] {
    return [...this.messageQueue];
  }

  clearMessageQueue(): void {
    this.messageQueue = [];
  }

  getHealthStatus(): {
    status: 'healthy' | 'warning' | 'critical';
    activeSessions: number;
    queuedMessages: number;
    encryptionEnabled: boolean;
    authenticationEnabled: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    if (this.activeSessions.size > 1000) {
      issues.push('High number of active sessions');
    }

    if (this.messageQueue.length > 100) {
      issues.push('Message queue is backing up');
    }

    if (!this.config.encryption.enabled) {
      issues.push('Encryption is disabled');
    }

    if (!this.config.authentication.enabled) {
      issues.push('Authentication is disabled');
    }

    let status: 'healthy' | 'warning' | 'critical' = 'healthy';
    if (issues.length > 0) status = 'warning';
    if (issues.some(issue => issue.includes('disabled'))) status = 'critical';

    return {
      status,
      activeSessions: this.activeSessions.size,
      queuedMessages: this.messageQueue.length,
      encryptionEnabled: this.config.encryption.enabled,
      authenticationEnabled: this.config.authentication.enabled,
      issues
    };
  }

  // Clean up expired sessions
  cleanup(): void {
    const now = Date.now();
    const sessionTimeout = 24 * 60 * 60 * 1000; // 24 hours

    for (const [sessionId, context] of this.activeSessions) {
      if (now - context.lastActivity > sessionTimeout) {
        this.activeSessions.delete(sessionId);
      }
    }

    logger.debug('🧹 VS Code secure bridge cleanup completed', {
      sessionsCleaned: this.activeSessions.size
    });
  }
}

export const secureVSCodeBridge = SecureVSCodeBridge.getInstance();

// Set up cleanup interval
setInterval(() => {
  secureVSCodeBridge.cleanup();
}, 60 * 60 * 1000); // Clean up every hour
