/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// OAuth 2.1 Authentication and Authorization System
import * as crypto from 'crypto';
import { logger } from '../../utils/logger.js';

export interface OAuth2Config {
  clientId: string;
  clientSecret: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  redirectUri: string;
  scopes: string[];
  grantTypes: string[];
}

export interface TokenInfo {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn: number;
  expiresAt: number;
  scope: string;
  userId: string;
  clientId: string;
  roles: string[];
  permissions: string[];
}

export interface UserSession {
  sessionId: string;
  userId: string;
  clientId: string;
  roles: string[];
  permissions: string[];
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
  metadata: Record<string, unknown>;
}

export interface RBACPolicy {
  roles: Record<string, RoleDefinition>;
  permissions: Record<string, PermissionDefinition>;
  resources: Record<string, ResourceDefinition>;
}

export interface RoleDefinition {
  name: string;
  description: string;
  permissions: string[];
  inherits?: string[];
}

export interface PermissionDefinition {
  name: string;
  description: string;
  resource: string;
  actions: string[];
}

export interface ResourceDefinition {
  name: string;
  description: string;
  type: 'tool' | 'data' | 'system' | 'api';
  owner?: string;
}

class OAuth2AuthManager {
  private static instance: OAuth2AuthManager;
  private config: OAuth2Config;
  private sessions: Map<string, UserSession> = new Map();
  private tokens: Map<string, TokenInfo> = new Map();
  private rbacPolicy: RBACPolicy;
  private sessionCleanupInterval: NodeJS.Timeout;

  static getInstance(): OAuth2AuthManager {
    if (!OAuth2AuthManager.instance) {
      OAuth2AuthManager.instance = new OAuth2AuthManager();
    }
    return OAuth2AuthManager.instance;
  }

  private constructor() {
    this.config = this.loadOAuthConfig();
    this.rbacPolicy = this.loadRBACPolicy();
    this.startSessionCleanup();
  }

  private loadOAuthConfig(): OAuth2Config {
    // Load from environment variables or config file
    return {
      clientId: process.env.OAUTH_CLIENT_ID || 'gemini-mcp-client',
      clientSecret: process.env.OAUTH_CLIENT_SECRET || crypto.randomBytes(32).toString('hex'),
      authorizationEndpoint: process.env.OAUTH_AUTH_ENDPOINT || 'https://accounts.google.com/oauth/authorize',
      tokenEndpoint: process.env.OAUTH_TOKEN_ENDPOINT || 'https://oauth2.googleapis.com/token',
      redirectUri: process.env.OAUTH_REDIRECT_URI || 'http://localhost:3000/oauth/callback',
      scopes: ['openid', 'profile', 'email', 'mcp:read', 'mcp:write', 'mcp:admin'],
      grantTypes: ['authorization_code', 'refresh_token', 'client_credentials']
    };
  }

  private loadRBACPolicy(): RBACPolicy {
    // Load RBAC policy - in production, this would come from a database
    return {
      roles: {
        'admin': {
          name: 'Administrator',
          description: 'Full system access',
          permissions: ['mcp:*', 'security:*', 'analytics:*', 'collaboration:*']
        },
        'security_analyst': {
          name: 'Security Analyst',
          description: 'Security monitoring and analysis',
          permissions: ['mcp:read', 'security:read', 'analytics:read', 'reports:generate']
        },
        'developer': {
          name: 'Developer',
          description: 'Development and testing access',
          permissions: ['mcp:read', 'mcp:write', 'fuzzer:run', 'analytics:read']
        },
        'auditor': {
          name: 'Auditor',
          description: 'Compliance and audit access',
          permissions: ['mcp:read', 'compliance:read', 'reports:read', 'audit:read']
        }
      },
      permissions: {
        'mcp:read': {
          name: 'MCP Read',
          description: 'Read access to MCP tools',
          resource: 'mcp',
          actions: ['read', 'list']
        },
        'mcp:write': {
          name: 'MCP Write',
          description: 'Write access to MCP tools',
          resource: 'mcp',
          actions: ['write', 'execute', 'modify']
        },
        'security:read': {
          name: 'Security Read',
          description: 'Read security data and metrics',
          resource: 'security',
          actions: ['read', 'view']
        },
        'analytics:read': {
          name: 'Analytics Read',
          description: 'Read analytics and reports',
          resource: 'analytics',
          actions: ['read', 'view']
        }
      },
      resources: {
        'mcp': {
          name: 'MCP Server',
          description: 'Main MCP server functionality',
          type: 'system'
        },
        'security': {
          name: 'Security System',
          description: 'Security monitoring and controls',
          type: 'system'
        },
        'analytics': {
          name: 'Analytics',
          description: 'Reporting and analytics',
          type: 'data'
        }
      }
    };
  }

  async authenticate(code: string, state?: string): Promise<TokenInfo> {
    try {
      logger.info('🔐 Starting OAuth2 authentication', { hasState: !!state });

      // Exchange authorization code for tokens
      const tokenResponse = await this.exchangeCodeForTokens(code);

      // Validate and decode token
      const tokenInfo = await this.validateAndDecodeToken(tokenResponse.access_token);

      // Create session
      const session = this.createSession(tokenInfo);

      // Store tokens
      this.tokens.set(tokenResponse.access_token, {
        ...tokenInfo,
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        tokenType: tokenResponse.token_type,
        expiresIn: tokenResponse.expires_in,
        expiresAt: Date.now() + (tokenResponse.expires_in * 1000)
      });

      logger.info('✅ OAuth2 authentication successful', {
        userId: tokenInfo.userId,
        sessionId: session.sessionId,
        roles: tokenInfo.roles.length
      });

      return this.tokens.get(tokenResponse.access_token)!;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ OAuth2 authentication failed', { error: errorMessage });
      throw new Error(`Authentication failed: ${errorMessage}`);
    }
  }

  private async exchangeCodeForTokens(code: string): Promise<any> {
    // In production, this would make an actual HTTP request to the OAuth provider
    // For now, simulate the token exchange
    return {
      access_token: crypto.randomBytes(32).toString('hex'),
      refresh_token: crypto.randomBytes(32).toString('hex'),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: this.config.scopes.join(' ')
    };
  }

  private async validateAndDecodeToken(token: string): Promise<Omit<TokenInfo, 'accessToken' | 'refreshToken' | 'tokenType' | 'expiresIn' | 'expiresAt'>> {
    // In production, this would validate the JWT token and extract claims
    // For now, simulate token validation
    return {
      scope: this.config.scopes.join(' '),
      userId: `user_${crypto.randomBytes(8).toString('hex')}`,
      clientId: this.config.clientId,
      roles: ['developer'], // Default role
      permissions: ['mcp:read', 'mcp:write']
    };
  }

  private createSession(tokenInfo: any): UserSession {
    const session: UserSession = {
      sessionId: crypto.randomBytes(16).toString('hex'),
      userId: tokenInfo.userId,
      clientId: tokenInfo.clientId,
      roles: tokenInfo.roles,
      permissions: tokenInfo.permissions,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      expiresAt: Date.now() + (3600 * 1000), // 1 hour
      metadata: {}
    };

    this.sessions.set(session.sessionId, session);
    return session;
  }

  async authorize(accessToken: string, resource: string, action: string): Promise<boolean> {
    try {
      // Validate token
      const tokenInfo = this.tokens.get(accessToken);
      if (!tokenInfo) {
        logger.warn('🚫 Invalid or expired token', { tokenPrefix: accessToken.substring(0, 8) });
        return false;
      }

      // Check token expiration
      if (Date.now() > tokenInfo.expiresAt) {
        logger.warn('⏰ Token expired', { userId: tokenInfo.userId });
        this.tokens.delete(accessToken);
        return false;
      }

      // Check permissions
      const hasPermission = this.checkPermissions(tokenInfo.permissions, resource, action);

      if (!hasPermission) {
        logger.warn('🚫 Permission denied', {
          userId: tokenInfo.userId,
          resource,
          action,
          permissions: tokenInfo.permissions
        });
      }

      // Update session activity
      const session = Array.from(this.sessions.values()).find(s => s.userId === tokenInfo.userId);
      if (session) {
        session.lastActivity = Date.now();
      }

      return hasPermission;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Authorization failed', { error: errorMessage });
      return false;
    }
  }

  private checkPermissions(userPermissions: string[], resource: string, action: string): boolean {
    // Check if user has the specific permission
    const requiredPermission = `${resource}:${action}`;

    // Check exact match
    if (userPermissions.includes(requiredPermission)) {
      return true;
    }

    // Check wildcard permissions
    if (userPermissions.includes(`${resource}:*`) || userPermissions.includes('*:*')) {
      return true;
    }

    // Check role-based permissions
    for (const permission of userPermissions) {
      if (permission.endsWith(':*')) {
        const resourcePrefix = permission.split(':')[0];
        if (resource.startsWith(resourcePrefix)) {
          return true;
        }
      }
    }

    return false;
  }

  getAuthorizationUrl(state?: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      state: state || crypto.randomBytes(16).toString('hex')
    });

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  async refreshToken(refreshToken: string): Promise<TokenInfo> {
    try {
      logger.info('🔄 Refreshing OAuth2 token');

      // Find the original token info
      const originalToken = Array.from(this.tokens.values()).find(t => t.refreshToken === refreshToken);
      if (!originalToken) {
        throw new Error('Invalid refresh token');
      }

      // Generate new tokens
      const newTokenInfo = await this.exchangeCodeForTokens('refresh');

      // Update stored tokens
      const updatedToken: TokenInfo = {
        ...originalToken,
        accessToken: newTokenInfo.access_token,
        refreshToken: newTokenInfo.refresh_token,
        expiresAt: Date.now() + (newTokenInfo.expires_in * 1000)
      };

      this.tokens.set(newTokenInfo.access_token, updatedToken);
      this.tokens.delete(originalToken.accessToken);

      logger.info('✅ Token refreshed successfully', { userId: updatedToken.userId });

      return updatedToken;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Token refresh failed', { error: errorMessage });
      throw new Error(`Token refresh failed: ${errorMessage}`);
    }
  }

  revokeToken(accessToken: string): boolean {
    const tokenInfo = this.tokens.get(accessToken);
    if (tokenInfo) {
      // Find and update session
      const session = Array.from(this.sessions.values()).find(s => s.userId === tokenInfo.userId);
      if (session) {
        session.expiresAt = Date.now(); // Expire session immediately
      }

      this.tokens.delete(accessToken);
      logger.info('🚪 Token revoked', { userId: tokenInfo.userId });
      return true;
    }
    return false;
  }

  getUserSession(sessionId: string): UserSession | null {
    return this.sessions.get(sessionId) || null;
  }

  getActiveSessions(): UserSession[] {
    const now = Date.now();
    return Array.from(this.sessions.values()).filter(session => session.expiresAt > now);
  }

  getRBACPolicy(): RBACPolicy {
    return { ...this.rbacPolicy };
  }

  updateUserRoles(userId: string, roles: string[]): boolean {
    // Find user's session
    const session = Array.from(this.sessions.values()).find(s => s.userId === userId);
    if (session) {
      session.roles = roles;

      // Update permissions based on new roles
      const permissions = this.calculatePermissionsFromRoles(roles);
      session.permissions = permissions;

      // Update corresponding tokens
      const userTokens = Array.from(this.tokens.values()).filter(t => t.userId === userId);
      userTokens.forEach(token => {
        token.roles = roles;
        token.permissions = permissions;
      });

      logger.info('👥 User roles updated', { userId, roles, permissionsCount: permissions.length });
      return true;
    }
    return false;
  }

  private calculatePermissionsFromRoles(roles: string[]): string[] {
    const permissions = new Set<string>();

    for (const roleName of roles) {
      const role = this.rbacPolicy.roles[roleName];
      if (role) {
        // Add direct permissions
        role.permissions.forEach(perm => permissions.add(perm));

        // Add inherited permissions
        if (role.inherits) {
          for (const inheritedRole of role.inherits) {
            const inherited = this.rbacPolicy.roles[inheritedRole];
            if (inherited) {
              inherited.permissions.forEach(perm => permissions.add(perm));
            }
          }
        }
      }
    }

    return Array.from(permissions);
  }

  private startSessionCleanup(): void {
    this.sessionCleanupInterval = setInterval(() => {
      this.cleanupExpiredSessions();
    }, 60000); // Clean up every minute
  }

  private cleanupExpiredSessions(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [sessionId, session] of this.sessions) {
      if (session.expiresAt <= now) {
        this.sessions.delete(sessionId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.info('🧹 Cleaned up expired sessions', { count: cleanedCount });
    }
  }

  // Admin methods for RBAC management
  addRole(role: RoleDefinition): boolean {
    if (this.rbacPolicy.roles[role.name]) {
      return false; // Role already exists
    }

    this.rbacPolicy.roles[role.name] = role;
    logger.info('➕ Role added to RBAC policy', { roleName: role.name });
    return true;
  }

  updateRole(roleName: string, updates: Partial<RoleDefinition>): boolean {
    if (!this.rbacPolicy.roles[roleName]) {
      return false; // Role doesn't exist
    }

    this.rbacPolicy.roles[roleName] = { ...this.rbacPolicy.roles[roleName], ...updates };
    logger.info('📝 Role updated in RBAC policy', { roleName });
    return true;
  }

  removeRole(roleName: string): boolean {
    if (!this.rbacPolicy.roles[roleName]) {
      return false; // Role doesn't exist
    }

    delete this.rbacPolicy.roles[roleName];
    logger.info('➖ Role removed from RBAC policy', { roleName });
    return true;
  }

  // Security audit methods
  getSecurityAuditLog(): Array<{
    timestamp: number;
    event: string;
    userId: string;
    resource: string;
    action: string;
    result: 'success' | 'failure';
    details?: Record<string, unknown>;
  }> {
    // This would integrate with a proper audit logging system
    // For now, return a sample audit log
    return [
      {
        timestamp: Date.now() - 3600000,
        event: 'authentication',
        userId: 'user_123',
        resource: 'mcp',
        action: 'login',
        result: 'success'
      },
      {
        timestamp: Date.now() - 1800000,
        event: 'authorization',
        userId: 'user_123',
        resource: 'security',
        action: 'read',
        result: 'success'
      }
    ];
  }
}

export const oauth2Manager = OAuth2AuthManager.getInstance();
