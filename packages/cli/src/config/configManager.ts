/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Advanced Configuration Management System with Validation and Hot-Reloading
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import { logger } from '../utils/logger.js';
import { validatorRegistry } from '../utils/dataValidator.js';
import type { ValidationSchema } from '../utils/dataValidator.js';

export interface ConfigValidationRule {
  path: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required?: boolean;
  default?: unknown;
  min?: number;
  max?: number;
  pattern?: RegExp;
  allowedValues?: unknown[];
  customValidator?: (value: unknown) => boolean;
  description?: string;
}

export interface ConfigSchema {
  [key: string]: ConfigValidationRule | ConfigSchema;
}

export interface ConfigSource {
  name: string;
  type: 'file' | 'environment' | 'database' | 'remote' | 'vault';
  path?: string;
  url?: string;
  priority: number;
  enabled: boolean;
  cache: {
    enabled: boolean;
    ttl: number;
  };
  secrets?: {
    encryption: boolean;
    keySource: 'environment' | 'file' | 'kms';
    keyPath?: string;
  };
}

export interface ConfigEnvironment {
  name: string;
  description: string;
  extends?: string; // Parent environment to inherit from
  variables: Record<string, unknown>;
  overrides: Record<string, unknown>;
  secrets: Record<string, string>; // References to secret values
}

export interface ConfigProfile {
  name: string;
  description: string;
  environments: string[];
  schema: ConfigSchema;
  validation: {
    enabled: boolean;
    strict: boolean;
    failOnMissing: boolean;
  };
  hotReload: {
    enabled: boolean;
    watchPaths: string[];
    debounceMs: number;
  };
}

export interface ConfigManagerOptions {
  profile: string;
  environment: string;
  sources: ConfigSource[];
  profiles: Record<string, ConfigProfile>;
  environments: Record<string, ConfigEnvironment>;
  globalValidationRules: ConfigValidationRule[];
  hotReloadEnabled: boolean;
  configCacheEnabled: boolean;
  secretManagement: {
    enabled: boolean;
    provider: 'vault' | 'aws-secrets' | 'gcp-secrets' | 'azure-keyvault';
    endpoint?: string;
    tokenPath?: string;
  };
}

export interface ConfigChangeEvent {
  path: string;
  oldValue: unknown;
  newValue: unknown;
  source: string;
  timestamp: number;
  environment: string;
}

export interface ConfigValidationResult {
  isValid: boolean;
  errors: Array<{
    path: string;
    rule: string;
    value: unknown;
    expected: string;
    message: string;
  }>;
  warnings: Array<{
    path: string;
    message: string;
  }>;
}

class ConfigManager extends EventEmitter {
  private static instance: ConfigManager;
  private options: ConfigManagerOptions;
  private currentConfig: Record<string, unknown> = {};
  private configCache: Map<string, { value: unknown; timestamp: number; hash: string }> = new Map();
  private fileWatchers: Map<string, fs.FSWatcher> = new Map();
  private fileWatcherTimeouts: Map<string, NodeJS.Timeout> = new Map();
  private validationResults: ConfigValidationResult | null = null;
  private configHash: string = '';
  private isInitialized = false;

  static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  private constructor() {
    super();
    this.options = this.loadConfigManagerOptions();
    this.initializeConfigManager();
  }

  private loadConfigManagerOptions(): ConfigManagerOptions {
    // Load basic configuration for the config manager itself
    const configPath = path.join(process.cwd(), 'config-manager.json');

    if (fs.existsSync(configPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        return { ...this.getDefaultOptions(), ...data };
      } catch (error) {
        logger.warn('⚠️ Failed to load config manager options, using defaults', { error: error instanceof Error ? error.message : String(error) });
      }
    }

    return this.getDefaultOptions();
  }

  private getDefaultOptions(): ConfigManagerOptions {
    return {
      profile: process.env['CONFIG_PROFILE'] || 'default',
      environment: process.env['NODE_ENV'] || 'development',
      sources: [
        {
          name: 'environment',
          type: 'environment',
          priority: 1,
          enabled: true,
          cache: { enabled: true, ttl: 300000 }
        },
        {
          name: 'config-file',
          type: 'file',
          path: path.join(process.cwd(), 'config'),
          priority: 2,
          enabled: true,
          cache: { enabled: true, ttl: 60000 }
        },
        {
          name: 'secrets',
          type: 'vault',
          priority: 3,
          enabled: process.env['VAULT_ENABLED'] === 'true',
          cache: { enabled: true, ttl: 300000 },
          secrets: {
            encryption: true,
            keySource: 'environment'
          }
        }
      ],
      profiles: {
        default: {
          name: 'Default Profile',
          description: 'Default configuration profile',
          environments: ['development', 'staging', 'production'],
          schema: {},
          validation: {
            enabled: true,
            strict: false,
            failOnMissing: false
          },
          hotReload: {
            enabled: true,
            watchPaths: ['config/**/*.json', 'config/**/*.yaml', 'config/**/*.yml'],
            debounceMs: 1000
          }
        }
      },
      environments: {
        development: {
          name: 'Development',
          description: 'Development environment',
          variables: {},
          overrides: {},
          secrets: {}
        },
        staging: {
          name: 'Staging',
          description: 'Staging environment',
          variables: {},
          overrides: {},
          secrets: {}
        },
        production: {
          name: 'Production',
          description: 'Production environment',
          variables: {},
          overrides: {},
          secrets: {}
        }
      },
      globalValidationRules: [],
    hotReloadEnabled: process.env['CONFIG_HOT_RELOAD'] !== 'false',
      configCacheEnabled: process.env['CONFIG_CACHE_ENABLED'] !== 'false',
      secretManagement: {
        enabled: process.env['SECRETS_ENABLED'] === 'true',
        provider: (process.env['SECRETS_PROVIDER'] as unknown as 'vault' | 'aws-secrets' | 'gcp-secrets' | 'azure-keyvault') || 'vault',
        endpoint: process.env['SECRETS_ENDPOINT'],
        tokenPath: process.env['VAULT_TOKEN_PATH']
      }
    };
  }

  private async initializeConfigManager(): Promise<void> {
    try {
      await this.loadConfiguration();
      await this.validateConfiguration();

      if (this.options.hotReloadEnabled) {
        this.setupHotReload();
      }

      this.isInitialized = true;
      logger.info('⚙️ Configuration manager initialized', {
        profile: this.options.profile,
        environment: this.options.environment,
        sources: this.options.sources.length
      });

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Configuration manager initialization failed', { error: errorMessage });
      throw error;
    }
  }

  private async loadConfiguration(): Promise<void> {
    const sources = [...this.options.sources]
      .filter(source => source.enabled)
      .sort((a, b) => a.priority - b.priority);

    const configLayers: Record<string, unknown>[] = [];

    for (const source of sources) {
      try {
        const layer = await this.loadFromSource(source);
        if (layer) {
          configLayers.push(layer);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.warn(`⚠️ Failed to load from source ${source.name}`, { error: errorMessage });
      }
    }

    // Merge configuration layers
    this.currentConfig = this.deepMerge({}, ...configLayers);

    // Apply environment-specific overrides
    const environment = this.options.environments[this.options.environment];
    if (environment) {
      this.currentConfig = this.deepMerge(this.currentConfig, environment.overrides);
    }

    // Load secrets if enabled
    if (this.options.secretManagement.enabled) {
      await this.loadSecrets();
    }

    // Generate configuration hash for change detection
    this.configHash = this.generateConfigHash(this.currentConfig);
  }

  private async loadFromSource(source: ConfigSource): Promise<Record<string, unknown> | null> {
    // Check cache first
    if (source.cache.enabled && this.options.configCacheEnabled) {
      const cacheKey = `source_${source.name}`;
    const cached = this.configCache.get(cacheKey) as { value: Record<string, unknown>; timestamp: number; hash: string } | undefined;

      if (cached && Date.now() - cached.timestamp < source.cache.ttl) {
        return cached.value;
      }
    }

    let config: Record<string, unknown> | null = null;

    switch (source.type) {
      case 'environment':
        config = this.loadFromEnvironment();
        break;

      case 'file':
        config = await this.loadFromFile(source);
        break;

      case 'database':
        config = await this.loadFromDatabase(source);
        break;

      case 'remote':
        config = await this.loadFromRemote(source);
        break;

      case 'vault':
        config = await this.loadFromVault(source);
        break;
    }

    // Cache the result
    if (config && source.cache.enabled && this.options.configCacheEnabled) {
      const cacheKey = `source_${source.name}`;
      this.configCache.set(cacheKey, {
        value: config,
        timestamp: Date.now(),
        hash: this.generateConfigHash(config)
      });
    }

    return config;
  }

  private loadFromEnvironment(): Record<string, unknown> {
    const config: Record<string, unknown> = {};
    const prefix = 'CONFIG_';

    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith(prefix)) {
        const configKey = key.slice(prefix.length).toLowerCase().replace(/_/g, '.');
        this.setNestedValue(config, configKey, this.parseValue(value));
      }
    }

    return config;
  }

  private async loadFromFile(source: ConfigSource): Promise<Record<string, unknown> | null> {
    if (!source.path) return null;

    const configDir = source.path;
    const config: Record<string, unknown> = {};

    // Load all config files in the directory
    const files = fs.readdirSync(configDir)
      .filter(file => file.endsWith('.json') || file.endsWith('.yaml') || file.endsWith('.yml'))
      .sort(); // Sort for consistent loading order

    for (const file of files) {
      const filePath = path.join(configDir, file);
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const parsed = this.parseConfigFile(content, path.extname(file));
        Object.assign(config, parsed);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.warn(`⚠️ Failed to load config file ${file}`, { error: errorMessage });
      }
    }

    return config;
  }

  private parseConfigFile(content: string, extension: string): Record<string, unknown> {
    switch (extension) {
      case '.json':
        return JSON.parse(content);

      case '.yaml':
      case '.yml':
        // Would use a YAML parser in production
        return JSON.parse(content);

      default:
        return JSON.parse(content);
    }
  }

  private async loadFromDatabase(source: ConfigSource): Promise<Record<string, unknown> | null> {
    // Implementation would connect to database and load config
    logger.debug('💾 Loading config from database', { source: source.name });
    return {};
  }

private async loadFromRemote(source: ConfigSource): Promise<Record<string, unknown> | null> {
    // Implementation would fetch config from remote URL
    logger.debug('🌐 Loading config from remote', { source: source.name });
    return {};
  }

  private async loadFromVault(source: ConfigSource): Promise<Record<string, unknown> | null> {
    // Implementation would connect to HashiCorp Vault or similar
    logger.debug('🔐 Loading config from vault', { source: source.name });
    return {};
  }

  private async loadSecrets(): Promise<void> {
    const environment = this.options.environments[this.options.environment];
    if (!environment?.secrets) return;

    for (const [key, secretRef] of Object.entries(environment.secrets)) {
      try {
        const secretValue = await this.resolveSecret(secretRef);
        this.setNestedValue(this.currentConfig, key, secretValue);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error(`❌ Failed to load secret ${key}`, { error: errorMessage });
      }
    }
  }

  private async resolveSecret(secretRef: string): Promise<string> {
    // Implementation would resolve secrets from the configured provider
    logger.debug('🔑 Resolving secret', { ref: secretRef });
    return `resolved_${secretRef}`;
  }

  private parseValue(value: string | undefined): unknown {
    if (!value) return value;

    // Try to parse as JSON first
    try {
      return JSON.parse(value);
    } catch {
      // Not JSON, return as string
      return value;
    }
  }

  private setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
    const keys = path.split('.');
    let current = obj;

    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current) || typeof current[key] !== 'object') {
        current[key] = {};
      }
      current = current[key] as Record<string, unknown>;
    }

    current[keys[keys.length - 1]] = value;
  }

  private deepMerge(target: Record<string, unknown>, ...sources: Record<string, unknown>[]): Record<string, unknown> {
    const result = { ...target };

    for (const source of sources) {
      for (const [key, value] of Object.entries(source)) {
        if (this.isObject(value) && this.isObject(result[key])) {
          result[key] = this.deepMerge(result[key] as Record<string, unknown>, value as Record<string, unknown>);
        } else {
          result[key] = value;
        }
      }
    }

    return result;
  }

  private isObject(value: unknown): boolean {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  private generateConfigHash(config: Record<string, unknown>): string {
    const data = JSON.stringify(config, Object.keys(config).sort());
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private async validateConfiguration(): Promise<void> {
    const profile = this.options.profiles[this.options.profile];
    if (!profile?.validation.enabled) return;

    const result = await validatorRegistry.validateWith('default', this.currentConfig, profile.schema as unknown as ValidationSchema);

    this.validationResults = {
      isValid: result.isValid,
      errors: result.errors.map(error => ({
        path: error.field,
        rule: error.rule,
        value: error.value,
        expected: 'validation schema',
        message: error.message
      })),
      warnings: result.warnings.map(warning => ({
        path: warning.field,
        message: warning.message
      }))
    };

    if (!result.isValid && profile.validation.failOnMissing) {
      const errorMessage = `Configuration validation failed: ${this.validationResults.errors.length} errors`;
      logger.error('❌ Configuration validation failed', {
        errors: this.validationResults.errors.length,
        warnings: this.validationResults.warnings.length
      });
      throw new Error(errorMessage);
    }
  }

  private setupHotReload(): void {
    const profile = this.options.profiles[this.options.profile];
    if (!profile?.hotReload.enabled) return;

    for (const watchPath of profile.hotReload.watchPaths) {
      const watcher = fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
        if (eventType === 'change' && filename) {
          this.handleFileChange(filename);
        }
      });

      this.fileWatchers.set(watchPath, watcher);
    }

    logger.info('🔄 Hot reload enabled', {
      watchPaths: profile.hotReload.watchPaths.length
    });
  }

  private handleFileChange(filename: string | null): void {
    if (!filename) return;

    // Debounce file changes
    const profile = this.options.profiles[this.options.profile];
    if (!profile) return;

    // Clear existing timeout for this file
    const existingWatcher = this.fileWatcherTimeouts.get(filename) as unknown as NodeJS.Timeout;
    if (existingWatcher) {
      clearTimeout(existingWatcher);
    }

    const timeout = setTimeout(async () => {
      try {
        const oldConfig = { ...this.currentConfig };
        await this.loadConfiguration();
        await this.validateConfiguration();

        const newHash = this.generateConfigHash(this.currentConfig);

        if (newHash !== this.configHash) {
          this.configHash = newHash;
          this.emitConfigurationChange(oldConfig, this.currentConfig, filename);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('❌ Hot reload failed', { filename, error: errorMessage });
      }
    }, profile.hotReload.debounceMs);

    // Store timeout reference
    this.fileWatcherTimeouts.set(filename, timeout);
  }

  private emitConfigurationChange(
    oldConfig: Record<string, unknown>,
    newConfig: Record<string, unknown>,
    source: string
  ): void {
    const changes: ConfigChangeEvent[] = [];

    // Find changed values
    this.findChanges(oldConfig, newConfig, '', changes, source);

    for (const change of changes) {
      this.emit('config_changed', change);
    }

    if (changes.length > 0) {
      logger.info('🔄 Configuration reloaded', {
        changes: changes.length,
        source
      });
    }
  }

  private findChanges(
    oldObj: unknown,
    newObj: unknown,
    path: string,
    changes: ConfigChangeEvent[],
    source: string
  ): void {
    if (oldObj === newObj) return;

    if (this.isObject(oldObj) && this.isObject(newObj)) {
      const allKeys = new Set([...Object.keys(oldObj as Record<string, unknown>), ...Object.keys(newObj as Record<string, unknown>)]);

      for (const key of allKeys) {
        const newPath = path ? `${path}.${key}` : key;
        this.findChanges((oldObj as Record<string, unknown>)[key], (newObj as Record<string, unknown>)[key], newPath, changes, source);
      }
    } else if (Array.isArray(oldObj) && Array.isArray(newObj)) {
      // Handle array changes
      if (JSON.stringify(oldObj) !== JSON.stringify(newObj)) {
        changes.push({
          path,
          oldValue: oldObj as unknown,
          newValue: newObj as unknown,
          source,
          timestamp: Date.now(),
          environment: this.options.environment
        });
      }
    } else if (oldObj !== newObj) {
      changes.push({
        path,
        oldValue: oldObj as unknown,
        newValue: newObj as unknown,
        source,
        timestamp: Date.now(),
        environment: this.options.environment
      });
    }
  }

  // Public API methods
  get<T = unknown>(path: string, defaultValue?: T): T {
    return this.getNestedValue(this.currentConfig, path, defaultValue) as T;
  }

set(path: string, value: unknown): void {
    const oldValue = this.get(path);
    this.setNestedValue(this.currentConfig, path, value);

    this.emit('config_changed', {
      path,
      oldValue,
      newValue: value,
      source: 'api',
      timestamp: Date.now(),
      environment: this.options.environment
    });

    logger.debug('⚙️ Configuration value set', { path });
  }

  has(path: string): boolean {
    try {
      this.getNestedValue(this.currentConfig, path);
      return true;
    } catch {
      return false;
    }
  }

  getAll(): Record<string, unknown> {
    return { ...this.currentConfig };
  }

  getValidationResults(): ConfigValidationResult | null {
    return this.validationResults;
  }

  async reload(): Promise<void> {
    logger.info('🔄 Reloading configuration');
    await this.loadConfiguration();
    await this.validateConfiguration();
  }

  getEnvironment(): string {
    return this.options.environment;
  }

  getProfile(): string {
    return this.options.profile;
  }

  setEnvironment(environment: string): void {
    if (!this.options.environments[environment]) {
      throw new Error(`Environment '${environment}' not found`);
    }

    this.options.environment = environment;
    logger.info('🌍 Environment changed', { environment });
  }

  setProfile(profile: string): void {
    if (!this.options.profiles[profile]) {
      throw new Error(`Profile '${profile}' not found`);
    }

    this.options.profile = profile;
    logger.info('📋 Profile changed', { profile });
  }

  getNestedValue(obj: Record<string, unknown>, path: string, defaultValue?: unknown): unknown {
    const keys = path.split('.');
    let current = obj;

    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key] as Record<string, unknown>;
      } else {
        return defaultValue;
      }
    }

    return current;
  }

  onConfigChange(callback: (change: ConfigChangeEvent) => void): void {
    this.on('config_changed', callback);
  }

  getHealthStatus(): {
    status: 'healthy' | 'warning' | 'error';
    environment: string;
    profile: string;
    validationErrors: number;
    cacheSize: number;
    watchersActive: number;
    lastReload: number;
    issues: string[];
  } {
    const issues: string[] = [];
    let status: 'healthy' | 'warning' | 'error' = 'healthy';

    if (this.validationResults && !this.validationResults.isValid) {
      issues.push(`${this.validationResults.errors.length} validation errors`);
      status = 'warning';
    }

    if (!this.isInitialized) {
      issues.push('Configuration manager not initialized');
      status = 'error';
    }

    return {
      status,
      environment: this.options.environment,
      profile: this.options.profile,
      validationErrors: this.validationResults?.errors.length || 0,
      cacheSize: this.configCache.size,
      watchersActive: this.fileWatchers.size,
      lastReload: Date.now(), // Would track actual last reload
      issues
    };
  }

  async exportConfig(format: 'json' | 'yaml' = 'json'): Promise<string> {
    const config = {
      manager: this.options,
      current: this.currentConfig,
      validation: this.validationResults,
      metadata: {
        exportedAt: new Date().toISOString(),
        environment: this.options.environment,
        profile: this.options.profile,
        hash: this.configHash
      }
    };

    if (format === 'yaml') {
      // Would convert to YAML in production
      return JSON.stringify(config, null, 2);
    }

    return JSON.stringify(config, null, 2);
  }

  async importConfig(configData: string, format: 'json' | 'yaml' = 'json'): Promise<void> {
    let parsed: Record<string, unknown> | null = null;

    if (format === 'yaml') {
      // Would parse YAML in production
      parsed = JSON.parse(configData) as Record<string, unknown>;
    } else {
      parsed = JSON.parse(configData) as Record<string, unknown>	;
    }

    if (parsed && typeof parsed === 'object' && 'current' in parsed && parsed['current']) {
      this.currentConfig = parsed['current'] as Record<string, unknown>;
      await this.validateConfiguration();
      logger.info('📥 Configuration imported', { format });
    }
  }

  async shutdown(): Promise<void> {
    // Clean up file watcher timeouts
    for (const timeout of this.fileWatcherTimeouts.values()) {
      clearTimeout(timeout);
    }
    this.fileWatcherTimeouts.clear();

    // Clean up file watchers
    for (const watcher of this.fileWatchers.values()) {
      watcher.close();
    }
    this.fileWatchers.clear();

    // Clear cache
    this.configCache.clear();

    logger.info('🛑 Configuration manager shutdown');
  }
}

export const configManager = ConfigManager.getInstance();
