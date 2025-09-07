/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Advanced Data Validation and Sanitization System
import { logger } from './logger.js';

export interface ValidationRule {
  field: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'email' | 'url' | 'uuid' | 'custom';
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp;
  allowedValues?: any[];
  customValidator?: (value: any, context?: any) => boolean | Promise<boolean>;
  errorMessage?: string;
  sanitize?: boolean;
  transform?: (value: any) => any;
}

export interface ValidationSchema {
  [key: string]: ValidationRule | ValidationSchema;
}

export interface ValidationResult {
  isValid: boolean;
  errors: Array<{
    field: string;
    rule: string;
    value: any;
    message: string;
  }>;
  warnings: Array<{
    field: string;
    message: string;
  }>;
  sanitizedData?: any;
  metadata: {
    validatedAt: number;
    validationTime: number;
    fieldsValidated: number;
    rulesApplied: number;
  };
}

export interface SanitizationOptions {
  removeNulls?: boolean;
  removeEmptyStrings?: boolean;
  trimStrings?: boolean;
  escapeHtml?: boolean;
  normalizeUnicode?: boolean;
  maxDepth?: number;
  maxArrayLength?: number;
  maxObjectSize?: number;
}

export interface DataValidatorConfig {
  strictMode?: boolean;
  failFast?: boolean;
  collectAllErrors?: boolean;
  enableSanitization?: boolean;
  sanitizationOptions?: SanitizationOptions;
  customValidators?: Record<string, (value: any, context?: any) => boolean | Promise<boolean>>;
  contextAware?: boolean;
}

class DataValidator {
  private config: DataValidatorConfig;
  private customValidators: Map<string, (value: any, context?: any) => boolean | Promise<boolean>> = new Map();

  constructor(config: DataValidatorConfig = {}) {
    this.config = {
      strictMode: false,
      failFast: false,
      collectAllErrors: true,
      enableSanitization: true,
      sanitizationOptions: {
        removeNulls: true,
        removeEmptyStrings: false,
        trimStrings: true,
        escapeHtml: true,
        normalizeUnicode: true,
        maxDepth: 10,
        maxArrayLength: 1000,
        maxObjectSize: 10000
      },
      ...config
    };

    // Register built-in custom validators
    this.registerCustomValidators();
  }

  private registerCustomValidators(): void {
    // Email validation
    this.customValidators.set('email', (value: string) => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return typeof value === 'string' && emailRegex.test(value);
    });

    // URL validation
    this.customValidators.set('url', (value: string) => {
      try {
        new URL(value);
        return true;
      } catch {
        return false;
      }
    });

    // UUID validation
    this.customValidators.set('uuid', (value: string) => {
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      return typeof value === 'string' && uuidRegex.test(value);
    });

    // SQL injection detection
    this.customValidators.set('no_sql_injection', (value: string) => {
      if (typeof value !== 'string') return true;
      const sqlPatterns = [
        /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b)/i,
        /('|(\\x27)|(\\x2D\\x2D)|(\\\\)|(\\;)|(\\x3B))/i,
        /(-{2}|\/\*|\*\/)/
      ];
      return !sqlPatterns.some(pattern => pattern.test(value));
    });

    // XSS detection
    this.customValidators.set('no_xss', (value: string) => {
      if (typeof value !== 'string') return true;
      const xssPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /on\w+\s*=/gi,
        /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi
      ];
      return !xssPatterns.some(pattern => pattern.test(value));
    });

    // Path traversal detection
    this.customValidators.set('no_path_traversal', (value: string) => {
      if (typeof value !== 'string') return true;
      const traversalPatterns = [
        /\.\.[\/\\]/,
        /\.\.$/,
        /%2e%2e[\/\\]/i,
        /\.\.%2f/i,
        /\.\.%5c/i
      ];
      return !traversalPatterns.some(pattern => pattern.test(value));
    });
  }

  async validate(data: any, schema: ValidationSchema, context?: any): Promise<ValidationResult> {
    const startTime = Date.now();
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      metadata: {
        validatedAt: startTime,
        validationTime: 0,
        fieldsValidated: 0,
        rulesApplied: 0
      }
    };

    try {
      const validatedData = await this.validateObject(data, schema, '', result, context);
      result.sanitizedData = this.config.enableSanitization ?
        this.sanitizeData(validatedData, this.config.sanitizationOptions!) : validatedData;

      result.isValid = result.errors.length === 0;
      result.metadata.validationTime = Date.now() - startTime;

      if (result.errors.length > 0) {
        logger.warn('❌ Data validation failed', {
          errors: result.errors.length,
          fieldsValidated: result.metadata.fieldsValidated
        });
      } else {
        logger.debug('✅ Data validation successful', {
          fieldsValidated: result.metadata.fieldsValidated,
          rulesApplied: result.metadata.rulesApplied
        });
      }

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      result.errors.push({
        field: 'validation',
        rule: 'unexpected_error',
        value: data,
        message: `Validation failed: ${errorMessage}`
      });
      result.isValid = false;
      result.metadata.validationTime = Date.now() - startTime;

      logger.error('💥 Data validation error', { error: errorMessage });
    }

    return result;
  }

  private async validateObject(
    data: any,
    schema: ValidationSchema,
    path: string,
    result: ValidationResult,
    context?: any
  ): Promise<any> {
    if (data === null || data === undefined) {
      return data;
    }

    const validatedData: any = Array.isArray(data) ? [] : {};

    for (const [key, rule] of Object.entries(schema)) {
      const fieldPath = path ? `${path}.${key}` : key;
      result.metadata.fieldsValidated++;

      // Handle nested schemas
      if (this.isValidationSchema(rule)) {
        if (data && typeof data === 'object') {
          const nestedValue = data[key];
          if (nestedValue !== undefined) {
            validatedData[key] = await this.validateObject(nestedValue, rule, fieldPath, result, context);
          }
        }
        continue;
      }

      // Validate field
      const fieldRule = rule as ValidationRule;
      const value = data ? data[key] : undefined;

      await this.validateField(value, fieldRule, fieldPath, result, context);

      // Apply transformation if specified
      if (fieldRule.transform && value !== undefined) {
        validatedData[key] = fieldRule.transform(value);
      } else {
        validatedData[key] = value;
      }

      result.metadata.rulesApplied++;
    }

    return validatedData;
  }

  private async validateField(
    value: any,
    rule: ValidationRule,
    path: string,
    result: ValidationResult,
    context?: any
  ): Promise<void> {
    // Check required fields
    if (rule.required && (value === undefined || value === null || value === '')) {
      result.errors.push({
        field: path,
        rule: 'required',
        value,
        message: rule.errorMessage || `${path} is required`
      });

      if (!this.config.collectAllErrors && this.config.failFast) {
        return;
      }
    }

    // Skip further validation if value is missing and not required
    if (value === undefined || value === null) {
      return;
    }

    // Type validation
    if (!this.validateType(value, rule.type)) {
      result.errors.push({
        field: path,
        rule: 'type',
        value,
        message: rule.errorMessage || `${path} must be of type ${rule.type}`
      });

      if (!this.config.collectAllErrors && this.config.failFast) {
        return;
      }
    }

    // Length validation for strings and arrays
    if (rule.minLength !== undefined && this.getLength(value) < rule.minLength) {
      result.errors.push({
        field: path,
        rule: 'minLength',
        value,
        message: rule.errorMessage || `${path} must be at least ${rule.minLength} characters long`
      });
    }

    if (rule.maxLength !== undefined && this.getLength(value) > rule.maxLength) {
      result.errors.push({
        field: path,
        rule: 'maxLength',
        value,
        message: rule.errorMessage || `${path} must be at most ${rule.maxLength} characters long`
      });
    }

    // Numeric validation
    if (typeof value === 'number') {
      if (rule.min !== undefined && value < rule.min) {
        result.errors.push({
          field: path,
          rule: 'min',
          value,
          message: rule.errorMessage || `${path} must be at least ${rule.min}`
        });
      }

      if (rule.max !== undefined && value > rule.max) {
        result.errors.push({
          field: path,
          rule: 'max',
          value,
          message: rule.errorMessage || `${path} must be at most ${rule.max}`
        });
      }
    }

    // Pattern validation
    if (rule.pattern && typeof value === 'string' && !rule.pattern.test(value)) {
      result.errors.push({
        field: path,
        rule: 'pattern',
        value,
        message: rule.errorMessage || `${path} does not match required pattern`
      });
    }

    // Allowed values validation
    if (rule.allowedValues && !rule.allowedValues.includes(value)) {
      result.errors.push({
        field: path,
        rule: 'allowedValues',
        value,
        message: rule.errorMessage || `${path} must be one of: ${rule.allowedValues.join(', ')}`
      });
    }

    // Custom validation
    if (rule.customValidator) {
      try {
        const isValid = await rule.customValidator(value, context);
        if (!isValid) {
          result.errors.push({
            field: path,
            rule: 'custom',
            value,
            message: rule.errorMessage || `${path} failed custom validation`
          });
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        result.errors.push({
          field: path,
          rule: 'custom',
          value,
          message: rule.errorMessage || `${path} custom validation error: ${errorMessage}`
        });
      }
    }

    // Context-aware validation
    if (this.config.contextAware && context) {
      await this.validateContext(value, rule, path, result, context);
    }
  }

  private validateType(value: any, expectedType: ValidationRule['type']): boolean {
    switch (expectedType) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return typeof value === 'number' && !isNaN(value);
      case 'boolean':
        return typeof value === 'boolean';
      case 'array':
        return Array.isArray(value);
      case 'object':
        return typeof value === 'object' && value !== null && !Array.isArray(value);
      case 'email':
      case 'url':
      case 'uuid':
        return this.customValidators.get(expectedType)?.(value) ?? false;
      case 'custom':
        return true; // Custom validation will handle this
      default:
        return false;
    }
  }

  private getLength(value: any): number {
    if (typeof value === 'string' || Array.isArray(value)) {
      return value.length;
    }
    return 0;
  }

  private isValidationSchema(obj: any): obj is ValidationSchema {
    return obj && typeof obj === 'object' && !obj.type && !obj.field;
  }

  private async validateContext(
    value: any,
    rule: ValidationRule,
    path: string,
    result: ValidationResult,
    context: any
  ): Promise<void> {
    // Context-aware validation rules
    if (context.userRole === 'admin' && rule.type === 'string') {
      // Admins can have longer inputs
      return;
    }

    if (context.requestRate > 100 && typeof value === 'string' && value.length > 1000) {
      result.warnings.push({
        field: path,
        message: 'Large input detected during high request rate'
      });
    }

    if (context.suspiciousActivity && rule.customValidator?.name === 'no_sql_injection') {
      // Extra strict validation during suspicious activity
      result.warnings.push({
        field: path,
        message: 'Enhanced validation applied due to suspicious activity'
      });
    }
  }

  private sanitizeData(data: any, options: SanitizationOptions): any {
    if (data === null || data === undefined) {
      return options.removeNulls ? undefined : data;
    }

    if (typeof data === 'string') {
      let sanitized = data;

      if (options.trimStrings) {
        sanitized = sanitized.trim();
      }

      if (options.escapeHtml) {
        sanitized = this.escapeHtml(sanitized);
      }

      if (options.normalizeUnicode) {
        sanitized = sanitized.normalize('NFC');
      }

      if (options.removeEmptyStrings && sanitized === '') {
        return undefined;
      }

      return sanitized;
    }

    if (Array.isArray(data)) {
      const sanitized = data
        .map(item => this.sanitizeData(item, options))
        .filter(item => item !== undefined);

      if (options.maxArrayLength && sanitized.length > options.maxArrayLength) {
        logger.warn('⚠️ Array truncated due to max length', {
          originalLength: data.length,
          truncatedLength: sanitized.length,
          maxLength: options.maxArrayLength
        });
        return sanitized.slice(0, options.maxArrayLength);
      }

      return sanitized;
    }

    if (typeof data === 'object') {
      const sanitized: any = {};

      for (const [key, value] of Object.entries(data)) {
        const sanitizedValue = this.sanitizeData(value, options);
        if (sanitizedValue !== undefined) {
          sanitized[key] = sanitizedValue;
        }
      }

      // Check object size limit
      const size = JSON.stringify(sanitized).length;
      if (options.maxObjectSize && size > options.maxObjectSize) {
        logger.warn('⚠️ Object truncated due to max size', {
          size,
          maxSize: options.maxObjectSize
        });
        // In a real implementation, you might truncate large objects
      }

      return sanitized;
    }

    return data;
  }

  private escapeHtml(text: string): string {
    const htmlEscapes: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;'
    };

    return text.replace(/[&<>"'\/]/g, char => htmlEscapes[char]);
  }

  // Public API methods
  registerCustomValidator(name: string, validator: (value: any, context?: any) => boolean | Promise<boolean>): void {
    this.customValidators.set(name, validator);
    logger.info('📝 Custom validator registered', { name });
  }

  unregisterCustomValidator(name: string): boolean {
    const deleted = this.customValidators.delete(name);
    if (deleted) {
      logger.info('🗑️ Custom validator unregistered', { name });
    }
    return deleted;
  }

  getCustomValidators(): string[] {
    return Array.from(this.customValidators.keys());
  }

  updateConfig(newConfig: Partial<DataValidatorConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info('⚙️ Data validator configuration updated');
  }

  getConfig(): DataValidatorConfig {
    return { ...this.config };
  }

  // Pre-built validation schemas
  static createMCPRequestSchema(): ValidationSchema {
    return {
      method: {
        type: 'string',
        required: true,
        allowedValues: ['list_tools', 'call_tool', 'get_status'],
        sanitize: true
      },
      params: {
        type: 'object',
        required: false,
        maxLength: 10000
      },
      id: {
        type: 'string',
        required: false,
        maxLength: 100
      }
    };
  }

  static createUserInputSchema(): ValidationSchema {
    return {
      message: {
        type: 'string',
        required: true,
        minLength: 1,
        maxLength: 10000,
        customValidator: 'no_sql_injection',
        sanitize: true
      },
      context: {
        type: 'object',
        required: false,
        maxLength: 5000
      },
      metadata: {
        type: 'object',
        required: false,
        maxLength: 2000
      }
    };
  }

  static createAPIToolSchema(): ValidationSchema {
    return {
      name: {
        type: 'string',
        required: true,
        pattern: /^[a-zA-Z_][a-zA-Z0-9_]*$/,
        maxLength: 100,
        customValidator: 'no_path_traversal'
      },
      arguments: {
        type: 'object',
        required: false,
        maxLength: 10000
      },
      timeout: {
        type: 'number',
        required: false,
        min: 1000,
        max: 300000
      }
    };
  }

  static createSecurityEventSchema(): ValidationSchema {
    return {
      eventType: {
        type: 'string',
        required: true,
        maxLength: 100
      },
      severity: {
        type: 'string',
        required: true,
        allowedValues: ['low', 'medium', 'high', 'critical']
      },
      source: {
        type: 'string',
        required: true,
        maxLength: 200
      },
      message: {
        type: 'string',
        required: true,
        maxLength: 1000,
        customValidator: 'no_xss',
        sanitize: true
      },
      userId: {
        type: 'string',
        required: false,
        maxLength: 100
      },
      metadata: {
        type: 'object',
        required: false,
        maxLength: 5000
      }
    };
  }
}

// Factory functions for common validators
export function createMCPRequestValidator(): DataValidator {
  return new DataValidator({
    strictMode: true,
    enableSanitization: true,
    sanitizationOptions: {
      removeNulls: true,
      trimStrings: true,
      escapeHtml: true,
      maxDepth: 5,
      maxArrayLength: 100
    }
  });
}

export function createSecurityValidator(): DataValidator {
  return new DataValidator({
    strictMode: true,
    failFast: false,
    enableSanitization: true,
    contextAware: true,
    sanitizationOptions: {
      removeNulls: false, // Keep nulls for security analysis
      trimStrings: true,
      escapeHtml: false, // Don't escape for security analysis
      maxDepth: 10,
      maxArrayLength: 1000
    }
  });
}

export function createAPIToolValidator(): DataValidator {
  return new DataValidator({
    strictMode: false,
    enableSanitization: true,
    sanitizationOptions: {
      removeNulls: true,
      trimStrings: true,
      escapeHtml: true,
      maxDepth: 3,
      maxArrayLength: 50
    }
  });
}

// Global validator registry
export class ValidatorRegistry {
  private static instance: ValidatorRegistry;
  private validators = new Map<string, DataValidator>();

  static getInstance(): ValidatorRegistry {
    if (!ValidatorRegistry.instance) {
      ValidatorRegistry.instance = new ValidatorRegistry();
    }
    return ValidatorRegistry.instance;
  }

  register(name: string, validator: DataValidator): void {
    this.validators.set(name, validator);
    logger.info('📝 Validator registered', { name });
  }

  get(name: string): DataValidator | undefined {
    return this.validators.get(name);
  }

  getAll(): Map<string, DataValidator> {
    return new Map(this.validators);
  }

  async validateWith(name: string, data: any, schema: ValidationSchema, context?: any): Promise<ValidationResult> {
    const validator = this.validators.get(name);
    if (!validator) {
      throw new Error(`Validator '${name}' not found`);
    }

    return validator.validate(data, schema, context);
  }

  getHealthStatus(): {
    totalValidators: number;
    validatorStatuses: Record<string, { isHealthy: boolean; config: DataValidatorConfig }>;
  } {
    const validatorStatuses: Record<string, any> = {};

    for (const [name, validator] of this.validators) {
      validatorStatuses[name] = {
        isHealthy: true, // Validators are generally healthy unless misconfigured
        config: validator.getConfig()
      };
    }

    return {
      totalValidators: this.validators.size,
      validatorStatuses
    };
  }
}

export const validatorRegistry = ValidatorRegistry.getInstance();

// Initialize common validators
validatorRegistry.register('mcp_request', createMCPRequestValidator());
validatorRegistry.register('security', createSecurityValidator());
validatorRegistry.register('api_tool', createAPIToolValidator());
