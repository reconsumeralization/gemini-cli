/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Automated Penetration Testing and Security Audit System
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../../utils/logger.js';
import { intelligentClassifier } from '../ml-training/intelligentClassifier.js';

export interface PenetrationTestConfig {
  enabled: boolean;
  testTypes: PenetrationTestType[];
  scope: TestScope;
  schedule: TestSchedule;
  intensity: 'low' | 'medium' | 'high' | 'aggressive';
  maxConcurrentTests: number;
  timeout: number;
  reporting: ReportingConfig;
}

export interface PenetrationTestType {
  name: string;
  description: string;
  enabled: boolean;
  category: 'injection' | 'authentication' | 'authorization' | 'data_exposure' | 'configuration' | 'api' | 'fuzzing';
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  estimatedDuration: number; // minutes
}

export interface TestScope {
  includeEndpoints: string[];
  excludeEndpoints: string[];
  includeParameters: string[];
  excludeParameters: string[];
  maxDepth: number;
  followRedirects: boolean;
}

export interface TestSchedule {
  enabled: boolean;
  frequency: 'daily' | 'weekly' | 'monthly' | 'custom';
  customCron?: string;
  timeWindow: {
    start: string; // HH:MM format
    end: string; // HH:MM format
  };
}

export interface ReportingConfig {
  format: 'json' | 'html' | 'pdf' | 'xml';
  includeDetails: boolean;
  includeRemediation: boolean;
  notifyOnCompletion: boolean;
  retentionDays: number;
}

export interface PenetrationTest {
  id: string;
  name: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  type: PenetrationTestType;
  scope: TestScope;
  startTime?: number;
  endTime?: number;
  duration?: number;
  findings: SecurityFinding[];
  statistics: TestStatistics;
  metadata: Record<string, unknown>;
}

export interface SecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  category: string;
  cwe?: string; // Common Weakness Enumeration
  cvss?: number; // CVSS score
  affectedEndpoint: string;
  payload?: string;
  evidence: string[];
  remediation: string[];
  references: string[];
  timestamp: number;
  testId: string;
}

export interface TestStatistics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  peakResponseTime: number;
  totalPayloads: number;
  uniqueFindings: number;
  falsePositives: number;
  coverage: number; // percentage
}

export interface PenetrationTestReport {
  testId: string;
  summary: {
    title: string;
    description: string;
    startTime: number;
    endTime: number;
    duration: number;
    overallRisk: 'low' | 'medium' | 'high' | 'critical';
  };
  executiveSummary: string;
  findings: SecurityFinding[];
  statistics: TestStatistics;
  riskAssessment: {
    overallScore: number;
    riskDistribution: Record<string, number>;
    topRisks: string[];
    trendAnalysis: string;
  };
  recommendations: string[];
  technicalDetails: {
    testConfiguration: PenetrationTestConfig;
    attackVectors: string[];
    defensiveMeasures: string[];
  };
  compliance: {
    standards: string[];
    complianceStatus: Record<string, boolean>;
    gaps: string[];
  };
}

class PenetrationTestingManager {
  private static instance: PenetrationTestingManager;
  private config: PenetrationTestConfig;
  private activeTests: Map<string, PenetrationTest> = new Map();
  private testHistory: PenetrationTest[] = [];
  private attackPayloads: Map<string, string[]> = new Map();
  private isInitialized = false;

  static getInstance(): PenetrationTestingManager {
    if (!PenetrationTestingManager.instance) {
      PenetrationTestingManager.instance = new PenetrationTestingManager();
    }
    return PenetrationTestingManager.instance;
  }

  private constructor() {
    this.config = this.loadPenetrationTestConfig();
    this.initializeAttackPayloads();
    if (this.config.enabled) {
      this.initializePenetrationTesting();
    }
  }

  private loadPenetrationTestConfig(): PenetrationTestConfig {
    return {
      enabled: process.env['PENETRATION_TESTING_ENABLED'] === 'true',
      testTypes: [
        {
          name: 'SQL Injection',
          description: 'Test for SQL injection vulnerabilities',
          enabled: true,
          category: 'injection',
          riskLevel: 'high',
          estimatedDuration: 30
        },
        {
          name: 'XSS Detection',
          description: 'Test for Cross-Site Scripting vulnerabilities',
          enabled: true,
          category: 'injection',
          riskLevel: 'high',
          estimatedDuration: 25
        },
        {
          name: 'Authentication Bypass',
          description: 'Test authentication mechanisms',
          enabled: true,
          category: 'authentication',
          riskLevel: 'critical',
          estimatedDuration: 45
        },
        {
          name: 'Authorization Flaws',
          description: 'Test for authorization bypass vulnerabilities',
          enabled: true,
          category: 'authorization',
          riskLevel: 'high',
          estimatedDuration: 35
        },
        {
          name: 'Sensitive Data Exposure',
          description: 'Test for sensitive data leakage',
          enabled: true,
          category: 'data_exposure',
          riskLevel: 'high',
          estimatedDuration: 20
        },
        {
          name: 'API Security',
          description: 'Test API endpoints for security issues',
          enabled: true,
          category: 'api',
          riskLevel: 'medium',
          estimatedDuration: 40
        },
        {
          name: 'Configuration Audit',
          description: 'Audit system configuration for security issues',
          enabled: true,
          category: 'configuration',
          riskLevel: 'medium',
          estimatedDuration: 15
        },
        {
          name: 'Fuzz Testing',
          description: 'Comprehensive fuzz testing of inputs',
          enabled: true,
          category: 'fuzzing',
          riskLevel: 'medium',
          estimatedDuration: 60
        }
      ],
      scope: {
        includeEndpoints: process.env['TEST_ENDPOINTS']?.split(',') || ['/api/*', '/tools/*'],
        excludeEndpoints: process.env['EXCLUDE_ENDPOINTS']?.split(',') || [],
        includeParameters: process.env['TEST_PARAMETERS']?.split(',') || ['query', 'body', 'headers'],
        excludeParameters: process.env['EXCLUDE_PARAMETERS']?.split(',') || [],
        maxDepth: parseInt(process.env['TEST_MAX_DEPTH'] || '3'),
        followRedirects: process.env['TEST_FOLLOW_REDIRECTS'] !== 'false'
      },
      schedule: {
        enabled: process.env['TEST_SCHEDULE_ENABLED'] === 'true',
        frequency: (process.env['TEST_FREQUENCY'] as TestSchedule['frequency']) || 'weekly',
        timeWindow: {
          start: process.env['TEST_WINDOW_START'] || '02:00',
          end: process.env['TEST_WINDOW_END'] || '06:00'
        }
      },
      intensity: (process.env['TEST_INTENSITY'] as PenetrationTestConfig['intensity']) || 'medium',
      maxConcurrentTests: parseInt(process.env['MAX_CONCURRENT_TESTS'] || '2'),
      timeout: parseInt(process.env['TEST_TIMEOUT'] || '300000'), // 5 minutes
      reporting: {
        format: (process.env['REPORT_FORMAT'] as ReportingConfig['format']) || 'html',
        includeDetails: process.env['REPORT_INCLUDE_DETAILS'] !== 'false',
        includeRemediation: process.env['REPORT_INCLUDE_REMEDIATION'] !== 'false',
        notifyOnCompletion: process.env['REPORT_NOTIFY_COMPLETION'] !== 'false',
        retentionDays: parseInt(process.env['REPORT_RETENTION_DAYS'] || '90')
      }
    };
  }

  private initializeAttackPayloads(): void {
    // SQL Injection payloads
    this.attackPayloads.set('sql_injection', [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT * FROM users --",
      "admin' --",
      "' OR 1=1 --",
      "') OR ('1'='1",
      "'; EXEC xp_cmdshell('net user') --",
      "' AND 1=0 UNION SELECT username, password FROM users --"
    ]);

    // XSS payloads
    this.attackPayloads.set('xss', [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<body onload=alert("XSS")>',
      '"><script>alert("XSS")</script>',
      '<input onfocus=alert("XSS") autofocus>'
    ]);

    // Command injection payloads
    this.attackPayloads.set('command_injection', [
      '; ls -la',
      '| cat /etc/passwd',
      '`whoami`',
      '$(rm -rf /)',
      '; net user',
      '| dir',
      '; id',
      '&& echo vulnerable'
    ]);

    // Path traversal payloads
    this.attackPayloads.set('path_traversal', [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '....//....//....//etc/passwd',
      '..%2F..%2F..%2Fetc%2Fpasswd',
      '.../...//.../...//etc/passwd',
      '..\\..\\..\\..\\..\\..\\windows\\win.ini'
    ]);

    // Authentication bypass payloads
    this.attackPayloads.set('auth_bypass', [
      'admin',
      'administrator',
      'root',
      'system',
      'guest',
      'test',
      'user',
      'anonymous'
    ]);

    // Fuzzing payloads (random data)
    this.attackPayloads.set('fuzz', [
      'A'.repeat(1000),
      'B'.repeat(5000),
      '\x00\x01\x02\x03',
      '%00%01%02%03',
      'null',
      'undefined',
      'NaN',
      '{}',
      '[]',
      'true',
      'false',
      '0',
      '-1',
      '999999',
      '-999999',
      '3.14159',
      'Infinity',
      '-Infinity'
    ]);

    logger.info('💣 Attack payloads initialized', {
      categories: this.attackPayloads.size,
      totalPayloads: Array.from(this.attackPayloads.values()).reduce((sum, payloads) => sum + payloads.length, 0)
    });
  }

  private initializePenetrationTesting(): void {
    this.isInitialized = true;
    logger.info('🔓 Penetration testing system initialized', {
      testTypes: this.config.testTypes.filter(t => t.enabled).length,
      intensity: this.config.intensity
    });

    // Start scheduled testing if enabled
    if (this.config.schedule.enabled) {
      this.startScheduledTesting();
    }
  }

  async startPenetrationTest(
    testType: string,
    customConfig?: Partial<PenetrationTestConfig>
  ): Promise<string> {
    if (!this.isInitialized) {
      throw new Error('Penetration testing system not initialized');
    }

    const testConfig = this.config.testTypes.find(t => t.name === testType);
    if (!testConfig) {
      throw new Error(`Unknown test type: ${testType}`);
    }

    if (!testConfig.enabled) {
      throw new Error(`Test type ${testType} is disabled`);
    }

    // Check concurrent test limit
    if (this.activeTests.size >= this.config.maxConcurrentTests) {
      throw new Error('Maximum concurrent tests reached');
    }

    const testId = `pentest_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

    const test: PenetrationTest = {
      id: testId,
      name: testType,
      description: testConfig.description,
      status: 'pending',
      type: testConfig,
      scope: customConfig?.scope || this.config.scope,
      findings: [],
      statistics: {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        averageResponseTime: 0,
        peakResponseTime: 0,
        totalPayloads: 0,
        uniqueFindings: 0,
        falsePositives: 0,
        coverage: 0
      },
      metadata: {
        customConfig,
        startedBy: 'system'
      }
    };

    this.activeTests.set(testId, test);

    // Start the test asynchronously
    this.runPenetrationTest(test).catch((error: unknown) => {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Penetration test failed', { testId, error: errorMessage });
      test.status = 'failed';
      test.metadata['error'] = errorMessage;
    });

    logger.info('🚀 Penetration test started', {
      testId,
      testType,
      intensity: this.config.intensity
    });

    return testId;
  }

  private async runPenetrationTest(test: PenetrationTest): Promise<void> {
    test.status = 'running';
    test.startTime = Date.now();

    try {
      logger.info('🔬 Running penetration test', {
        testId: test.id,
        type: test.name,
        category: test.type.category
      });

      // Run the specific test based on type
      switch (test.type.category) {
        case 'injection':
          await this.runInjectionTest(test);
          break;
        case 'authentication':
          await this.runAuthenticationTest(test);
          break;
        case 'authorization':
          await this.runAuthorizationTest(test);
          break;
        case 'data_exposure':
          await this.runDataExposureTest(test);
          break;
        case 'configuration':
          await this.runConfigurationTest(test);
          break;
        case 'api':
          await this.runAPITest(test);
          break;
        case 'fuzzing':
          await this.runFuzzTest(test);
          break;
        default:
          throw new Error(`Unsupported test category: ${test.type.category}`);
      }

      test.status = 'completed';
      test.endTime = Date.now();
      test.duration = test.endTime - (test.startTime || 0);

      // Calculate statistics
      this.calculateTestStatistics(test);

      // Generate report
      await this.generateTestReport(test);

      logger.info('✅ Penetration test completed', {
        testId: test.id,
        duration: test.duration,
        findings: test.findings.length,
        coverage: test.statistics.coverage
      });

    } catch (error: unknown) {
      test.status = 'failed';
      test.endTime = Date.now();
      test.duration = test.endTime - (test.startTime || 0);
      const errorMessage = error instanceof Error ? error.message : String(error);
      test.metadata['error'] = errorMessage;

      logger.error('❌ Penetration test failed', {
        testId: test.id,
        error: errorMessage
      });
    }

    // Move to history
    this.activeTests.delete(test.id);
    this.testHistory.push(test);
  }

  private async runInjectionTest(test: PenetrationTest): Promise<void> {
    const payloads = [
      ...this.attackPayloads.get('sql_injection') || [],
      ...this.attackPayloads.get('xss') || [],
      ...this.attackPayloads.get('command_injection') || []
    ];

    for (const endpoint of this.config.scope.includeEndpoints) {
      for (const payload of payloads) {
        if (this.isTestTimeout(test)) break;

        const finding = await this.testInjectionPayload(endpoint, payload, test);
        if (finding) {
          test.findings.push(finding);
        }

        test.statistics.totalRequests++;
        test.statistics.totalPayloads++;
      }
    }
  }

  private async runAuthenticationTest(test: PenetrationTest): Promise<void> {
    const authPayloads = this.attackPayloads.get('auth_bypass') || [];

    for (const endpoint of this.config.scope.includeEndpoints) {
      if (endpoint.includes('/auth') || endpoint.includes('/login')) {
        for (const payload of authPayloads) {
          if (this.isTestTimeout(test)) break;

          const finding = await this.testAuthenticationPayload(endpoint, payload, test);
          if (finding) {
            test.findings.push(finding);
          }

          test.statistics.totalRequests++;
          test.statistics.totalPayloads++;
        }
      }
    }
  }

  private async runAuthorizationTest(test: PenetrationTest): Promise<void> {
    // Test for IDOR, privilege escalation, etc.
    const authTests = [
      { name: 'IDOR Test', payload: '../admin/users', expectedStatus: 403 },
      { name: 'Privilege Escalation', payload: 'role=admin', expectedStatus: 403 },
      { name: 'Horizontal Privilege', payload: 'user_id=999', expectedStatus: 403 }
    ];

    for (const endpoint of this.config.scope.includeEndpoints) {
      for (const authTest of authTests) {
        if (this.isTestTimeout(test)) break;

        const finding = await this.testAuthorizationEndpoint(endpoint, authTest, test);
        if (finding) {
          test.findings.push(finding);
        }

        test.statistics.totalRequests++;
      }
    }
  }

  private async runDataExposureTest(test: PenetrationTest): Promise<void> {
    const sensitivePatterns = [
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit cards
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Emails
      /\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b/, // Phone numbers
      /\b[A-Z]{2}\d{6}[A-Z]\b/, // SSN pattern
      /\bapi[_-]?key|apikey|secret[_-]?key|access[_-]?token\b/i, // API keys
      /\bpassword|passwd|pwd\b/i // Password indicators
    ];

    for (const endpoint of this.config.scope.includeEndpoints) {
      if (this.isTestTimeout(test)) break;

      const finding = await this.testDataExposure(endpoint, sensitivePatterns, test);
      if (finding) {
        test.findings.push(finding);
      }

      test.statistics.totalRequests++;
    }
  }

  private async runConfigurationTest(test: PenetrationTest): Promise<void> {
    const configChecks = [
      { name: 'Directory Listing', pattern: /<title>Index of/, severity: 'medium' },
      { name: 'Backup Files', pattern: /\.bak$|\.backup$|\.old$/i, severity: 'low' },
      { name: 'Debug Mode', pattern: /debug.*true|development.*mode/i, severity: 'medium' },
      { name: 'Default Credentials', pattern: /admin.*admin|root.*root/i, severity: 'high' },
      { name: 'Information Disclosure', pattern: /server.*version|php.*version/i, severity: 'low' }
    ];

    for (const check of configChecks) {
      if (this.isTestTimeout(test)) break;

      const findings = await this.performConfigurationCheck(check, test);
      test.findings.push(...findings);
    }
  }

  private async runAPITest(test: PenetrationTest): Promise<void> {
    const apiChecks = [
      { name: 'Missing Authentication', method: 'GET', expectAuth: true },
      { name: 'Weak CORS Policy', headers: { 'Origin': 'evil.com' } },
      { name: 'HTTP Methods Allowed', method: 'OPTIONS' },
      { name: 'Rate Limiting Bypass', concurrent: true },
      { name: 'API Version Disclosure', checkHeaders: true }
    ];

    for (const endpoint of this.config.scope.includeEndpoints) {
      for (const check of apiChecks) {
        if (this.isTestTimeout(test)) break;

        const finding = await this.performAPICheck(endpoint, check, test);
        if (finding) {
          test.findings.push(finding);
        }

        test.statistics.totalRequests++;
      }
    }
  }

  private async runFuzzTest(test: PenetrationTest): Promise<void> {
    const fuzzPayloads = this.attackPayloads.get('fuzz') || [];

    for (const endpoint of this.config.scope.includeEndpoints) {
      for (const payload of fuzzPayloads) {
        if (this.isTestTimeout(test)) break;

        const finding = await this.testFuzzPayload(endpoint, payload, test);
        if (finding) {
          test.findings.push(finding);
        }

        test.statistics.totalRequests++;
        test.statistics.totalPayloads++;
      }
    }
  }

  private async testInjectionPayload(
    endpoint: string,
    payload: string,
    test: PenetrationTest
  ): Promise<SecurityFinding | null> {
    try {
      // Simulate testing the payload against the endpoint
      // In a real implementation, this would make actual HTTP requests

      // Use the intelligent classifier to analyze the payload
      const analysis = await intelligentClassifier.analyzeInput(payload, {
        source: 'tool',
        userRole: 'user',
        toolAcl: [],
        conversationId: test.id
      });

      if (analysis.ensembleDecision.finalDecision === 'block' ||
          analysis.ensembleDecision.finalDecision === 'allow_sanitized') {
        return {
          id: `finding_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
          title: 'Potential Injection Vulnerability',
          description: `Injection payload detected and ${analysis.ensembleDecision.finalDecision}`,
          severity: analysis.ensembleDecision.finalDecision === 'block' ? 'high' : 'medium',
          confidence: analysis.ensembleDecision.confidence,
          category: 'Injection',
          affectedEndpoint: endpoint,
          payload,
          evidence: [
            `Payload: ${payload}`,
            `Classification: ${analysis.ensembleDecision.finalDecision}`,
            `Confidence: ${(analysis.ensembleDecision.confidence * 100).toFixed(1)}%`
          ],
          remediation: [
            'Implement input validation and sanitization',
            'Use parameterized queries for SQL',
            'Implement Content Security Policy (CSP) for XSS',
            'Use safe encoding functions'
          ],
          references: [
            'OWASP Injection Prevention Cheat Sheet',
            'CWE-79: Cross-site Scripting',
            'CWE-89: SQL Injection'
          ],
          timestamp: Date.now(),
          testId: test.id
        };
      }

      return null;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.warn('⚠️ Injection test failed', { endpoint, payload, error: errorMessage });
      return null;
    }
  }

  private async testAuthenticationPayload(
    _endpoint: string,
    _payload: string,
    _test: PenetrationTest
  ): Promise<SecurityFinding | null> {
    // Simulate authentication testing
    // In production, this would attempt actual authentication bypass
    return null;
  }

  private async testAuthorizationEndpoint(
    _endpoint: string,
    _authTest: Record<string, unknown>,
    _test: PenetrationTest
  ): Promise<SecurityFinding | null> {
    // Simulate authorization testing
    return null;
  }

  private async testDataExposure(
    _endpoint: string,
    _patterns: RegExp[],
    _test: PenetrationTest
  ): Promise<SecurityFinding | null> {
    // Simulate data exposure testing
    return null;
  }

  private async performConfigurationCheck(
    _check: Record<string, unknown>,
    _test: PenetrationTest
  ): Promise<SecurityFinding[]> {
    // Simulate configuration checking
    return [];
  }

  private async performAPICheck(
    _endpoint: string,
    _check: Record<string, unknown>,
    _test: PenetrationTest
  ): Promise<SecurityFinding | null> {
    // Simulate API testing
    return null;
  }

  private async testFuzzPayload(
    _endpoint: string,
    _payload: string,
    _test: PenetrationTest
  ): Promise<SecurityFinding | null> {
    // Simulate fuzz testing
    return null;
  }

  private isTestTimeout(test: PenetrationTest): boolean {
    if (!test.startTime) return false;
    return Date.now() - test.startTime > this.config.timeout;
  }

  private calculateTestStatistics(test: PenetrationTest): void {
    const stats = test.statistics;

    // Calculate success rate
    if (stats.totalRequests > 0) {
      stats.coverage = (stats.successfulRequests / stats.totalRequests) * 100;
    }

    // Remove duplicates
    const uniqueFindings = new Map<string, SecurityFinding>();
    test.findings.forEach(finding => {
      const key = `${finding.category}:${finding.affectedEndpoint}`;
      if (!uniqueFindings.has(key)) {
        uniqueFindings.set(key, finding);
      }
    });

    stats.uniqueFindings = uniqueFindings.size;
    test.findings = Array.from(uniqueFindings.values());
  }

  private async generateTestReport(test: PenetrationTest): Promise<void> {
    const report: PenetrationTestReport = {
      testId: test.id,
      summary: {
        title: test.name,
        description: test.description,
        startTime: test.startTime || 0,
        endTime: test.endTime || 0,
        duration: test.duration || 0,
        overallRisk: this.calculateOverallRisk(test.findings)
      },
      executiveSummary: this.generateExecutiveSummary(test),
      findings: test.findings,
      statistics: test.statistics,
      riskAssessment: this.performRiskAssessment(test),
      recommendations: this.generateRecommendations(test),
      technicalDetails: {
        testConfiguration: this.config,
        attackVectors: this.getAttackVectors(test),
        defensiveMeasures: this.getDefensiveMeasures(test)
      },
      compliance: {
        standards: ['OWASP', 'NIST', 'ISO 27001'],
        complianceStatus: this.checkCompliance(test),
        gaps: this.identifyComplianceGaps(test)
      }
    };

    // Save report to file
    await this.saveReport(report);

    logger.info('📊 Penetration test report generated', {
      testId: test.id,
      findings: test.findings.length,
      risk: report.summary.overallRisk
    });
  }

  private calculateOverallRisk(findings: SecurityFinding[]): 'low' | 'medium' | 'high' | 'critical' {
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;

    if (criticalCount > 0) return 'critical';
    if (highCount > 2) return 'high';
    if (highCount > 0 || findings.filter(f => f.severity === 'medium').length > 3) return 'medium';
    return 'low';
  }

  private generateExecutiveSummary(test: PenetrationTest): string {
    const risk = this.calculateOverallRisk(test.findings);
    const coverage = test.statistics.coverage;

    return `
Penetration testing completed for ${test.name} with ${coverage.toFixed(1)}% coverage.
Found ${test.findings.length} security issues with overall risk level: ${risk.toUpperCase()}.

Key findings:
- Total vulnerabilities discovered: ${test.findings.length}
- Critical severity issues: ${test.findings.filter(f => f.severity === 'critical').length}
- High severity issues: ${test.findings.filter(f => f.severity === 'high').length}
- Test duration: ${Math.round((test.duration || 0) / 1000 / 60)} minutes

Recommendations have been provided for remediation and security hardening.
    `.trim();
  }

  private performRiskAssessment(test: PenetrationTest): {
    overallScore: number;
    riskDistribution: Record<string, number>;
    topRisks: string[];
    trendAnalysis: string;
  } {
    const findings = test.findings;
    const riskDistribution: Record<string, number> = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length
    };

    const topRisks = findings
      .sort((a, b) => this.getSeverityScore(b.severity) - this.getSeverityScore(a.severity))
      .slice(0, 5)
      .map(f => f.title);

    return {
      overallScore: this.calculateRiskScore(findings),
      riskDistribution,
      topRisks,
      trendAnalysis: 'Risk assessment completed'
    };
  }

  private getSeverityScore(severity: string): number {
    const scores: Record<string, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };
    return scores[severity] || 0;
  }

  private calculateRiskScore(findings: SecurityFinding[]): number {
    const weights = { critical: 10, high: 7, medium: 4, low: 2, info: 1 };
    return findings.reduce((score, finding) => {
      return score + (weights[finding.severity] || 0) * finding.confidence;
    }, 0);
  }

  private generateRecommendations(test: PenetrationTest): string[] {
    const recommendations: string[] = [];

    const criticalFindings = test.findings.filter(f => f.severity === 'critical');
    const highFindings = test.findings.filter(f => f.severity === 'high');

    if (criticalFindings.length > 0) {
      recommendations.push('🚨 CRITICAL: Immediate attention required for critical findings');
      recommendations.push('🔒 CRITICAL: Implement emergency security measures');
    }

    if (highFindings.length > 2) {
      recommendations.push('⚠️ HIGH: Prioritize remediation of high-severity vulnerabilities');
      recommendations.push('🛡️ HIGH: Enhance security controls and monitoring');
    }

    recommendations.push('📚 Review and implement provided remediation steps');
    recommendations.push('🔄 Schedule regular security testing and assessments');
    recommendations.push('📊 Implement continuous security monitoring');

    return recommendations;
  }

  private getAttackVectors(test: PenetrationTest): string[] {
    return [...new Set(test.findings.map(f => f.category))];
  }

  private getDefensiveMeasures(test: PenetrationTest): string[] {
    const measures: string[] = [];

    if (test.findings.some(f => f.category === 'Injection')) {
      measures.push('Input validation and sanitization');
      measures.push('Parameterized queries');
      measures.push('Content Security Policy (CSP)');
    }

    if (test.findings.some(f => f.category === 'Authentication')) {
      measures.push('Multi-factor authentication');
      measures.push('Secure password policies');
      measures.push('Session management');
    }

    return measures;
  }

  private checkCompliance(test: PenetrationTest): Record<string, boolean> {
    // Simplified compliance checking
    return {
      'OWASP Top 10': test.findings.length < 5,
      'NIST Framework': test.statistics.coverage > 80,
      'ISO 27001': test.findings.filter(f => f.severity === 'critical').length === 0
    };
  }

  private identifyComplianceGaps(test: PenetrationTest): string[] {
    const gaps: string[] = [];

    if (test.findings.some(f => f.category === 'Injection')) {
      gaps.push('Input validation controls need enhancement');
    }

    if (test.statistics.coverage < 80) {
      gaps.push('Test coverage needs improvement');
    }

    return gaps;
  }

  private async saveReport(report: PenetrationTestReport): Promise<void> {
    const reportPath = path.join(process.cwd(), 'reports', `pentest-${report.testId}.json`);

    try {
      await fs.promises.mkdir(path.dirname(reportPath), { recursive: true });
      await fs.promises.writeFile(reportPath, JSON.stringify(report, null, 2));
      logger.info('💾 Penetration test report saved', { path: reportPath });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Failed to save report', { path: reportPath, error: errorMessage });
    }
  }

  private startScheduledTesting(): void {
    // Implementation for scheduled testing would go here
    logger.info('⏰ Scheduled penetration testing enabled', {
      frequency: this.config.schedule.frequency,
      window: this.config.schedule.timeWindow
    });
  }

  // Public API methods
  getActiveTests(): PenetrationTest[] {
    return Array.from(this.activeTests.values());
  }

  getTestHistory(limit = 10): PenetrationTest[] {
    return this.testHistory.slice(-limit);
  }

  getTestById(testId: string): PenetrationTest | null {
    return this.activeTests.get(testId) ||
           this.testHistory.find(test => test.id === testId) || null;
  }

  async cancelTest(testId: string): Promise<boolean> {
    const test = this.activeTests.get(testId);
    if (test && test.status === 'running') {
      test.status = 'cancelled';
      test.endTime = Date.now();
      this.activeTests.delete(testId);
      this.testHistory.push(test);
      logger.info('🚫 Penetration test cancelled', { testId });
      return true;
    }
    return false;
  }

  getAvailableTestTypes(): PenetrationTestType[] {
    return this.config.testTypes.filter(type => type.enabled);
  }

  getTestStatistics(): {
    totalTests: number;
    activeTests: number;
    completedTests: number;
    failedTests: number;
    averageDuration: number;
    totalFindings: number;
    averageRiskScore: number;
  } {
    const completedTests = this.testHistory.filter(test => test.status === 'completed');
    const failedTests = this.testHistory.filter(test => test.status === 'failed');

    const totalDuration = completedTests.reduce((sum, test) => sum + (test.duration || 0), 0);
    const averageDuration = completedTests.length > 0 ? totalDuration / completedTests.length : 0;

    const totalFindings = this.testHistory.reduce((sum, test) => sum + test.findings.length, 0);
    const averageRiskScore = completedTests.length > 0 ?
      completedTests.reduce((sum, test) => sum + this.calculateRiskScore(test.findings), 0) / completedTests.length : 0;

    return {
      totalTests: this.testHistory.length,
      activeTests: this.activeTests.size,
      completedTests: completedTests.length,
      failedTests: failedTests.length,
      averageDuration,
      totalFindings,
      averageRiskScore
    };
  }

  getStatus(): {
    enabled: boolean;
    initialized: boolean;
    activeTests: number;
    testHistory: number;
    availableTestTypes: number;
    scheduled: boolean;
    health: 'healthy' | 'warning' | 'error';
  } {
    return {
      enabled: this.config.enabled,
      initialized: this.isInitialized,
      activeTests: this.activeTests.size,
      testHistory: this.testHistory.length,
      availableTestTypes: this.getAvailableTestTypes().length,
      scheduled: this.config.schedule.enabled,
      health: this.isInitialized ? 'healthy' : 'error'
    };
  }

  async shutdown(): Promise<void> {
    // Cancel all active tests
    for (const [testId] of this.activeTests) {
      await this.cancelTest(testId);
    }

    this.isInitialized = false;
    logger.info('🛑 Penetration testing system shutdown');
  }
}

export const penetrationTester = PenetrationTestingManager.getInstance();
