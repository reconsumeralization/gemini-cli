/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Circuit Breaker Pattern for Resilient System Operations
export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures before opening
  recoveryTimeout: number; // Time in ms before attempting recovery
  monitoringPeriod: number; // Time window for failure counting
  successThreshold: number; // Number of successes needed to close
  name: string; // Circuit breaker identifier
}

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerMetrics {
  state: CircuitState;
  failures: number;
  successes: number;
  lastFailureTime?: number;
  lastSuccessTime?: number;
  totalRequests: number;
  totalFailures: number;
  totalSuccesses: number;
  uptimePercentage: number;
}

class CircuitBreaker {
  private config: CircuitBreakerConfig;
  private state: CircuitState = 'CLOSED';
  private failures = 0;
  private successes = 0;
  private lastFailureTime?: number;
  private lastSuccessTime?: number;
  private nextAttemptTime = 0;
  private metrics: CircuitBreakerMetrics;

  constructor(config: CircuitBreakerConfig) {
    this.config = config;
    this.metrics = this.initializeMetrics();
  }

  private initializeMetrics(): CircuitBreakerMetrics {
    return {
      state: this.state,
      failures: 0,
      successes: 0,
      lastFailureTime: undefined,
      lastSuccessTime: undefined,
      totalRequests: 0,
      totalFailures: 0,
      totalSuccesses: 0,
      uptimePercentage: 100
    };
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    this.metrics.totalRequests++;

    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttemptTime) {
        throw new Error(`Circuit breaker ${this.config.name} is OPEN`);
      }
      this.state = 'HALF_OPEN';
      this.successes = 0;
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.lastSuccessTime = Date.now();
    this.metrics.successes++;
    this.metrics.totalSuccesses++;

    if (this.state === 'HALF_OPEN') {
      this.successes++;
      if (this.successes >= this.config.successThreshold) {
        this.close();
      }
    }

    this.updateMetrics();
  }

  private onFailure(): void {
    this.lastFailureTime = Date.now();
    this.failures++;
    this.metrics.failures++;
    this.metrics.totalFailures++;

    if (this.state === 'CLOSED' && this.failures >= this.config.failureThreshold) {
      this.open();
    } else if (this.state === 'HALF_OPEN') {
      this.open();
    }

    this.updateMetrics();
  }

  private open(): void {
    this.state = 'OPEN';
    this.nextAttemptTime = Date.now() + this.config.recoveryTimeout;
    this.metrics.state = 'OPEN';
  }

  private close(): void {
    this.state = 'CLOSED';
    this.failures = 0;
    this.successes = 0;
    this.metrics.state = 'CLOSED';
    this.updateMetrics();
  }

  private updateMetrics(): void {
    const total = this.metrics.totalSuccesses + this.metrics.totalFailures;
    this.metrics.uptimePercentage = total > 0 ?
      (this.metrics.totalSuccesses / total) * 100 : 100;
    this.metrics.lastFailureTime = this.lastFailureTime;
    this.metrics.lastSuccessTime = this.lastSuccessTime;
  }

  getMetrics(): CircuitBreakerMetrics {
    return { ...this.metrics };
  }

  getState(): CircuitState {
    return this.state;
  }

  reset(): void {
    this.state = 'CLOSED';
    this.failures = 0;
    this.successes = 0;
    this.lastFailureTime = undefined;
    this.lastSuccessTime = undefined;
    this.nextAttemptTime = 0;
    this.metrics = this.initializeMetrics();
  }

  forceOpen(): void {
    this.open();
  }

  forceClose(): void {
    this.close();
  }
}

class CircuitBreakerRegistry {
  private static instance: CircuitBreakerRegistry;
  private breakers = new Map<string, CircuitBreaker>();
  private healthCheckInterval?: NodeJS.Timeout;

  static getInstance(): CircuitBreakerRegistry {
    if (!CircuitBreakerRegistry.instance) {
      CircuitBreakerRegistry.instance = new CircuitBreakerRegistry();
    }
    return CircuitBreakerRegistry.instance;
  }

  private constructor() {
    this.startHealthMonitoring();
  }

  createBreaker(name: string, config: Omit<CircuitBreakerConfig, 'name'>): CircuitBreaker {
    const fullConfig: CircuitBreakerConfig = { ...config, name };
    const breaker = new CircuitBreaker(fullConfig);
    this.breakers.set(name, breaker);
    return breaker;
  }

  getBreaker(name: string): CircuitBreaker | undefined {
    return this.breakers.get(name);
  }

  getAllBreakers(): Map<string, CircuitBreaker> {
    return new Map(this.breakers);
  }

  getHealthStatus(): {
    totalBreakers: number;
    openBreakers: number;
    halfOpenBreakers: number;
    closedBreakers: number;
    overallHealth: 'healthy' | 'degraded' | 'critical';
    breakerDetails: Array<{
      name: string;
      state: CircuitState;
      uptime: number;
      failures: number;
    }>;
  } {
    const breakers = Array.from(this.breakers.values());
    const openCount = breakers.filter(b => b.getState() === 'OPEN').length;
    const halfOpenCount = breakers.filter(b => b.getState() === 'HALF_OPEN').length;
    const closedCount = breakers.filter(b => b.getState() === 'CLOSED').length;

    let overallHealth: 'healthy' | 'degraded' | 'critical' = 'healthy';
    if (openCount > 0) overallHealth = 'critical';
    else if (halfOpenCount > 0) overallHealth = 'degraded';

    const breakerDetails = breakers.map(breaker => {
      const metrics = breaker.getMetrics();
      return {
        name: breaker.getMetrics().state === 'OPEN' ? 'unknown' : 'circuit-breaker',
        state: breaker.getState(),
        uptime: metrics.uptimePercentage,
        failures: metrics.totalFailures
      };
    });

    return {
      totalBreakers: breakers.length,
      openBreakers: openCount,
      halfOpenBreakers: halfOpenCount,
      closedBreakers: closedCount,
      overallHealth,
      breakerDetails
    };
  }

  private startHealthMonitoring(): void {
    this.healthCheckInterval = setInterval(() => {
      this.performHealthCheck();
    }, 30000); // Check every 30 seconds
  }

  private performHealthCheck(): void {
    const status = this.getHealthStatus();

    if (status.overallHealth === 'critical') {
      console.warn('🚨 Circuit Breaker Alert: Multiple services are unavailable', {
        openBreakers: status.openBreakers,
        affectedServices: status.breakerDetails.filter(b => b.state === 'OPEN').map(b => b.name)
      });
    } else if (status.overallHealth === 'degraded') {
      console.info('⚠️ Circuit Breaker Warning: Some services are in recovery mode', {
        halfOpenBreakers: status.halfOpenBreakers
      });
    }
  }

  async shutdown(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    // Reset all breakers to closed state
    for (const breaker of this.breakers.values()) {
      breaker.reset();
    }

    console.log('🔌 Circuit Breaker Registry shutdown');
  }
}

export const circuitBreakerRegistry = CircuitBreakerRegistry.getInstance();

// Pre-configured circuit breakers for common services
export const createOAuthBreaker = () =>
  circuitBreakerRegistry.createBreaker('oauth-service', {
    failureThreshold: 5,
    recoveryTimeout: 60000, // 1 minute
    monitoringPeriod: 300000, // 5 minutes
    successThreshold: 3
  });

export const createSIEMBreaker = () =>
  circuitBreakerRegistry.createBreaker('siem-service', {
    failureThreshold: 3,
    recoveryTimeout: 120000, // 2 minutes
    monitoringPeriod: 600000, // 10 minutes
    successThreshold: 2
  });

export const createTicketingBreaker = () =>
  circuitBreakerRegistry.createBreaker('ticketing-service', {
    failureThreshold: 3,
    recoveryTimeout: 90000, // 1.5 minutes
    monitoringPeriod: 450000, // 7.5 minutes
    successThreshold: 2
  });

export const createCacheBreaker = () =>
  circuitBreakerRegistry.createBreaker('cache-service', {
    failureThreshold: 10,
    recoveryTimeout: 30000, // 30 seconds
    monitoringPeriod: 180000, // 3 minutes
    successThreshold: 5
  });
