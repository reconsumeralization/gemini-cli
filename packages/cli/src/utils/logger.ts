/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Simple logger utility for MCP server
export class Logger {
  private level: 'debug' | 'info' | 'warn' | 'error' = 'info';

  setLevel(level: 'debug' | 'info' | 'warn' | 'error'): void {
    this.level = level;
  }

  debug(message: string, ...args: any[]): void {
    if (this.level === 'debug') {
      console.debug(`[DEBUG] ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]): void {
    if (['debug', 'info'].includes(this.level)) {
      console.info(`[INFO] ${message}`, ...args);
    }
  }

  warn(message: string, ...args: any[]): void {
    if (!['error'].includes(this.level)) {
      console.warn(`[WARN] ${message}`, ...args);
    }
  }

  error(message: string, ...args: any[]): void {
    console.error(`[ERROR] ${message}`, ...args);
  }
}

export const logger = new Logger();
