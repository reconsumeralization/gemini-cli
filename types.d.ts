/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Module declarations for external dependencies that don't have TypeScript definitions

declare module 'express' {
  import { Application } from 'express';
  import { Server } from 'node:http';
  interface Express extends Application {
    use(...handlers: unknown[]): this;
    post(path: string, ...handlers: unknown[]): this;
    get(path: string, ...handlers: unknown[]): this;
    listen(port: number, callback?: () => void): Server;
  }

  const express: (() => Express) & {
    json: () => unknown;
    static: (path: string) => unknown;
    urlencoded: (options?: Record<string, unknown>) => unknown;
  };
  export = express;
  export { Express };
}

declare module 'mime-types' {
  interface MimeTypes {
    lookup(path: string): string | false;
  }

  const mime: MimeTypes & {
    default?: MimeTypes;
  };
  export = mime;
}
declare module '@lvce-editor/ripgrep' {
  interface RipgrepOptions {
    cwd?: string;
    args?: string[];
    [key: string]: unknown;
  }

  interface RipgrepResult {
    stdout: string;
    stderr: string;
    code: number;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [key: string]: any;
  }

  const ripgrep: (options?: RipgrepOptions) => Promise<RipgrepResult>;
  export = ripgrep;
  export const rgPath: string;
}

declare module 'mock-fs' {
  interface MockFsOptions {
    [path: string]: string | Buffer | MockFsOptions;
  }
  
  interface MockFs {
    symlink(arg0: { path: string; }): string | MockFileSystem;
    (config: MockFsOptions): void;
    restore(): void;
  }
  
  const mockFs: MockFs;
  export = mockFs;
}

declare module 'express-serve-static-core' {
  import { IncomingMessage } from 'node:http';
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  import { ServerResponse } from 'node:http';

  export interface Request extends IncomingMessage {
    body?: unknown;
    params?: Record<string, string>;
    query?: Record<string, string>;
    headers: Record<string, string | string[] | undefined>;
    method?: string;
    url?: string;
  }

  export interface Response {
    status(code: number): Response;
    json(data: unknown): Response;
    send(data: unknown): Response;
    headersSent?: boolean;
    writeHead(statusCode: number, headers?: Record<string, string | string[]>): Response;
    end(data?: unknown): Response;
    setHeader(name: string, value: string | string[]): Response;
    getHeader(name: string): string | string[] | undefined;
    removeHeader(name: string): void;
  }
}
