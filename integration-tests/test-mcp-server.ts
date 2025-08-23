/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type Express } from 'express';
import type { Request, Response } from 'express-serve-static-core'; 
import { type Server as HTTPServer } from 'node:http';
import { randomUUID } from 'node:crypto';

const MCP_SESSION_ID_HEADER = 'mcp-session-id';

export class TestMcpServer {
  private server: HTTPServer | undefined;
  private transports = new Map<string, StreamableHTTPServerTransport>();
  private log = (message: string) => console.log(`[TestMcpServer] ${message}`);

  async start(): Promise<number> {
    const app: Express = express();
    app.use(express.json());
    
    const mcpServer = new McpServer(
      {
        name: 'test-mcp-server',
        version: '1.0.0',
      },
      { capabilities: {} },
    );

    app.post('/mcp', async (req: Request, res: Response) => {
      const sessionId = req.headers[MCP_SESSION_ID_HEADER] as string | undefined;
      let transport: StreamableHTTPServerTransport;

      if (sessionId && this.transports.has(sessionId)) {
        transport = this.transports.get(sessionId)!;
      } else {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            this.log(`New session initialized: ${newSessionId}`);
            this.transports.set(newSessionId, transport);
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            this.log(`Session closed: ${transport.sessionId}`);
            this.transports.delete(transport.sessionId);
          }
        };

        await mcpServer.connect(transport);
      }

      try {
        // Type assertion needed due to Express 5.x compatibility with MCP SDK
        await transport.handleRequest(
          req as unknown as Parameters<typeof transport.handleRequest>[0], 
          res as unknown as Parameters<typeof transport.handleRequest>[1], 
          req.body
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        this.log(`Error handling MCP request: ${errorMessage}`);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0' as const,
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          });
        }
      }
    });

    return new Promise((resolve, reject) => {
      this.server = app.listen(0, () => {
        const address = this.server?.address();
        if (address && typeof address !== 'string') {
          this.log(`Test MCP server listening on port ${address.port}`);
          resolve(address.port);
        } else {
          reject(new Error('Could not determine server port.'));
        }
      });
      this.server?.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      // Close all active transports
      for (const [sessionId, transport] of this.transports) {
        this.log(`Closing session: ${sessionId}`);
        transport.close?.();
      }
      this.transports.clear();

      await new Promise<void>((resolve, reject) => {
        this.server!.close((err?: Error) => {
          if (err) {
            reject(err);
          } else {
            this.log('Test MCP server stopped');
            resolve();
          }
        });
      });
      this.server = undefined;
    }
  }
}
