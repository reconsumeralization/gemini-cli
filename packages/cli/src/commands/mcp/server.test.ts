/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, jest, beforeEach } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { GeminiFuzzingMCPServer } from './server.js';
import * as fs from 'fs';
import * as path from 'path';

// Mock the MCP SDK
jest.mock('@modelcontextprotocol/sdk/server/index.js');
jest.mock('@modelcontextprotocol/sdk/server/stdio.js');

// Mock file system
jest.mock('fs');
jest.mock('path');

describe('GeminiFuzzingMCPServer', () => {
  let server: GeminiFuzzingMCPServer;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Mock fs functions
    (fs.existsSync as jest.Mock).mockReturnValue(true);
    (fs.readdirSync as jest.Mock).mockReturnValue(['fuzz_json_decoder.js', 'fuzz_http_header.js']);
    (fs.statSync as jest.Mock).mockReturnValue({
      size: 1024,
      mtime: new Date(),
    });
    (fs.readFileSync as jest.Mock).mockReturnValue('mock file content');
    (fs.mkdirSync as jest.Mock).mockImplementation(() => {});
    (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

    // Mock path functions
    (path.join as jest.Mock).mockImplementation((...args: string[]) => args.join('/'));
    (path.dirname as jest.Mock).mockReturnValue('/mock/dir');

    // Create server instance
    server = new GeminiFuzzingMCPServer();
  });

  describe('handleListFuzzers', () => {
    it('should return list of available fuzzers', async () => {
      const result = await (server as any).handleListFuzzers();

      expect(result.content[0].text).toContain('fuzz_json_decoder');
      expect(result.content[0].text).toContain('fuzz_http_header');
    });

    it('should handle file system errors', async () => {
      (fs.readdirSync as jest.Mock).mockImplementation(() => {
        throw new Error('File system error');
      });

      const result = await (server as any).handleListFuzzers();

      expect(result.content[0].text).toContain('Error listing fuzzers');
    });
  });

  describe('handleRunFuzzer', () => {
    it('should run fuzzer successfully', async () => {
      // Mock successful fuzzer execution
      const mockFuzzer = jest.fn().mockReturnValue(0);
      jest.doMock('/mock/path/fuzzers/fuzz_json_decoder.js', () => ({
        LLVMFuzzerTestOneInput: mockFuzzer,
      }), { virtual: true });

      const result = await (server as any).handleRunFuzzer('fuzz_json_decoder', 'test input', 100);

      expect(result.content[0].text).toContain('Fuzzer Results');
      expect(result.content[0].text).toContain('Iterations: 100');
    });

    it('should handle fuzzer not found', async () => {
      (fs.existsSync as jest.Mock).mockReturnValue(false);

      const result = await (server as any).handleRunFuzzer('nonexistent_fuzzer', 'test', 100);

      expect(result.content[0].text).toContain('not found');
    });
  });

  describe('handleGetFuzzerStats', () => {
    it('should return fuzzer statistics', async () => {
      const result = await (server as any).handleGetFuzzerStats('fuzz_json_decoder');

      expect(result.content[0].text).toContain('File Size: 1024 bytes');
      expect(result.content[0].text).toContain('Lines of Code:');
    });
  });

  describe('handleGenerateSeedCorpus', () => {
    it('should generate seed files', async () => {
      const result = await (server as any).handleGenerateSeedCorpus('fuzz_json_decoder', 3);

      expect(result.content[0].text).toContain('Generated 3 seed files');
      expect(fs.writeFileSync).toHaveBeenCalledTimes(3);
    });
  });

  describe('generateSeedData', () => {
    it('should generate appropriate seed data for different fuzzer types', () => {
      const jsonSeed = (server as any).generateSeedData('fuzz_json_decoder');
      const httpSeed = (server as any).generateSeedData('fuzz_http_header');
      const urlSeed = (server as any).generateSeedData('fuzz_url');

      expect(jsonSeed).toContain('generated_seed');
      expect(httpSeed).toContain('HTTP/1.1');
      expect(urlSeed).toContain('https://');
    });
  });
});
