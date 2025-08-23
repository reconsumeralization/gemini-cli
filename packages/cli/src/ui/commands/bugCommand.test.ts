/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import open from 'open';
import { bugCommand } from './bugCommand.js';
import { createMockCommandContext } from '../../test-utils/mockCommandContext.js';
import { getCliVersion } from '../../utils/version.js';
import { formatMemoryUsage } from '../utils/formatters.js';
import process from 'node:process';

// Mock the internal git commit module
vi.mock('../../generated/git-commit.js', () => ({
  GIT_COMMIT_INFO: 'mock-commit-hash',
}));

// Use the mocked value directly
const GIT_COMMIT_INFO = 'mock-commit-hash';

// Mock dependencies
vi.mock('open');
vi.mock('../../utils/version.js');
vi.mock('../utils/formatters.js');
vi.mock('@google/gemini-cli-core', () => ({
  sessionId: 'test-session-id',
}));

// Mock Node.js process module
vi.mock('node:process', () => ({
  default: {
    env: {
      SANDBOX: 'gemini-test',
    },
    platform: 'test-platform',
    version: 'v20.0.0',
    memoryUsage: () => ({ rss: 104857600 }), // 100 MB in bytes
  },
}));

describe('bugCommand', () => {
  beforeEach(() => {
    vi.mocked(getCliVersion).mockResolvedValue('0.1.0');
    vi.mocked(formatMemoryUsage).mockReturnValue('100 MB');
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should generate the default GitHub issue URL', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getModel: () => 'gemini-pro',
          getBugCommand: () => undefined,
          getIdeClient: () => ({
            getDetectedIdeDisplayName: () => 'VSCode',
          }),
          getIdeMode: () => true,
        },
      },
    });

    if (!bugCommand.action) throw new Error('Action is not defined');
    await bugCommand.action(mockContext, 'A test bug');

    const expectedInfo = `
* **CLI Version:** 0.1.0
* **Git Commit:** ${GIT_COMMIT_INFO}
* **Session ID:** test-session-id
* **Operating System:** test-platform v20.0.0
* **Sandbox Environment:** gemini-test
* **Model Version:** gemini-pro
* **Memory Usage:** 100 MB
* **IDE Client:** VSCode
`;
    const expectedUrl =
      'https://github.com/google-gemini/gemini-cli/issues/new?template=bug_report.yml&title=A%20test%20bug&info=' +
      encodeURIComponent(expectedInfo);

    expect(open).toHaveBeenCalledWith(expectedUrl);
  });

  it('should use a custom URL template from config if provided', async () => {
    const customTemplate =
      'https://internal.bug-tracker.com/new?desc={title}&details={info}';
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getModel: () => 'gemini-pro',
          getBugCommand: () => ({ urlTemplate: customTemplate }),
          getIdeClient: () => ({
            getDetectedIdeDisplayName: () => 'VSCode',
          }),
          getIdeMode: () => true,
        },
      },
    });

    if (!bugCommand.action) throw new Error('Action is not defined');
    await bugCommand.action(mockContext, 'A custom bug');

    const expectedInfo = `
* **CLI Version:** 0.1.0
* **Git Commit:** ${GIT_COMMIT_INFO}
* **Session ID:** test-session-id
* **Operating System:** test-platform v20.0.0
* **Sandbox Environment:** gemini-test
* **Model Version:** gemini-pro
* **Memory Usage:** 100 MB
* **IDE Client:** VSCode
`;
    const expectedUrl = customTemplate
      .replace('{title}', encodeURIComponent('A custom bug'))
      .replace('{info}', encodeURIComponent(expectedInfo));

    expect(open).toHaveBeenCalledWith(expectedUrl);
  });

  it('should handle missing environment variables gracefully', async () => {
    // Mock process with no SANDBOX environment variable
    vi.mocked(process).env = {};

    const mockContext = createMockCommandContext({
      services: {
        config: {
          getModel: () => 'gemini-pro',
          getBugCommand: () => undefined,
          getIdeClient: () => ({
            getDetectedIdeDisplayName: () => 'Unknown',
          }),
          getIdeMode: () => false,
        },
      },
    });

    if (!bugCommand.action) throw new Error('Action is not defined');
    await bugCommand.action(mockContext, 'Bug without sandbox');

    const expectedInfo = `
* **CLI Version:** 0.1.0
* **Git Commit:** ${GIT_COMMIT_INFO}
* **Session ID:** test-session-id
* **Operating System:** test-platform v20.0.0
* **Sandbox Environment:** N/A
* **Model Version:** gemini-pro
* **Memory Usage:** 100 MB
* **IDE Client:** Unknown
`;
    const expectedUrl =
      'https://github.com/google-gemini/gemini-cli/issues/new?template=bug_report.yml&title=Bug%20without%20sandbox&info=' +
      encodeURIComponent(expectedInfo);

    expect(open).toHaveBeenCalledWith(expectedUrl);
  });

  it('should handle CLI mode (non-IDE) correctly', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getModel: () => 'gemini-flash',
          getBugCommand: () => undefined,
          getIdeClient: () => null,
          getIdeMode: () => false,
        },
      },
    });

    if (!bugCommand.action) throw new Error('Action is not defined');
    await bugCommand.action(mockContext, 'CLI mode bug');

    const expectedInfo = `
* **CLI Version:** 0.1.0
* **Git Commit:** ${GIT_COMMIT_INFO}
* **Session ID:** test-session-id
* **Operating System:** test-platform v20.0.0
* **Sandbox Environment:** gemini-test
* **Model Version:** gemini-flash
* **Memory Usage:** 100 MB
* **IDE Client:** CLI
`;
    const expectedUrl =
      'https://github.com/google-gemini/gemini-cli/issues/new?template=bug_report.yml&title=CLI%20mode%20bug&info=' +
      encodeURIComponent(expectedInfo);

    expect(open).toHaveBeenCalledWith(expectedUrl);
  });

  it('should handle errors when opening URL', async () => {
    const mockError = new Error('Failed to open URL');
    vi.mocked(open).mockRejectedValue(mockError);

    const mockContext = createMockCommandContext({
      services: {
        config: {
          getModel: () => 'gemini-pro',
          getBugCommand: () => undefined,
          getIdeClient: () => ({
            getDetectedIdeDisplayName: () => 'VSCode',
          }),
          getIdeMode: () => true,
        },
      },
    });

    if (!bugCommand.action) throw new Error('Action is not defined');
    
    await expect(
      bugCommand.action(mockContext, 'Error test bug')
    ).rejects.toThrow('Failed to open URL');
  });

  it('should properly encode special characters in title and info', async () => {
    const mockContext = createMockCommandContext({
      services: {
        config: {
          getModel: () => 'gemini-pro',
          getBugCommand: () => undefined,
          getIdeClient: () => ({
            getDetectedIdeDisplayName: () => 'VS Code & Extensions',
          }),
          getIdeMode: () => true,
        },
      },
    });

    if (!bugCommand.action) throw new Error('Action is not defined');
    await bugCommand.action(mockContext, 'Bug with special chars: & < > "');

    const expectedInfo = `
* **CLI Version:** 0.1.0
* **Git Commit:** ${GIT_COMMIT_INFO}
* **Session ID:** test-session-id
* **Operating System:** test-platform v20.0.0
* **Sandbox Environment:** gemini-test
* **Model Version:** gemini-pro
* **Memory Usage:** 100 MB
* **IDE Client:** VS Code & Extensions
`;
    const expectedUrl =
      'https://github.com/google-gemini/gemini-cli/issues/new?template=bug_report.yml&title=Bug%20with%20special%20chars%3A%20%26%20%3C%20%3E%20%22&info=' +
      encodeURIComponent(expectedInfo);

    expect(open).toHaveBeenCalledWith(expectedUrl);
  });
});
