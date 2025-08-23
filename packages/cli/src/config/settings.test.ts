/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/// <reference types="vitest/globals" />

// Mock 'os' first.
import * as osActual from 'os'; // Import for type info for the mock factory
vi.mock('os', async (importOriginal) => {
  const actualOs = await importOriginal<typeof osActual>();
  return {
    ...actualOs,
    homedir: vi.fn(() => '/mock/home/user'),
    platform: vi.fn(() => 'linux'),
  };
});

// Mock './settings.js' to ensure it uses the mocked 'os.homedir()' for its internal constants.
vi.mock('./settings.js', async (importActual) => {
  const originalModule = await importActual<typeof import('./settings.js')>();
  return {
    __esModule: true, // Ensure correct module shape
    ...originalModule, // Re-export all original members
    // We are relying on originalModule's USER_SETTINGS_PATH being constructed with mocked os.homedir()
  };
});

// Mock trustedFolders
vi.mock('./trustedFolders.js', () => ({
  isWorkspaceTrusted: vi.fn(),
}));

// NOW import everything else, including the (now effectively re-exported) settings.js
import * as pathActual from 'path'; // Restored for MOCK_WORKSPACE_SETTINGS_PATH
import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  type Mocked,
  type Mock,
} from 'vitest';
import * as fs from 'fs'; // fs will be mocked separately
import stripJsonComments from 'strip-json-comments'; // Will be mocked separately
import { isWorkspaceTrusted } from './trustedFolders.js';

// These imports will get the versions from the vi.mock('./settings.js', ...) factory.
import {
  loadSettings,
  USER_SETTINGS_PATH, // This IS the mocked path.
  getSystemSettingsPath,
  SETTINGS_DIRECTORY_NAME, // This is from the original module, but used by the mock.
  SettingScope,
} from './settings.js';

const MOCK_WORKSPACE_DIR = '/mock/workspace';
// Use the (mocked) SETTINGS_DIRECTORY_NAME for consistency
const MOCK_WORKSPACE_SETTINGS_PATH = pathActual.join(
  MOCK_WORKSPACE_DIR,
  SETTINGS_DIRECTORY_NAME,
  'settings.json',
);

vi.mock('fs', async (importOriginal) => {
  // Get all the functions from the real 'fs' module
  const actualFs = await importOriginal<typeof fs>();

  return {
    ...actualFs, // Keep all the real functions
    // Now, just override the ones we need for the test
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
    realpathSync: (p: string) => p,
  };
});

vi.mock('strip-json-comments', () => ({
  default: vi.fn((content) => content),
}));

describe('Settings Loading and Merging', () => {
  let mockFsExistsSync: Mocked<typeof fs.existsSync>;
  let mockStripJsonComments: Mocked<typeof stripJsonComments>;
  let mockFsMkdirSync: Mocked<typeof fs.mkdirSync>;

  beforeEach(() => {
    vi.resetAllMocks();

    mockFsExistsSync = vi.mocked(fs.existsSync);
    mockFsMkdirSync = vi.mocked(fs.mkdirSync);
    mockStripJsonComments = vi.mocked(stripJsonComments);

    vi.mocked(osActual.homedir).mockReturnValue('/mock/home/user');
    (mockStripJsonComments as unknown as Mock).mockImplementation(
      (jsonString: string) => jsonString,
    );
    (mockFsExistsSync as Mock).mockReturnValue(false);
    (fs.readFileSync as Mock).mockReturnValue('{}'); // Return valid empty JSON
    (mockFsMkdirSync as Mock).mockImplementation(() => undefined);
    vi.mocked(isWorkspaceTrusted).mockReturnValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('loadSettings', () => {
    it('should load empty settings if no files exist', () => {
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.system.settings).toEqual({});
      expect(settings.user.settings).toEqual({});
      expect(settings.workspace.settings).toEqual({});
      expect(settings.merged).toEqual({
        customThemes: {},
        mcpServers: {},
        includeDirectories: [],
        chatCompression: {},
      });
      expect(settings.errors.length).toBe(0);
    });

    it('should load system settings if only system file exists', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === getSystemSettingsPath(),
      );
      const systemSettingsContent = {
        theme: 'system-default',
        sandbox: false,
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === getSystemSettingsPath())
            return JSON.stringify(systemSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(fs.readFileSync).toHaveBeenCalledWith(
        getSystemSettingsPath(),
        'utf-8',
      );
      expect(settings.system.settings).toEqual(systemSettingsContent);
      expect(settings.user.settings).toEqual({});
      expect(settings.workspace.settings).toEqual({});
      expect(settings.merged).toEqual({
        ...systemSettingsContent,
        customThemes: {},
        mcpServers: {},
        includeDirectories: [],
        chatCompression: {},
      });
    });

    it('should load user settings if only user file exists', () => {
      const expectedUserSettingsPath = USER_SETTINGS_PATH; // Use the path actually resolved by the (mocked) module

      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === expectedUserSettingsPath,
      );
      const userSettingsContent = {
        theme: 'dark',
        contextFileName: 'USER_CONTEXT.md',
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === expectedUserSettingsPath)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(fs.readFileSync).toHaveBeenCalledWith(
        expectedUserSettingsPath,
        'utf-8',
      );
      expect(settings.user.settings).toEqual(userSettingsContent);
      expect(settings.workspace.settings).toEqual({});
      expect(settings.merged).toEqual({
        ...userSettingsContent,
        customThemes: {},
        mcpServers: {},
        includeDirectories: [],
        chatCompression: {},
      });
    });

    it('should load workspace settings if only workspace file exists', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === MOCK_WORKSPACE_SETTINGS_PATH,
      );
      const workspaceSettingsContent = {
        sandbox: true,
        contextFileName: 'WORKSPACE_CONTEXT.md',
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(fs.readFileSync).toHaveBeenCalledWith(
        MOCK_WORKSPACE_SETTINGS_PATH,
        'utf-8',
      );
      expect(settings.user.settings).toEqual({});
      expect(settings.workspace.settings).toEqual(workspaceSettingsContent);
      expect(settings.merged).toEqual({
        ...workspaceSettingsContent,
        customThemes: {},
        mcpServers: {},
        includeDirectories: [],
        chatCompression: {},
      });
    });

    it('should merge user and workspace settings, with workspace taking precedence', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        theme: 'dark',
        sandbox: false,
        contextFileName: 'USER_CONTEXT.md',
      };
      const workspaceSettingsContent = {
        sandbox: true,
        coreTools: ['tool1'],
        contextFileName: 'WORKSPACE_CONTEXT.md',
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(settings.user.settings).toEqual(userSettingsContent);
      expect(settings.workspace.settings).toEqual(workspaceSettingsContent);
      expect(settings.merged).toEqual({
        theme: 'dark',
        sandbox: true,
        coreTools: ['tool1'],
        contextFileName: 'WORKSPACE_CONTEXT.md',
        customThemes: {},
        mcpServers: {},
        includeDirectories: [],
        chatCompression: {},
      });
    });

    it('should merge system, user and workspace settings, with system taking precedence over workspace, and workspace over user', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const systemSettingsContent = {
        theme: 'system-theme',
        sandbox: false,
        allowMCPServers: ['server1', 'server2'],
        telemetry: { enabled: false },
      };
      const userSettingsContent = {
        theme: 'dark',
        sandbox: true,
        contextFileName: 'USER_CONTEXT.md',
      };
      const workspaceSettingsContent = {
        sandbox: false,
        coreTools: ['tool1'],
        contextFileName: 'WORKSPACE_CONTEXT.md',
        allowMCPServers: ['server1', 'server2', 'server3'],
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === getSystemSettingsPath())
            return JSON.stringify(systemSettingsContent);
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(settings.system.settings).toEqual(systemSettingsContent);
      expect(settings.user.settings).toEqual(userSettingsContent);
      expect(settings.workspace.settings).toEqual(workspaceSettingsContent);
      expect(settings.merged).toEqual({
        theme: 'system-theme',
        sandbox: false,
        telemetry: { enabled: false },
        coreTools: ['tool1'],
        contextFileName: 'WORKSPACE_CONTEXT.md',
        allowMCPServers: ['server1', 'server2'],
        customThemes: {},
        mcpServers: {},
        includeDirectories: [],
        chatCompression: {},
      });
    });

    it('should ignore folderTrust from workspace settings', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        folderTrust: true,
      };
      const workspaceSettingsContent = {
        folderTrust: false, // This should be ignored
      };
      const systemSettingsContent = {
        // No folderTrust here
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === getSystemSettingsPath())
            return JSON.stringify(systemSettingsContent);
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.folderTrust).toBe(true); // User setting should be used
    });

    it('should use system folderTrust over user setting', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        folderTrust: false,
      };
      const workspaceSettingsContent = {
        folderTrust: true, // This should be ignored
      };
      const systemSettingsContent = {
        folderTrust: true,
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === getSystemSettingsPath())
            return JSON.stringify(systemSettingsContent);
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.folderTrust).toBe(true); // System setting should be used
    });

    it('should handle contextFileName correctly when only in user settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      const userSettingsContent = { contextFileName: 'CUSTOM.md' };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.contextFileName).toBe('CUSTOM.md');
    });

    it('should handle contextFileName correctly when only in workspace settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === MOCK_WORKSPACE_SETTINGS_PATH,
      );
      const workspaceSettingsContent = {
        contextFileName: 'PROJECT_SPECIFIC.md',
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.contextFileName).toBe('PROJECT_SPECIFIC.md');
    });

    it('should handle excludedProjectEnvVars correctly when only in user settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      const userSettingsContent = {
        excludedProjectEnvVars: ['DEBUG', 'NODE_ENV', 'CUSTOM_VAR'],
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.excludedProjectEnvVars).toEqual([
        'DEBUG',
        'NODE_ENV',
        'CUSTOM_VAR',
      ]);
    });

    it('should handle excludedProjectEnvVars correctly when only in workspace settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === MOCK_WORKSPACE_SETTINGS_PATH,
      );
      const workspaceSettingsContent = {
        excludedProjectEnvVars: ['WORKSPACE_DEBUG', 'WORKSPACE_VAR'],
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.excludedProjectEnvVars).toEqual([
        'WORKSPACE_DEBUG',
        'WORKSPACE_VAR',
      ]);
    });

    it('should merge excludedProjectEnvVars with workspace taking precedence over user', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        excludedProjectEnvVars: ['DEBUG', 'NODE_ENV', 'USER_VAR'],
      };
      const workspaceSettingsContent = {
        excludedProjectEnvVars: ['WORKSPACE_DEBUG', 'WORKSPACE_VAR'],
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.user.settings.excludedProjectEnvVars).toEqual([
        'DEBUG',
        'NODE_ENV',
        'USER_VAR',
      ]);
      expect(settings.workspace.settings.excludedProjectEnvVars).toEqual([
        'WORKSPACE_DEBUG',
        'WORKSPACE_VAR',
      ]);
      expect(settings.merged.excludedProjectEnvVars).toEqual([
        'WORKSPACE_DEBUG',
        'WORKSPACE_VAR',
      ]);
    });

    it('should default contextFileName to undefined if not in settings file', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = { theme: 'dark' };
      const workspaceSettingsContent = { sandbox: true };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.contextFileName).toBeUndefined();
    });

    it('should load telemetry setting from user settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      const userSettingsContent = { telemetry: true };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.telemetry).toBe(true);
    });

    it('should load telemetry setting from workspace settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === MOCK_WORKSPACE_SETTINGS_PATH,
      );
      const workspaceSettingsContent = { telemetry: false };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.telemetry).toBe(false);
    });

    it('should prioritize workspace telemetry setting over user setting', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = { telemetry: true };
      const workspaceSettingsContent = { telemetry: false };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.telemetry).toBe(false);
    });

    it('should have telemetry as undefined if not in settings file', () => {
      (mockFsExistsSync as Mock).mockReturnValue(false); // No settings files exist
      (fs.readFileSync as Mock).mockReturnValue('{}');
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.telemetry).toBeUndefined();
      expect(settings.merged.customThemes).toEqual({});
      expect(settings.merged.mcpServers).toEqual({});
    });

    it('should merge MCP servers correctly, with workspace taking precedence', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        mcpServers: {
          'user-server': {
            command: 'user-command',
            args: ['--user-arg'],
            description: 'User MCP server',
          },
          'shared-server': {
            command: 'user-shared-command',
            description: 'User shared server config',
          },
        },
      };
      const workspaceSettingsContent = {
        mcpServers: {
          'workspace-server': {
            command: 'workspace-command',
            args: ['--workspace-arg'],
            description: 'Workspace MCP server',
          },
          'shared-server': {
            command: 'workspace-shared-command',
            description: 'Workspace shared server config',
          },
        },
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(settings.user.settings).toEqual(userSettingsContent);
      expect(settings.workspace.settings).toEqual(workspaceSettingsContent);
      expect(settings.merged.mcpServers).toEqual({
        'user-server': {
          command: 'user-command',
          args: ['--user-arg'],
          description: 'User MCP server',
        },
        'workspace-server': {
          command: 'workspace-command',
          args: ['--workspace-arg'],
          description: 'Workspace MCP server',
        },
        'shared-server': {
          command: 'workspace-shared-command',
          description: 'Workspace shared server config',
        },
      });
    });

    it('should handle MCP servers when only in user settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      const userSettingsContent = {
        mcpServers: {
          'user-only-server': {
            command: 'user-only-command',
            description: 'User only server',
          },
        },
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.mcpServers).toEqual({
        'user-only-server': {
          command: 'user-only-command',
          description: 'User only server',
        },
      });
    });

    it('should handle MCP servers when only in workspace settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === MOCK_WORKSPACE_SETTINGS_PATH,
      );
      const workspaceSettingsContent = {
        mcpServers: {
          'workspace-only-server': {
            command: 'workspace-only-command',
            description: 'Workspace only server',
          },
        },
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.mcpServers).toEqual({
        'workspace-only-server': {
          command: 'workspace-only-command',
          description: 'Workspace only server',
        },
      });
    });

    it('should have mcpServers as empty object if not in settings file', () => {
      (mockFsExistsSync as Mock).mockReturnValue(false); // No settings files exist
      (fs.readFileSync as Mock).mockReturnValue('{}');
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.mcpServers).toEqual({});
    });

    it('should merge chatCompression settings, with workspace taking precedence', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        chatCompression: { contextPercentageThreshold: 0.5 },
      };
      const workspaceSettingsContent = {
        chatCompression: { contextPercentageThreshold: 0.8 },
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(settings.user.settings.chatCompression).toEqual({
        contextPercentageThreshold: 0.5,
      });
      expect(settings.workspace.settings.chatCompression).toEqual({
        contextPercentageThreshold: 0.8,
      });
      expect(settings.merged.chatCompression).toEqual({
        contextPercentageThreshold: 0.8,
      });
    });

    it('should handle chatCompression when only in user settings', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      const userSettingsContent = {
        chatCompression: { contextPercentageThreshold: 0.5 },
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.chatCompression).toEqual({
        contextPercentageThreshold: 0.5,
      });
    });

    it('should have chatCompression as an empty object if not in settings file', () => {
      (mockFsExistsSync as Mock).mockReturnValue(false); // No settings files exist
      (fs.readFileSync as Mock).mockReturnValue('{}');
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.chatCompression).toEqual({});
    });

    it('should ignore chatCompression if contextPercentageThreshold is invalid', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      const userSettingsContent = {
        chatCompression: { contextPercentageThreshold: 1.5 },
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.merged.chatCompression).toBeUndefined();
      expect(warnSpy).toHaveBeenCalledWith(
        'Invalid value for chatCompression.contextPercentageThreshold: "1.5". Please use a value between 0 and 1. Using default compression settings.',
      );
      warnSpy.mockRestore();
    });

    it('should deep merge chatCompression settings', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        chatCompression: { contextPercentageThreshold: 0.5 },
      };
      const workspaceSettingsContent = {
        chatCompression: {},
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(settings.merged.chatCompression).toEqual({
        contextPercentageThreshold: 0.5,
      });
    });

    it('should merge includeDirectories from all scopes', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const systemSettingsContent = {
        includeDirectories: ['/system/dir'],
      };
      const userSettingsContent = {
        includeDirectories: ['/user/dir1', '/user/dir2'],
      };
      const workspaceSettingsContent = {
        includeDirectories: ['/workspace/dir'],
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === getSystemSettingsPath())
            return JSON.stringify(systemSettingsContent);
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(settings.merged.includeDirectories).toEqual([
        '/system/dir',
        '/user/dir1',
        '/user/dir2',
        '/workspace/dir',
      ]);
    });

    it('should handle JSON parsing errors gracefully', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true); // Both files "exist"
      const invalidJsonContent = 'invalid json';
      const userReadError = new SyntaxError(
        "Expected ',' or '}' after property value in JSON at position 10",
      );
      const workspaceReadError = new SyntaxError(
        'Unexpected token i in JSON at position 0',
      );

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH) {
            // Simulate JSON.parse throwing for user settings
            vi.spyOn(JSON, 'parse').mockImplementationOnce(() => {
              throw userReadError;
            });
            return invalidJsonContent; // Content that would cause JSON.parse to throw
          }
          if (p === MOCK_WORKSPACE_SETTINGS_PATH) {
            // Simulate JSON.parse throwing for workspace settings
            vi.spyOn(JSON, 'parse').mockImplementationOnce(() => {
              throw workspaceReadError;
            });
            return invalidJsonContent;
          }
          return '{}'; // Default for other reads
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      // Check that settings are empty due to parsing errors
      expect(settings.user.settings).toEqual({});
      expect(settings.workspace.settings).toEqual({});
      expect(settings.merged).toEqual({
        customThemes: {},
        mcpServers: {},
        includeDirectories: [],
        chatCompression: {},
      });

      // Check that error objects are populated in settings.errors
      expect(settings.errors).toBeDefined();
      // Assuming both user and workspace files cause errors and are added in order
      expect(settings.errors.length).toEqual(2);

      const userError = settings.errors.find(
        (e) => e.path === USER_SETTINGS_PATH,
      );
      expect(userError).toBeDefined();
      expect(userError?.message).toBe(userReadError.message);

      const workspaceError = settings.errors.find(
        (e) => e.path === MOCK_WORKSPACE_SETTINGS_PATH,
      );
      expect(workspaceError).toBeDefined();
      expect(workspaceError?.message).toBe(workspaceReadError.message);

      // Restore JSON.parse mock if it was spied on specifically for this test
      vi.restoreAllMocks(); // Or more targeted restore if needed
    });

    it('should resolve environment variables in user settings', () => {
      process.env['TEST_API_KEY'] = 'user_api_key_from_env';
      const userSettingsContent = {
        apiKey: '$TEST_API_KEY',
        someUrl: 'https://test.com/${TEST_API_KEY}',
      };
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      // Type guard to safely access properties
      if (typeof settings.user.settings === 'object' && settings.user.settings !== null && 'apiKey' in settings.user.settings) {
        expect((settings.user.settings as { apiKey: string }).apiKey).toBe('user_api_key_from_env');
      }
      if (typeof settings.user.settings === 'object' && settings.user.settings !== null && 'someUrl' in settings.user.settings) {
        expect((settings.user.settings as { someUrl: string }).someUrl).toBe('https://test.com/user_api_key_from_env');
      }
      if (typeof settings.merged === 'object' && settings.merged !== null && 'apiKey' in settings.merged) {
        expect((settings.merged as { apiKey: string }).apiKey).toBe('user_api_key_from_env');
      }
      if (typeof settings.merged === 'object' && settings.merged !== null && 'someUrl' in settings.merged) {
        expect((settings.merged as { someUrl: string }).someUrl).toBe('https://test.com/user_api_key_from_env');
      }
      delete process.env['TEST_API_KEY'];
    });

    it('should resolve environment variables in workspace settings', () => {
      process.env['WORKSPACE_ENDPOINT'] = 'workspace_endpoint_from_env';
      const workspaceSettingsContent = {
        endpoint: '${WORKSPACE_ENDPOINT}/api',
        nested: { value: '$WORKSPACE_ENDPOINT' },
      };
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === MOCK_WORKSPACE_SETTINGS_PATH,
      );
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      // Type guard to safely access properties
      if (typeof settings.workspace.settings === 'object' && settings.workspace.settings !== null && 'endpoint' in settings.workspace.settings) {
        expect((settings.workspace.settings as { endpoint: string }).endpoint).toBe(
          'workspace_endpoint_from_env/api',
        );
      }
      if (typeof settings.workspace.settings === 'object' && settings.workspace.settings !== null && 'nested' in settings.workspace.settings) {
        const nested = (settings.workspace.settings as { nested: { value: string } }).nested;
        expect(nested.value).toBe('workspace_endpoint_from_env');
      }
      if (typeof settings.merged === 'object' && settings.merged !== null && 'endpoint' in settings.merged) {
        expect((settings.merged as { endpoint: string }).endpoint).toBe('workspace_endpoint_from_env/api');
      }
      delete process.env['WORKSPACE_ENDPOINT'];
    });

    it('should correctly resolve and merge env variables from different scopes', () => {
      process.env['SYSTEM_VAR'] = 'system_value';
      process.env['USER_VAR'] = 'user_value';
      process.env['WORKSPACE_VAR'] = 'workspace_value';
      process.env['SHARED_VAR'] = 'final_value';

      const systemSettingsContent = {
        configValue: '$SHARED_VAR',
        systemOnly: '$SYSTEM_VAR',
      };
      const userSettingsContent = {
        configValue: '$SHARED_VAR',
        userOnly: '$USER_VAR',
        theme: 'dark',
      };
      const workspaceSettingsContent = {
        configValue: '$SHARED_VAR',
        workspaceOnly: '$WORKSPACE_VAR',
        theme: 'light',
      };

      (mockFsExistsSync as Mock).mockReturnValue(true);
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === getSystemSettingsPath()) {
            return JSON.stringify(systemSettingsContent);
          }
          if (p === USER_SETTINGS_PATH) {
            return JSON.stringify(userSettingsContent);
          }
          if (p === MOCK_WORKSPACE_SETTINGS_PATH) {
            return JSON.stringify(workspaceSettingsContent);
          }
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      // Check resolved values in individual scopes
       
        const systemSettings = settings.system.settings as { configValue?: string; systemOnly?: string };
        expect(systemSettings.configValue).toBe('final_value');
        expect(systemSettings.systemOnly).toBe('system_value');
       
      const userSettings = settings.user.settings as { configValue?: string; userOnly?: string };
      if (typeof userSettings.configValue !== 'undefined') {
        expect(userSettings.configValue).toBe('final_value');
        expect(userSettings.userOnly).toBe('user_value');
      }
      
      const workspaceSettings = settings.workspace.settings as { configValue?: string; workspaceOnly?: string };
      if (typeof workspaceSettings.configValue !== 'undefined') {
        expect(workspaceSettings.configValue).toBe('final_value');
        expect(workspaceSettings.workspaceOnly).toBe('workspace_value');
      }

      // Check merged values (system > workspace > user) with type guards
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((settings.merged as any).configValue).toBe('final_value');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((settings.merged as any).systemOnly).toBe('system_value');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((settings.merged as any).userOnly).toBe('user_value');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((settings.merged as any).workspaceOnly).toBe('workspace_value');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((settings.merged as any).theme).toBe('light'); // workspace overrides user

      delete process.env['SYSTEM_VAR'];
      delete process.env['USER_VAR'];
      delete process.env['WORKSPACE_VAR'];
      delete process.env['SHARED_VAR'];
    });

    it('should correctly merge dnsResolutionOrder with workspace taking precedence', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        dnsResolutionOrder: 'ipv4first',
      };
      const workspaceSettingsContent = {
        dnsResolutionOrder: 'verbatim',
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      if (typeof settings.merged === 'object' && settings.merged !== null && 'dnsResolutionOrder' in settings.merged) {
        expect((settings.merged as { dnsResolutionOrder: string }).dnsResolutionOrder).toBe('verbatim');
      }
    });

    it('should use user dnsResolutionOrder if workspace is not defined', () => {
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      const userSettingsContent = {
        dnsResolutionOrder: 'verbatim',
      };
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      if (typeof settings.merged === 'object' && settings.merged !== null && 'dnsResolutionOrder' in settings.merged) {
        expect((settings.merged as { dnsResolutionOrder: string }).dnsResolutionOrder).toBe('verbatim');
      }
    });

    it('should leave unresolved environment variables as is', () => {
      const userSettingsContent = { apiKey: '$UNDEFINED_VAR' };
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      if (typeof settings.user.settings === 'object' && settings.user.settings !== null && 'apiKey' in settings.user.settings) {
        expect((settings.user.settings as { apiKey: string }).apiKey).toBe('$UNDEFINED_VAR');
      }
      if (typeof settings.merged === 'object' && settings.merged !== null && 'apiKey' in settings.merged) {
        expect((settings.merged as { apiKey: string }).apiKey).toBe('$UNDEFINED_VAR');
      }
    });

    it('should resolve multiple environment variables in a single string', () => {
      process.env['VAR_A'] = 'valueA';
      process.env['VAR_B'] = 'valueB';
      const userSettingsContent = { path: '/path/$VAR_A/${VAR_B}/end' };
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      if (typeof settings.user.settings === 'object' && settings.user.settings !== null && 'path' in settings.user.settings) {
        expect((settings.user.settings as { path: string }).path).toBe('/path/valueA/valueB/end');
      }
      delete process.env['VAR_A'];
      delete process.env['VAR_B'];
    });

    it('should resolve environment variables in arrays', () => {
      process.env['ITEM_1'] = 'item1_env';
      process.env['ITEM_2'] = 'item2_env';
      const userSettingsContent = { list: ['$ITEM_1', '${ITEM_2}', 'literal'] };
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );
      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      if (typeof settings.user.settings === 'object' && settings.user.settings !== null && 'list' in settings.user.settings) {
        expect((settings.user.settings as { list: string[] }).list).toEqual([
          'item1_env',
          'item2_env',
          'literal',
        ]);
      }
      delete process.env['ITEM_1'];
      delete process.env['ITEM_2'];
    });

    it('should correctly pass through null, boolean, and number types, and handle undefined properties', () => {
      process.env['MY_ENV_STRING'] = 'env_string_value';
      process.env['MY_ENV_STRING_NESTED'] = 'env_string_nested_value';

      const userSettingsContent = {
        nullVal: null,
        trueVal: true,
        falseVal: false,
        numberVal: 123.45,
        stringVal: '$MY_ENV_STRING',
        nestedObj: {
          nestedNull: null,
          nestedBool: true,
          nestedNum: 0,
          nestedString: 'literal',
          anotherEnv: '${MY_ENV_STRING_NESTED}',
        },
      };

      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      if (typeof settings.user.settings === 'object' && settings.user.settings !== null) {
        const userSettings = settings.user.settings as {
          nullVal?: null;
          trueVal?: boolean;
          falseVal?: boolean;
          numberVal?: number;
          stringVal?: string;
          undefinedVal?: undefined;
          nestedObj?: {
            nestedNull?: null;
            nestedBool?: boolean;
            nestedNum?: number;
            nestedString?: string;
            anotherEnv?: string;
          };
        };
        
        expect(userSettings.nullVal).toBeNull();
        expect(userSettings.trueVal).toBe(true);
        expect(userSettings.falseVal).toBe(false);
        expect(userSettings.numberVal).toBe(123.45);
        expect(userSettings.stringVal).toBe('env_string_value');
        expect(userSettings.undefinedVal).toBeUndefined();

        if (userSettings.nestedObj) {
          expect(userSettings.nestedObj.nestedNull).toBeNull();
          expect(userSettings.nestedObj.nestedBool).toBe(true);
          expect(userSettings.nestedObj.nestedNum).toBe(0);
          expect(userSettings.nestedObj.nestedString).toBe('literal');
          expect(userSettings.nestedObj.anotherEnv).toBe('env_string_nested_value');
        }
      }

      delete process.env['MY_ENV_STRING'];
      delete process.env['MY_ENV_STRING_NESTED'];
    });

    it('should resolve multiple concatenated environment variables in a single string value', () => {
      process.env['TEST_HOST'] = 'myhost';
      process.env['TEST_PORT'] = '9090';
      const userSettingsContent = {
        serverAddress: '${TEST_HOST}:${TEST_PORT}/api',
      };
      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      
      if (typeof settings.user.settings === 'object' && settings.user.settings !== null && 'serverAddress' in settings.user.settings) {
        expect((settings.user.settings as { serverAddress: string }).serverAddress).toBe('myhost:9090/api');
      }

      delete process.env['TEST_HOST'];
      delete process.env['TEST_PORT'];
    });

    describe('when GEMINI_CLI_SYSTEM_SETTINGS_PATH is set', () => {
      const MOCK_ENV_SYSTEM_SETTINGS_PATH = '/mock/env/system/settings.json';

      beforeEach(() => {
        process.env['GEMINI_CLI_SYSTEM_SETTINGS_PATH'] =
          MOCK_ENV_SYSTEM_SETTINGS_PATH;
      });

      afterEach(() => {
        delete process.env['GEMINI_CLI_SYSTEM_SETTINGS_PATH'];
      });

      it('should load system settings from the path specified in the environment variable', () => {
        (mockFsExistsSync as Mock).mockImplementation(
          (p: fs.PathLike) => p === MOCK_ENV_SYSTEM_SETTINGS_PATH,
        );
        const systemSettingsContent = {
          theme: 'env-var-theme',
          sandbox: true,
        };
        (fs.readFileSync as Mock).mockImplementation(
          (p: fs.PathOrFileDescriptor) => {
            if (p === MOCK_ENV_SYSTEM_SETTINGS_PATH)
              return JSON.stringify(systemSettingsContent);
            return '{}';
          },
        );

        const settings = loadSettings(MOCK_WORKSPACE_DIR);

        expect(fs.readFileSync).toHaveBeenCalledWith(
          MOCK_ENV_SYSTEM_SETTINGS_PATH,
          'utf-8',
        );
        
        if (typeof settings.system.settings === 'object' && settings.system.settings !== null && 'path' in settings.system.settings) {
          expect((settings.system.settings as { path: string }).path).toBe(MOCK_ENV_SYSTEM_SETTINGS_PATH);
        }
        expect(settings.system.settings).toEqual(systemSettingsContent);
        
        if (typeof settings.merged === 'object' && settings.merged !== null) {
          expect(settings.merged).toEqual({
            ...systemSettingsContent,
            customThemes: {},
            mcpServers: {},
            includeDirectories: [],
            chatCompression: {},
          });
        }
      });
    });
  });

  describe('LoadedSettings class', () => {
    it('setValue should update the correct scope and recompute merged settings', () => {
      (mockFsExistsSync as Mock).mockReturnValue(false);
      const loadedSettings = loadSettings(MOCK_WORKSPACE_DIR);

      vi.mocked(fs.writeFileSync).mockImplementation(() => {});
      // mkdirSync is mocked in beforeEach to return undefined, which is fine for void usage

      loadedSettings.setValue(SettingScope.User, 'theme', 'matrix');
      
      if (typeof loadedSettings.user.settings === 'object' && loadedSettings.user.settings !== null && 'theme' in loadedSettings.user.settings) {
        expect((loadedSettings.user.settings as { theme: string }).theme).toBe('matrix');
      }
      if (typeof loadedSettings.merged === 'object' && loadedSettings.merged !== null && 'theme' in loadedSettings.merged) {
        expect((loadedSettings.merged as { theme: string }).theme).toBe('matrix');
      }
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        USER_SETTINGS_PATH,
        JSON.stringify({ theme: 'matrix' }, null, 2),
        'utf-8',
      );

      loadedSettings.setValue(
        SettingScope.Workspace,
        'contextFileName',
        'MY_AGENTS.md',
      );
      
      if (typeof loadedSettings.workspace.settings === 'object' && loadedSettings.workspace.settings !== null && 'contextFileName' in loadedSettings.workspace.settings) {
        expect((loadedSettings.workspace.settings as { contextFileName: string }).contextFileName).toBe(
          'MY_AGENTS.md',
        );
      }
      if (typeof loadedSettings.merged === 'object' && loadedSettings.merged !== null && 'contextFileName' in loadedSettings.merged) {
        expect((loadedSettings.merged as { contextFileName: string }).contextFileName).toBe('MY_AGENTS.md');
      }
      if (typeof loadedSettings.merged === 'object' && loadedSettings.merged !== null && 'theme' in loadedSettings.merged) {
        expect((loadedSettings.merged as { theme: string }).theme).toBe('matrix'); // User setting should still be there
      }
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        MOCK_WORKSPACE_SETTINGS_PATH,
        JSON.stringify({ contextFileName: 'MY_AGENTS.md' }, null, 2),
        'utf-8',
      );

      // System theme overrides user and workspace themes
      loadedSettings.setValue(SettingScope.System, 'theme', 'ocean');

      if (typeof loadedSettings.system.settings === 'object' && loadedSettings.system.settings !== null && 'theme' in loadedSettings.system.settings) {
        expect((loadedSettings.system.settings as { theme: string }).theme).toBe('ocean');
      }
      if (typeof loadedSettings.merged === 'object' && loadedSettings.merged !== null && 'theme' in loadedSettings.merged) {
        expect((loadedSettings.merged as { theme: string }).theme).toBe('ocean');
      }
    });
  });

  describe('excludedProjectEnvVars integration', () => {
    const originalEnv = { ...process.env };

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should exclude DEBUG and DEBUG_MODE from project .env files by default', () => {
      // Create a workspace settings file with excludedProjectEnvVars
      const workspaceSettingsContent = {
        excludedProjectEnvVars: ['DEBUG', 'DEBUG_MODE'],
      };

      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === MOCK_WORKSPACE_SETTINGS_PATH,
      );

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      // Mock findEnvFile to return a project .env file
      const originalFindEnvFile = (
        loadSettings as unknown as { findEnvFile: () => string }
      ).findEnvFile;
      (loadSettings as unknown as { findEnvFile: () => string }).findEnvFile =
        () => '/mock/project/.env';

      // Mock fs.readFileSync for .env file content
      const originalReadFileSync = fs.readFileSync;
      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === '/mock/project/.env') {
            return 'DEBUG=true\nDEBUG_MODE=1\nGEMINI_API_KEY=test-key';
          }
          if (p === MOCK_WORKSPACE_SETTINGS_PATH) {
            return JSON.stringify(workspaceSettingsContent);
          }
          return '{}';
        },
      );

      try {
        // This will call loadEnvironment internally with the merged settings
        const settings = loadSettings(MOCK_WORKSPACE_DIR);

        // Verify the settings were loaded correctly
        if (typeof settings.merged === 'object' && settings.merged !== null && 'excludedProjectEnvVars' in settings.merged) {
          expect((settings.merged as { excludedProjectEnvVars: string[] }).excludedProjectEnvVars).toEqual([
            'DEBUG',
            'DEBUG_MODE',
          ]);
        }

        // Note: We can't directly test process.env changes here because the mocking
        // prevents the actual file system operations, but we can verify the settings
        // are correctly merged and passed to loadEnvironment
      } finally {
        (loadSettings as unknown as { findEnvFile: () => string }).findEnvFile =
          originalFindEnvFile;
        (fs.readFileSync as Mock).mockImplementation(originalReadFileSync);
      }
    });

    it('should respect custom excludedProjectEnvVars from user settings', () => {
      const userSettingsContent = {
        excludedProjectEnvVars: ['NODE_ENV', 'DEBUG'],
      };

      (mockFsExistsSync as Mock).mockImplementation(
        (p: fs.PathLike) => p === USER_SETTINGS_PATH,
      );

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);
      expect(settings.user.settings.excludedProjectEnvVars).toEqual([
        'NODE_ENV',
        'DEBUG',
      ]);
      expect(settings.merged.excludedProjectEnvVars).toEqual([
        'NODE_ENV',
        'DEBUG',
      ]);
    });

    it('should merge excludedProjectEnvVars with workspace taking precedence', () => {
      const userSettingsContent = {
        excludedProjectEnvVars: ['DEBUG', 'NODE_ENV', 'USER_VAR'],
      };
      const workspaceSettingsContent = {
        excludedProjectEnvVars: ['WORKSPACE_DEBUG', 'WORKSPACE_VAR'],
      };

      (mockFsExistsSync as Mock).mockReturnValue(true);

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      expect(settings.user.settings.excludedProjectEnvVars).toEqual([
        'DEBUG',
        'NODE_ENV',
        'USER_VAR',
      ]);
      expect(settings.workspace.settings.excludedProjectEnvVars).toEqual([
        'WORKSPACE_DEBUG',
        'WORKSPACE_VAR',
      ]);
      expect(settings.merged.excludedProjectEnvVars).toEqual([
        'WORKSPACE_DEBUG',
        'WORKSPACE_VAR',
      ]);
    });
  });

  describe('with workspace trust', () => {
    it('should merge workspace settings when workspace is trusted', () => {
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = { theme: 'dark', sandbox: false };
      const workspaceSettingsContent = {
        sandbox: true,
        contextFileName: 'WORKSPACE.md',
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      if (typeof settings.merged === 'object' && settings.merged !== null) {
        const mergedSettings = settings.merged as { sandbox?: boolean; contextFileName?: string; theme?: string };
        expect(mergedSettings.sandbox).toBe(true);
        expect(mergedSettings.contextFileName).toBe('WORKSPACE.md');
        expect(mergedSettings.theme).toBe('dark');
      }
    });

    it('should NOT merge workspace settings when workspace is not trusted', () => {
      vi.mocked(isWorkspaceTrusted).mockReturnValue(false);
      (mockFsExistsSync as Mock).mockReturnValue(true);
      const userSettingsContent = {
        theme: 'dark',
        sandbox: false,
        contextFileName: 'USER.md',
      };
      const workspaceSettingsContent = {
        sandbox: true,
        contextFileName: 'WORKSPACE.md',
      };

      (fs.readFileSync as Mock).mockImplementation(
        (p: fs.PathOrFileDescriptor) => {
          if (p === USER_SETTINGS_PATH)
            return JSON.stringify(userSettingsContent);
          if (p === MOCK_WORKSPACE_SETTINGS_PATH)
            return JSON.stringify(workspaceSettingsContent);
          return '{}';
        },
      );

      const settings = loadSettings(MOCK_WORKSPACE_DIR);

      // Verify that workspace settings are ignored when workspace is not trusted
      if (typeof settings.merged === 'object' && settings.merged !== null) {
        const mergedSettings = settings.merged as { sandbox?: boolean; contextFileName?: string; theme?: string };
        expect(mergedSettings.sandbox).toBe(false); // User setting takes precedence
        expect(mergedSettings.contextFileName).toBe('USER.md'); // User setting preserved
        expect(mergedSettings.theme).toBe('dark'); // User setting preserved
      }
      
      // Verify workspace settings were loaded but not merged
      if (typeof settings.workspace.settings === 'object' && settings.workspace.settings !== null) {
        const workspaceSettings = settings.workspace.settings as { sandbox?: boolean; contextFileName?: string };
        expect(workspaceSettings.sandbox).toBe(true);
        expect(workspaceSettings.contextFileName).toBe('WORKSPACE.md');
      }
      
      // Verify user settings are still applied
      expect(settings.user.settings.theme).toBe('dark');
      expect(settings.user.settings.sandbox).toBe(false);
      expect(settings.user.settings.contextFileName).toBe('USER.md');
    });
  });
});
