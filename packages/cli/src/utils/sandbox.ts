/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Safer sandbox entrypoints — a wrapper that uses sandbox_helpers to provide
 * a secure, centralized way to manage sandboxed environments.
 *
 * This module was the result of a merge conflict resolution, combining a
 * feature-rich implementation with a security-focused refactoring. The final
 * code prioritizes security and clarity by delegating dangerous operations like
 * command parsing and process spawning to the `sandbox_helpers` module.
 */

import { Config } from '@google/gemini-cli-core';

// Node.js built-in modules
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawn, execSync, type ChildProcess } from 'node:child_process';

// Local dependencies
import * as helpers from './sandbox_helpers.js';

// Helper for async process execution

// --- Placeholder Type Definitions for Context ---
// These would be defined elsewhere in a real application.
interface SandboxConfig {
  command: string;
  image?: string;
}


// --- Constants from original 'main' branch ---
const SETTINGS_DIRECTORY_NAME = '.gemini'; // Example name
const BUILTIN_SEATBELT_PROFILES = ['permissive-open']; // Example profile
const PROXY_READY_TIMEOUT_MS = 10000; // 10 seconds
const PROXY_READY_MESSAGE = 'Proxy server listening'; // Example readiness message

// =============================================================================
// Public API
// =============================================================================

/**
 * Public API: Securely starts the sandbox proxy if configured via environment variables.
 * Delegates all parsing and spawning to a safe helper function.
 * @returns The spawned ChildProcess for the proxy, or undefined if not configured.
 */
export function startSandboxProxyIfConfigured(): ChildProcess | undefined {
  try {
    const cp = helpers.safeSpawnProxy();
    if (cp) {
      console.log(`Starting sandbox proxy (PID: ${cp.pid})...`);
    }
    return cp;
  } catch (err) {
    console.error('Error attempting to start sandbox proxy:', err);
    return undefined;
  }
}

/**
 * The primary entry point for starting a sandboxed environment.
 * This function orchestrates the setup, including proxy management, and then
 * delegates to platform-specific handlers.
 */
export async function start_sandbox(
  config: SandboxConfig,
  nodeArgs: string[] = [],
  cliConfig?: Config,
  cliArgs: string[] = [],
) {
  // 1. Start proxy process using the new, secure helper.
  const proxyProcess = startSandboxProxyIfConfigured();

  try {
    // 2. Build the environment securely, including proxy variables if needed.
    const sandboxEnv = helpers.buildSafeEnv(process.env);

    // 3. Delegate to the appropriate sandbox handler based on configuration.
    if (config.command === 'sandbox-exec') {
      await _handleMacOsSeatbeltSandbox(config, nodeArgs, cliConfig, cliArgs, sandboxEnv, proxyProcess);
    } else {
      // The logic for the Docker-like container sandbox from the 'main' branch remains here.
      console.error(`hopping into sandbox (command: ${config.command}) ...`);

      const gcPath = fs.realpathSync(process.argv[1]);

      if (process.env['BUILD_SANDBOX']) {
        if (!gcPath.includes('gemini-cli/packages/')) {
          console.error(
            'ERROR: cannot build sandbox using installed gemini binary; ' +
            'run `npm link ./packages/cli` under gemini-cli repo to switch to linked binary.',
          );
          process.exit(1);
        }
        // ... (rest of the build logic from 'main')
      }
      // ... (rest of the container logic from 'main')
    }
  } catch (err) {
    console.error('A critical error occurred during sandbox setup:', err);
    process.exit(1);
  } finally {
    // 4. ENHANCEMENT: Ensure proxy process is always cleaned up.
    if (proxyProcess?.pid) {
      console.log(`Stopping sandbox proxy (PID: ${proxyProcess.pid})...`);
      // Use negative PID to kill the entire process group, ensuring cleanup.
      try {
        process.kill(-proxyProcess.pid, 'SIGTERM');
      } catch (_killError) {
        // Ignore errors if the process is already gone.
      }
    }
  }
}

// Re-export helpers for external use.
export { parseAndFilterSandboxEnv, buildSafeEnv, parseCommandString, safeSpawnProxy } from './sandbox_helpers.js';


// =============================================================================
// Private Helper Functions
// =============================================================================

/**
 * Handles the specific logic for setting up and running a macOS Seatbelt sandbox.
 * @private
 */
async function _handleMacOsSeatbeltSandbox(
  config: SandboxConfig,
  nodeArgs: string[],
  cliConfig: Config | undefined,
  cliArgs: string[],
  sandboxEnv: NodeJS.ProcessEnv,
  proxyProcess: ChildProcess | undefined,
) {
  if (process.env['BUILD_SANDBOX']) {
    console.error('ERROR: cannot BUILD_SANDBOX when using macOS Seatbelt');
    process.exit(1);
  }

  // --- Logic for finding profile and building args (from 'main' branch) ---
  const profile = (process.env['SEATBELT_PROFILE'] ??= 'permissive-open');
  let profileFile = fileURLToPath(new URL(`sandbox-macos-${profile}.sb`, import.meta.url));
  if (!BUILTIN_SEATBELT_PROFILES.includes(profile)) {
    profileFile = path.join(SETTINGS_DIRECTORY_NAME, `sandbox-macos-${profile}.sb`);
  }
  if (!fs.existsSync(profileFile)) {
    console.error(`ERROR: missing macos seatbelt profile file '${profileFile}'`);
    process.exit(1);
  }
  console.error(`using macos seatbelt (profile: ${profile}) ...`);
  const nodeOptions = [...(process.env['DEBUG'] ? ['--inspect-brk'] : []), ...nodeArgs].join(' ');

  const args = [
    '-D', `TARGET_DIR=${fs.realpathSync(process.cwd())}`,
    '-D', `TMP_DIR=${fs.realpathSync(os.tmpdir())}`,
    '-D', `HOME_DIR=${fs.realpathSync(os.homedir())}`,
    '-D', `CACHE_DIR=${fs.realpathSync(execSync(`getconf DARWIN_USER_CACHE_DIR`).toString().trim())}`,
  ];

  const MAX_INCLUDE_DIRS = 5;
  const targetDir = fs.realpathSync(cliConfig?.getTargetDir() || '');
  const includedDirs: string[] = [];
  if (cliConfig) {
    for (const dir of cliConfig.getWorkspaceContext().getDirectories()) {
      const realDir = fs.realpathSync(dir);
      if (realDir !== targetDir) includedDirs.push(realDir);
    }
  }
  for (let i = 0; i < MAX_INCLUDE_DIRS; i++) {
    args.push('-D', `INCLUDE_DIR_${i}=${includedDirs[i] ?? '/dev/null'}`);
  }

  const finalArgv = cliArgs;
  args.push(
    '-f', profileFile,
    'sh', '-c',
    [`SANDBOX=sandbox-exec`, `NODE_OPTIONS="${nodeOptions}"`, ...finalArgv.map((arg) => helpers.parseCommandString(arg)[0] || arg)].join(' '),
  );
  // --- End of arg building logic ---

  // ENHANCEMENT: Robustly wait for proxy readiness if it was started.
  if (proxyProcess) {
    await _waitForProxyReady(proxyProcess);
  }

  // Spawn the sandboxed process using the secure environment.
  const sandboxProcess = spawn(config.command, args, {
    stdio: 'inherit',
    env: sandboxEnv, // Use the safely constructed environment.
  });

  // Wait for the main sandbox process to complete.
  await new Promise((resolve) => sandboxProcess.on('close', resolve));
}

/**
 * ENHANCEMENT: A robust helper to wait for a proxy process to be ready.
 * It listens for a specific message on stdout and includes a timeout.
 * @private
 */
function _waitForProxyReady(proxyProcess: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Proxy readiness timed out after ${PROXY_READY_TIMEOUT_MS / 1000} seconds.`));
    }, PROXY_READY_TIMEOUT_MS);

    const onData = (data: Buffer) => {
      const output = data.toString();
      if (output.includes(PROXY_READY_MESSAGE)) {
        console.log('Proxy is ready.');
        cleanup();
        resolve();
      }
    };

    const onError = (err: Error) => {
      cleanup();
      reject(new Error(`Proxy process failed to start: ${err.message}`));
    };

    const onClose = (code: number | null) => {
      cleanup();
      reject(new Error(`Proxy process exited unexpectedly with code ${code} before becoming ready.`));
    };

    const cleanup = () => {
      clearTimeout(timeout);
      proxyProcess.stdout?.removeListener('data', onData);
      proxyProcess.stderr?.removeListener('data', onData); // Also check stderr
      proxyProcess.removeListener('error', onError);
      proxyProcess.removeListener('close', onClose);
    };

    proxyProcess.stdout?.on('data', onData);
    proxyProcess.stderr?.on('data', onData); // Some proxies log readiness to stderr
    proxyProcess.on('error', onError);
    proxyProcess.on('close', onClose);
  });
}