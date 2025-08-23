/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * vitest unit tests for sandbox parsing and safe spawn helpers
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as child from 'node:child_process';

// import named helpers for testing
import {
  parseAndFilterSandboxEnv,
  buildSafeEnv,
  parseCommandString,
  safeSpawnProxy,
  validateSandboxMounts,
  isValidEnvKey,
  isSafeEnvValue,
} from './sandbox_helpers.js';

vi.mock('node:child_process', () => ({
  spawn: vi.fn(() => ({
    on: vi.fn(),
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    pid: 12345,
  })),
}));

describe('sandbox_helpers', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // clear env changes between tests
    delete process.env['GEMINI_SANDBOX_PROXY_COMMAND'];
    delete process.env['SANDBOX_ENV'];
  });

  it('parseCommandString respects quoted tokens', () => {
    const s = '/usr/bin/socat "TCP-LISTEN:9999,bind=127.0.0.1,reuseaddr" -';
    const tokens = parseCommandString(s);
    expect(tokens[0]).toBe('/usr/bin/socat');
    expect(tokens[1]).toBe('TCP-LISTEN:9999,bind=127.0.0.1,reuseaddr');
    expect(tokens[2]).toBe('-');
  });

  it('parseAndFilterSandboxEnv rejects dangerous values', () => {
    const raw = 'GOOD=hello,EVIL=1;rm -rf /,BAD2=`echo hi`,EMPTY=,VALID2=ok.value';
    const parsed = parseAndFilterSandboxEnv(raw);
    expect(parsed).toHaveProperty('GOOD');
    expect(parsed['GOOD']).toBe('hello');
    expect(parsed).not.toHaveProperty('EVIL');
    expect(parsed).not.toHaveProperty('BAD2');
    expect(parsed).not.toHaveProperty('EMPTY'); // empty values are treated as absent
    expect(parsed).toHaveProperty('VALID2');
    expect(parsed['VALID2']).toBe('ok.value');
  });

  it('buildSafeEnv drops dangerous parent env vars', () => {
    const parent = {
      PATH: '/usr/bin',
      LD_PRELOAD: '/tmp/mal.so',
      IFS: ';',
      LANG: 'en_US.UTF-8',
      HOME: '/home/test',
      SANDBOX_ENV: 'S1=one,GOOD=ok',
    } as NodeJS.ProcessEnv;
    const safe = buildSafeEnv(parent);
    expect(safe['PATH']).toBeDefined();
    expect(safe['LANG']).toBe('en_US.UTF-8');
    expect(safe['HOME']).toBe('/home/test');
    expect(safe['LD_PRELOAD']).toBeUndefined();
    expect(safe['IFS']).toBeUndefined();
    expect(safe['S1']).toBe('one');
    expect(safe['GOOD']).toBe('ok');
  });

  it('safeSpawnProxy spawns with shell:false and tokenized args for plain string', () => {
    process.env['GEMINI_SANDBOX_PROXY_COMMAND'] = '/usr/bin/socat "ARG WITH SPACE" -';
    const cp = safeSpawnProxy();
    // spawn must have been called
    expect(vi.mocked(child.spawn)).toHaveBeenCalled();
    const call = vi.mocked(child.spawn).mock.calls[0];
    const [cmd, args, opts] = call;
    expect(cmd).toBe('/usr/bin/socat');
    expect(Array.isArray(args)).toBe(true);
    expect(args[0]).toBe('ARG WITH SPACE');
    expect(opts && opts.shell).toBe(false);
    // cp should be returned (mock)
    expect(cp).toBeDefined();
  });

  it('safeSpawnProxy accepts JSON array form', () => {
    process.env['GEMINI_SANDBOX_PROXY_COMMAND'] = '["/usr/bin/echo", "hello", "world"]';
    const cp = safeSpawnProxy();
    expect(vi.mocked(child.spawn)).toHaveBeenCalled();
    const [cmd, args, opts] = vi.mocked(child.spawn).mock.calls[0];
    expect(cmd).toBe('/usr/bin/echo');
    expect(args).toEqual(['hello', 'world']);
    expect(opts.shell).toBe(false);
    expect(cp).toBeDefined();
  });
});

describe('Information Disclosure Prevention', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // Clear sensitive environment variables between tests
    delete process.env['GEMINI_API_KEY'];
    delete process.env['GOOGLE_API_KEY'];
    delete process.env['SANDBOX_ENV'];
  });

  it('filters sensitive environment variables from SANDBOX_ENV', () => {
    const raw = 'SAFE_VAR=hello,GEMINI_API_KEY=secret123,GOOGLE_API_KEY=secret456,ANOTHER_SAFE=test';
    const parsed = parseAndFilterSandboxEnv(raw);
    expect(parsed).toHaveProperty('SAFE_VAR');
    expect(parsed).toHaveProperty('ANOTHER_SAFE');
    expect(parsed).not.toHaveProperty('GEMINI_API_KEY');
    expect(parsed).not.toHaveProperty('GOOGLE_API_KEY');
    expect(parsed['SAFE_VAR']).toBe('hello');
    expect(parsed['ANOTHER_SAFE']).toBe('test');
  });

  it('filters sensitive environment variables with pattern matching', () => {
    const raw = 'USER_TOKEN=abc123,PASSWORD=secret,DATABASE_URL=postgres://...';
    const parsed = parseAndFilterSandboxEnv(raw);
    expect(parsed).not.toHaveProperty('USER_TOKEN');
    expect(parsed).not.toHaveProperty('PASSWORD');
    expect(parsed).not.toHaveProperty('DATABASE_URL');
  });

  it('buildSafeEnv filters sensitive parent environment variables', () => {
    const parent = {
      PATH: '/usr/bin',
      LANG: 'en_US.UTF-8',
      GEMINI_API_KEY: 'secret-key-123',
      GOOGLE_API_KEY: 'google-secret-456',
      AWS_ACCESS_KEY_ID: 'aws-key',
      GITHUB_TOKEN: 'github-token',
      SAFE_VAR: 'this-is-safe',
    } as NodeJS.ProcessEnv;

    const safe = buildSafeEnv(parent);

    // Safe variables should be preserved
    expect(safe['PATH']).toBeDefined();
    expect(safe['LANG']).toBe('en_US.UTF-8');

    // Sensitive variables should be filtered out
    expect(safe['GEMINI_API_KEY']).toBeUndefined();
    expect(safe['GOOGLE_API_KEY']).toBeUndefined();
    expect(safe['AWS_ACCESS_KEY_ID']).toBeUndefined();
    expect(safe['GITHUB_TOKEN']).toBeUndefined();
  });

  it('validateSandboxMounts allows only safe paths', () => {
    const mounts = '/usr/bin,/tmp,/home/user/secret,/etc/passwd,/bin';
    const validMounts = validateSandboxMounts(mounts);

    expect(validMounts).toContain('/usr/bin');
    expect(validMounts).toContain('/tmp');
    expect(validMounts).toContain('/bin');
    expect(validMounts).not.toContain('/home/user/secret');
    expect(validMounts).not.toContain('/etc/passwd');
  });

  it('validateSandboxMounts handles complex mount specifications', () => {
    const mounts = '/usr/bin:/usr/bin:ro,/tmp:/tmp:rw,/unsafe/path:/unsafe';
    const validMounts = validateSandboxMounts(mounts);

    expect(validMounts).toContain('/usr/bin:/usr/bin:ro');
    expect(validMounts).toContain('/tmp:/tmp:rw');
    expect(validMounts).not.toContain('/unsafe/path:/unsafe');
  });

  it('validateSandboxMounts returns empty array for undefined input', () => {
    const validMounts = validateSandboxMounts(undefined);
    expect(validMounts).toEqual([]);
  });

  it('validateSandboxMounts normalizes Windows paths', () => {
    const mounts = 'C:\\Windows\\System32';
    const validMounts = validateSandboxMounts(mounts);
    expect(validMounts).toEqual([]); // Should be filtered out
  });

  it('buildSafeEnv preserves essential system variables', () => {
    const parent = {
      PATH: '/usr/bin:/bin',
      LANG: 'en_US.UTF-8',
      HOME: '/home/user',
      TERM: 'xterm-256color',
      SHELL: '/bin/bash',
      USER: 'testuser',
      LOGNAME: 'testuser',
      LC_ALL: 'en_US.UTF-8',
      LC_CTYPE: 'UTF-8',
    } as NodeJS.ProcessEnv;

    const safe = buildSafeEnv(parent);

    expect(safe['PATH']).toBe('/usr/bin:/bin');
    expect(safe['LANG']).toBe('en_US.UTF-8');
    expect(safe['HOME']).toBe('/home/user');
    expect(safe['TERM']).toBe('xterm-256color');
    expect(safe['SHELL']).toBe('/bin/bash');
    expect(safe['USER']).toBe('testuser');
    expect(safe['LOGNAME']).toBe('testuser');
    expect(safe['LC_ALL']).toBe('en_US.UTF-8');
    expect(safe['LC_CTYPE']).toBe('UTF-8');
  });

  it('buildSafeEnv filters out dangerous environment variables', () => {
    const parent = {
      PATH: '/usr/bin',
      LD_PRELOAD: '/tmp/mal.so',
      BASH_ENV: '/tmp/bash_env',
      ENV: '/tmp/env',
      IFS: ':',
      NODE_OPTIONS: '--inspect',
    } as NodeJS.ProcessEnv;

    const safe = buildSafeEnv(parent);

    expect(safe['PATH']).toBeDefined();
    expect(safe['LD_PRELOAD']).toBeUndefined();
    expect(safe['BASH_ENV']).toBeUndefined();
    expect(safe['ENV']).toBeUndefined();
    expect(safe['IFS']).toBeUndefined();
    expect(safe['NODE_OPTIONS']).toBeUndefined();
  });
});

describe('Environment Variable Validation', () => {
  describe('isValidEnvKey', () => {
    it('accepts valid environment variable names', () => {
      const validKeys = [
        'PATH',
        'HOME',
        'LANG',
        'USER',
        'TERM',
        'SHELL',
        'EDITOR',
        'PAGER',
        'TZ',
        'LC_ALL',
        'HTTP_PROXY',
        'HTTPS_PROXY',
        'NO_PROXY',
        'DOCKER_HOST',
        'KUBECONFIG',
        'DATABASE_URL',
        'REDIS_URL',
        'API_KEY',
        'SECRET_KEY',
        'DEBUG',
        'VERBOSE',
        'NODE_ENV'
      ];

      validKeys.forEach(key => {
        expect(isValidEnvKey(key)).toBe(true);
      });
    });

    it('rejects invalid environment variable names', () => {
      const invalidKeys = [
        '',           // empty string
        ' ',          // space only
        '\t',         // tab only
        '123START',   // starts with number
        'CONTAINS SPACE',  // contains space
        'HAS-DASH',   // contains dash
        'has.dot',    // contains dot
        'has/slash',  // contains slash
        'has\\backslash', // contains backslash
        'has"quote',  // contains quote
        "has'quote",  // contains single quote
        'has=equals', // contains equals
        'TOO_LONG_KEY_' + 'A'.repeat(250), // too long
        'a'.repeat(256), // exactly 256 chars (should be invalid)
        'UNDEFINED',  // reserved word
        'NULL',       // reserved word
        'true',       // boolean literal
        'false'       // boolean literal
      ];

      invalidKeys.forEach(key => {
        expect(isValidEnvKey(key)).toBe(false);
      });
    });

    it('rejects null and undefined values', () => {
      expect(isValidEnvKey(null as unknown as string)).toBe(false);
      expect(isValidEnvKey(undefined as unknown as string)).toBe(false);
    });

    it('accepts single character keys', () => {
      expect(isValidEnvKey('A')).toBe(true);
      expect(isValidEnvKey('Z')).toBe(true);
      expect(isValidEnvKey('a')).toBe(true);
      expect(isValidEnvKey('z')).toBe(true);
    });

    it('accepts keys with underscores', () => {
      expect(isValidEnvKey('VALID_KEY')).toBe(true);
      expect(isValidEnvKey('another_valid_key')).toBe(true);
      expect(isValidEnvKey('_STARTS_WITH_UNDERSCORE')).toBe(true);
      expect(isValidEnvKey('ENDS_WITH_UNDERSCORE_')).toBe(true);
    });

    it('accepts keys with numbers after first character', () => {
      expect(isValidEnvKey('KEY1')).toBe(true);
      expect(isValidEnvKey('key123')).toBe(true);
      expect(isValidEnvKey('A1B2C3')).toBe(true);
    });
  });

  describe('isSafeEnvValue', () => {
    it('accepts safe environment variable values', () => {
      const safeValues = [
        'hello',
        'world123',
        '/usr/bin:/bin:/usr/local/bin',
        'en_US.UTF-8',
        'xterm-256color',
        '/home/user',
        'testuser',
        '123',
        'true',
        'false',
        'production',
        'development',
        'http://localhost:3000',
        'https://api.example.com',
        'postgres://user:pass@localhost:5432/db',
        'redis://localhost:6379',
        'file:///tmp/cache',
        'npm_config_cache=/tmp/npm-cache',
        'DOCKER_TLS_VERIFY=1',
        'no_proxy=localhost,127.0.0.1',
        'DEBUG=*',
        'VERBOSE=1'
      ];

      safeValues.forEach(value => {
        expect(isSafeEnvValue(value)).toBe(true);
      });
    });

    it('rejects dangerous environment variable values', () => {
      const dangerousValues = [
        'value; rm -rf /',           // command injection with semicolon
        'value && evil',             // command injection with AND
        'value || bad',              // command injection with OR
        'value | cat /etc/passwd',   // pipe injection
        'value`rm -rf /`',           // backtick injection
        'value$(rm -rf /)',          // command substitution injection
        'value${USER}',              // variable expansion
        'value$((1+1))',             // arithmetic expansion
        'value<(evil)',              // process substitution
        'value>(output)',            // process substitution
        'value& background',         // background process
        'value; background &',       // background process with semicolon
        'value > /dev/null',         // redirection to device
        'value < /etc/passwd',       // redirection from sensitive file
        'value >> /etc/hosts',       // append redirection to system file
        'value 2>&1',                // stderr to stdout redirection
        'value 1>&2',                // stdout to stderr redirection
        'value>&2',                  // combined redirection
        'value>>&2',                 // combined append redirection
        'value|& cat',               // pipe with stderr
        'value;& echo',              // multiple commands with semicolon
        'value&& echo',              // multiple commands with AND
        'value|| echo',              // multiple commands with OR
        'value;;; echo',             // multiple semicolons
        'value&&& echo',             // multiple ampersands
        'value||| echo',             // multiple pipes
        'value;;; echo'              // multiple semicolons
      ];

      dangerousValues.forEach(value => {
        expect(isSafeEnvValue(value)).toBe(false);
      });
    });

    it('rejects values that are too long', () => {
      const longValue = 'A'.repeat(5000); // Much longer than 4096 limit
      expect(isSafeEnvValue(longValue)).toBe(false);
    });

    it('rejects null and undefined values', () => {
      expect(isSafeEnvValue(null as unknown as string)).toBe(false);
      expect(isSafeEnvValue(undefined as unknown as string)).toBe(false);
    });

    it('accepts empty string', () => {
      expect(isSafeEnvValue('')).toBe(true);
    });

    it('accepts values exactly at length limit', () => {
      const exactly4096 = 'A'.repeat(4096);
      expect(isSafeEnvValue(exactly4096)).toBe(true);
    });

    it('rejects values over length limit', () => {
      const over4096 = 'A'.repeat(4097);
      expect(isSafeEnvValue(over4096)).toBe(false);
    });

    it('handles special characters in safe contexts', () => {
      const safeSpecialValues = [
        'hello world',              // spaces
        'hello\tworld',             // tabs
        'hello\nworld',             // newlines
        'hello\rworld',             // carriage returns
        'hello:world',              // colons
        'hello@world.com',          // at symbol
        'hello.world',              // dot
        'hello-world',              // dash
        'hello_world',              // underscore
        'hello+world',              // plus
        'hello=world',              // equals (in value context)
        'hello?world',              // question mark
        'hello#world',              // hash
        'hello$world',              // dollar (not followed by special chars)
        'hello%world',              // percent
        'hello^world',              // caret
        'hello&world',              // ampersand (not followed by another &)
        'hello*world',              // asterisk
        'hello(world)',             // parentheses
        'hello[world]',             // brackets
        'hello{world}',             // braces
        'hello|world',              // pipe (single)
        'hello;world',              // semicolon (single)
        'hello\'world\'',           // single quotes
        'hello"world"',             // double quotes
        'hello\\world',             // backslash
        'hello/world',              // forward slash
        'hello\\world',             // backslash
        'C:\\Windows\\System32',    // Windows path
        '/usr/local/bin/node',      // Unix path
        '192.168.1.1',              // IP address
        'example.com:8080',         // host:port
        'file:///path/to/file',     // file URI
        'data:text/plain;base64,SGVsbG8=', // data URI
      ];

      safeSpecialValues.forEach(value => {
        expect(isSafeEnvValue(value)).toBe(true);
      });
    });

    it('rejects dangerous shell metacharacters', () => {
      const dangerousMetaChars = [
        ';', '&&', '||', '|', '&', '`', '$', '(', ')', '<', '>', '<<', '>>',
        '2>&1', '1>&2', '>&', '<&', '>>', '<<', '<<<', '&>', '>|', '<>',
        '&>>', '&>', '&&&', '|||', ';;;'
      ];

      dangerousMetaChars.forEach(char => {
        const dangerousValue = `prefix${char}dangerous`;
        expect(isSafeEnvValue(dangerousValue)).toBe(false);
      });
    });

    it('rejects dangerous command patterns', () => {
      const dangerousPatterns = [
        '/dev/null',
        '/dev/zero',
        '/dev/random',
        '/dev/urandom',
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/hosts',
        '/etc/fstab',
        '/root/.ssh',
        'authorized_keys',
        'id_rsa',
        'id_dsa',
        '.bash_history',
        '.ssh_history'
      ];

      dangerousPatterns.forEach(pattern => {
        const dangerousValue = `/some/path/${pattern}`;
        expect(isSafeEnvValue(dangerousValue)).toBe(false);
      });
    });
  });
});
