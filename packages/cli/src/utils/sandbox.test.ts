/**
 * vitest unit tests for sandbox parsing and safe spawn helpers
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as child from 'node:child_process';

// import named helpers for testing
import {
  parseAndFilterSandboxEnv,
  buildSafeEnv,
  parseCommandString,
  safeSpawnProxy,
} from './sandbox_helpers';

vi.mock('node:child_process', () => {
  return {
    spawn: vi.fn(() => {
      return { on: vi.fn(), stdout: { on: vi.fn() }, stderr: { on: vi.fn() }, pid: 12345 };
    }),
  };
});

describe('sandbox_helpers', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // clear env changes between tests
    delete process.env.GEMINI_SANDBOX_PROXY_COMMAND;
    delete process.env.SANDBOX_ENV;
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
    expect(parsed.GOOD).toBe('hello');
    expect(parsed).not.toHaveProperty('EVIL');
    expect(parsed).not.toHaveProperty('BAD2');
    expect(parsed).not.toHaveProperty('EMPTY'); // empty values are treated as absent
    expect(parsed).toHaveProperty('VALID2');
    expect(parsed.VALID2).toBe('ok.value');
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
    expect(safe.PATH).toBeDefined();
    expect(safe.LANG).toBe('en_US.UTF-8');
    expect(safe.HOME).toBe('/home/test');
    expect((safe as any).LD_PRELOAD).toBeUndefined();
    expect((safe as any).IFS).toBeUndefined();
    expect(safe.S1).toBe('one');
    expect(safe.GOOD).toBe('ok');
  });

  it('safeSpawnProxy spawns with shell:false and tokenized args for plain string', () => {
    process.env.GEMINI_SANDBOX_PROXY_COMMAND = '/usr/bin/socat "ARG WITH SPACE" -';
    const cp = safeSpawnProxy();
    // spawn must have been called
    expect((child as any).spawn).toHaveBeenCalled();
    const call = (child as any).spawn.mock.calls[0];
    const [cmd, args, opts] = call;
    expect(cmd).toBe('/usr/bin/socat');
    expect(Array.isArray(args)).toBe(true);
    expect(args[0]).toBe('ARG WITH SPACE');
    expect(opts && opts.shell).toBe(false);
    // cp should be returned (mock)
    expect(cp).toBeDefined();
  });

  it('safeSpawnProxy accepts JSON array form', () => {
    process.env.GEMINI_SANDBOX_PROXY_COMMAND = '["/usr/bin/echo", "hello", "world"]';
    const cp = safeSpawnProxy();
    expect((child as any).spawn).toHaveBeenCalled();
    const [cmd, args, opts] = (child as any).spawn.mock.calls[0];
    expect(cmd).toBe('/usr/bin/echo');
    expect(args).toEqual(['hello', 'world']);
    expect(opts.shell).toBe(false);
    expect(cp).toBeDefined();
  });
});

describe('sandbox_helpers security enhancements', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('parseAndFilterSandboxEnv filters invalid keys/values and enforces limits', () => {
    const raw = 'GOOD=A;BAD-KEY=b;EMPTY=;INJECT=a;export=foo;TOOLONG=' + 'x'.repeat(5000);
    const env = parseAndFilterSandboxEnv(raw);
    expect(env.GOOD).toBe('A');
    expect(env['BAD-KEY']).toBeUndefined();
    expect(env.EMPTY).toBeUndefined();
    expect(env.INJECT).toBeUndefined();
    expect(env.export).toBeUndefined();
    expect(env.TOOLONG).toBeUndefined();
  });

  it('buildSafeEnv removes dangerous envs and preserves whitelisted ones', () => {
    const parent = {
      PATH: '/usr/bin',
      LANG: 'C',
      HOME: '/home/node',
      TERM: 'xterm-256color',
      GEMINI_API_KEY: 'secret',
      LD_PRELOAD: 'hack',
      HTTPS_PROXY: 'http://proxy:8080',
      SANDBOX_ENV: 'GOOD=Y',
    } as NodeJS.ProcessEnv;
    const safe = buildSafeEnv(parent);
    expect(safe.GEMINI_API_KEY).toBeUndefined();
    expect(safe.LD_PRELOAD).toBeUndefined();
    expect(safe.PATH).toBe('/usr/bin');
    expect(safe.LANG).toBe('C');
    expect(safe.TERM).toBe('xterm-256color');
    expect(safe.GOOD).toBe('Y');
    expect(safe.HTTPS_PROXY).toBe('http://proxy:8080');
  });

  it('parseCommandString respects token and length limits', () => {
    const many = Array.from({ length: 40 }, (_, i) => `t${i}`).join(' ');
    expect(parseCommandString(many)).toEqual([]);

    const longToken = 'a'.repeat(10000);
    expect(parseCommandString(longToken)).toEqual([]);

    const ok = 'cmd "arg with space" b';
    expect(parseCommandString(ok)).toEqual(['cmd', 'arg with space', 'b']);
  });
});
