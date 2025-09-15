/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi } from 'vitest';
import { render } from 'ink-testing-library';
import { FolderTrustDialog } from './FolderTrustDialog.js';

describe('FolderTrustDialog', () => {
  it('should render the trust dialog', () => {
    const { lastFrame } = render(
      <FolderTrustDialog onSelect={vi.fn()} />,
    );

    expect(lastFrame()).toContain('Folder Trust');
    expect(lastFrame()).toContain('This folder is not trusted');
    expect(lastFrame()).toContain('Use Enter to trust, Escape to skip');
  });

  it('should display restart message when isRestarting is true', () => {
    const { lastFrame } = render(
      <FolderTrustDialog onSelect={vi.fn()} isRestarting={true} />,
    );

    expect(lastFrame()).toContain(
      'Gemini CLI is restarting to apply changes...',
    );
  });

  it('should not display restart message when isRestarting is false', () => {
    const { lastFrame } = render(
      <FolderTrustDialog onSelect={vi.fn()} isRestarting={false} />,
    );

    expect(lastFrame()).not.toContain(
      'Gemini CLI is restarting to apply changes...',
    );
  });
});
