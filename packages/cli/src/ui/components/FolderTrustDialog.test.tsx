import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderWithProviders } from '../../test-utils/renderWithProviders.js';
import { FolderTrustDialog, FolderTrustChoice } from './FolderTrustDialog.js';
import { waitFor } from '@testing-library/react';

// Mock process.exit
const mockedExit = vi.fn();
beforeEach(() => {
  vi.stubGlobal('process', {
    ...process,
    exit: mockedExit,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  mockedExit.mockClear();
});

describe('FolderTrustDialog', () => {
  it('should render trust options', () => {
    const { lastFrame } = renderWithProviders(
      <FolderTrustDialog onSelect={vi.fn()} />,
    );

    expect(lastFrame()).toContain('Do you trust this folder?');
    expect(lastFrame()).toContain('Trust folder');
    expect(lastFrame()).toContain('Trust parent folder');
    expect(lastFrame()).toContain("Don't trust");
  });

  it('should display restart message when isRestarting is true', () => {
    const { lastFrame } = renderWithProviders(
      <FolderTrustDialog onSelect={vi.fn()} isRestarting={true} />,
    );

    expect(lastFrame()).toContain(
      'Gemini CLI is restarting to apply changes...',
    );
  });

  it('should not respond to "r" key press since manual restart is no longer supported', async () => {
    const { stdin } = renderWithProviders(
      <FolderTrustDialog onSelect={vi.fn()} isRestarting={true} />,
    );

    stdin.write('r');

    await waitFor(() => {
      expect(mockedExit).not.toHaveBeenCalled();
    });
  });

  it('should call onSelect when escape is pressed', async () => {
    const onSelect = vi.fn();
    const { stdin } = renderWithProviders(
      <FolderTrustDialog onSelect={onSelect} />,
    );

    stdin.write('\u001b'); // Escape key

    await waitFor(() => {
      expect(onSelect).toHaveBeenCalledWith(FolderTrustChoice.DO_NOT_TRUST);
    });
  });
});