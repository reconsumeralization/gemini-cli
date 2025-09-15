/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { Box, Text } from 'ink';
import { Colors } from '../colors.js';

interface FolderTrustDialogProps {
  onSelect: (trust: boolean) => void;
  isRestarting?: boolean;
}

export function FolderTrustDialog({
  onSelect: _onSelect,
  isRestarting = false,
}: FolderTrustDialogProps): React.JSX.Element {
  return (
    <Box
      borderStyle="round"
      borderColor={Colors.Gray}
      flexDirection="column"
      padding={1}
      width="100%"
    >
      <Text bold>Folder Trust</Text>
      <Box marginTop={1}>
        <Text>
          This folder is not trusted. To enable full functionality, you can trust
          this folder.
        </Text>
      </Box>
      <Box marginTop={1}>
        <Text color={Colors.Gray}>
          (Use Enter to trust, Escape to skip)
        </Text>
      </Box>
      {isRestarting && (
        <Box marginLeft={1} marginTop={1}>
          <Text color={Colors.AccentYellow}>
            Gemini CLI is restarting to apply changes...
          </Text>
        </Box>
      )}
    </Box>
  );
}
