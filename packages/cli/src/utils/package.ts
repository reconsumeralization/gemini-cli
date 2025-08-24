/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  readPackageUp,
  type PackageJson as BasePackageJson,
} from 'read-package-up';
// import { fileURLToPath } from 'url'; // Not needed with current approach
import * as path from 'path';

export type PackageJson = BasePackageJson & {
  config?: {
    sandboxImageUri?: string;
  };
};

const __filename = process.argv[1] || '';
const __dirname = path.dirname(__filename);

let packageJson: PackageJson | undefined;

export async function getPackageJson(): Promise<PackageJson | undefined> {
  if (packageJson) {
    return packageJson;
  }

  const result = await readPackageUp({ cwd: __dirname });
  if (!result) {
    // TODO: Maybe bubble this up as an error.
    return;
  }

  packageJson = result.packageJson;
  return packageJson;
}
