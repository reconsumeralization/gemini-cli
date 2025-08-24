/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Security Profile Definitions
 *
 * Defines the 4-tier security model for the Gemini CLI
 */

export enum SecurityProfile {
  BEGINNER = 'beginner',
  STANDARD = 'standard',
  ADVANCED = 'advanced',
  DEVELOPER = 'developer'
}

export enum CommandRisk {
  SAFE = 'safe',
  MEDIUM_RISK = 'medium_risk',
  DANGEROUS = 'dangerous'
}

export interface SecurityConfig {
  profile: SecurityProfile;
  enabled: boolean;
  autoBlockDangerous: boolean;
  requireConfirmation: boolean;
  educationalMode: boolean;
  logSecurityEvents: boolean;
}

export const DEFAULT_SECURITY_CONFIG: Record<SecurityProfile, SecurityConfig> = {
  [SecurityProfile.BEGINNER]: {
    profile: SecurityProfile.BEGINNER,
    enabled: true,
    autoBlockDangerous: true,
    requireConfirmation: true,
    educationalMode: true,
    logSecurityEvents: true
  },
  [SecurityProfile.STANDARD]: {
    profile: SecurityProfile.STANDARD,
    enabled: true,
    autoBlockDangerous: true,
    requireConfirmation: false,
    educationalMode: false,
    logSecurityEvents: true
  },
  [SecurityProfile.ADVANCED]: {
    profile: SecurityProfile.ADVANCED,
    enabled: true,
    autoBlockDangerous: false,
    requireConfirmation: false,
    educationalMode: false,
    logSecurityEvents: false
  },
  [SecurityProfile.DEVELOPER]: {
    profile: SecurityProfile.DEVELOPER,
    enabled: false,
    autoBlockDangerous: false,
    requireConfirmation: false,
    educationalMode: false,
    logSecurityEvents: false
  }
};
