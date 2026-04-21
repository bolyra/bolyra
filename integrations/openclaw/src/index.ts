// OpenClaw adapter for Bolyra — ZKP-native agent trust verification
export {
  createBolyraPlugin,
  verifyAgent,
  computeTrustScore,
  scoreToGrade,
  buildDid,
} from './adapter';

export type {
  TrustVerificationResult,
  TrustGrade,
  OpenClawPlugin,
  BolyraOpenClawConfig,
  VerificationPoint,
} from './types';
