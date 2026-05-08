// v0.2 primary surface
export { allow } from "./allow";
export { present } from "./present";
export { verify } from "./verify";

// v0.1 back-compat — opt-in via verify({...acceptLegacyV01: true})
export { verifyV01 } from "./legacy-v01";

// Issuer key resolution
export { staticIssuerResolver, ResolverError } from "./kid-resolver";
export type { IssuerKeyResolver } from "./kid-resolver";

// JWK thumbprint helper (RFC 7638)
export { jwkThumbprint } from "./jwk-thumbprint";

// Status-list helpers
export {
  publishStatusList,
  fetchStatusList,
  setStatusBit,
  readStatusListPayload,
  StatusListIssuerMismatchError,
  StatusListSignatureError,
} from "./status-list";
export type {
  SlotStatus,
  FetchStatusListOpts,
  PublishStatusListOptions,
  StatusListPayload,
} from "./status-list";

// v0.2 types
export type {
  AllowOptions,
  PresentOptions,
  VerifyOptions,
  VerifyResult,
  VerifyFailureReason,
  StatusListChecker,
  StatusListResult,
} from "./types";
