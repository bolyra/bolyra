export declare const ORG_ID_PATTERN: RegExp;
export declare const TOKEN_PATTERN: RegExp;
export declare const MAX_TENANTS_BYTES: number;
export declare function hasDuplicateKey(text: string): boolean;
export declare function checkTenants(raw: string | undefined): { ok: boolean; errors: string[]; warnings: string[]; bytes: number; orgs: string[] };
