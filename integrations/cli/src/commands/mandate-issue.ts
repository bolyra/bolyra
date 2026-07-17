/**
 * bolyra mandate issue — Issue a delegated spend mandate for an agent.
 *
 * The operator signs a Bolyra request binding that authorizes ONE agent to
 * spend within ONE financial tier, for ONE audience, until an expiry, and emits
 * the `bvp/1` presentation the @bolyra/mpp payment gate consumes (the
 * `X-Bolyra-Authorization` header value). This is ISSUANCE, not key management
 * or a wallet: the operator key is supplied by the caller (`--operator-key`, the
 * same Ed25519/Baby-Jubjub key file `bolyra key generate` writes and
 * `bolyra cred create` consumes); this command never generates, stores, or
 * rotates keys, holds funds, or settles payments.
 *
 * Fail closed: any bad input refuses to emit a mandate and exits non-zero.
 * The presentation is written to stdout (pipe-clean); a human-readable summary
 * goes to stderr so stdout can be piped straight into a request header.
 *
 * Classical trust boundary (binding v2): the operator signature binds {agent,
 * audience, program, model, capabilities, expiry} — the spend ceiling rides the
 * signed capability tier, and `expiry` is signature-bound (pinned to the
 * credential expiry), so a presenter cannot re-anchor a later expiry. See
 * @bolyra/mpp's `issueMandate` docs.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import { issueMandate, type FinancialTier, type MandateEncoding } from '@bolyra/mpp';
import { parseExpiry, parseKeyFile } from '../parse';

const HELP = `bolyra mandate issue — Issue a delegated spend mandate for an agent

Emits the bvp/1 presentation the @bolyra/mpp payment gate verifies (the
X-Bolyra-Authorization header value). Issuance only — not key management,
not a wallet, not payment settlement.

Flags:
  --operator-key <path>   Path to the operator private key file (required)
                          (the key from \`bolyra key generate\`)
  --agent <name>          Acting agent identity (required)
  --audience <id>         Payee / project key the mandate is valid for (required)
  --model <name>          Model identifier the credential binds to (required)
  --tier <tier>           Financial tier: small (<$100), medium (<$10k),
                          or unlimited. Provide this OR --max-usd.
  --max-usd <amount>      Max USD spend; mapped to the smallest covering tier.
                          Provide this OR --tier.
  --expiry <duration>     Duration (30d, 1y, 8h) or Unix timestamp (required).
                          Signature-bound in binding v2 (pinned to the credential
                          expiry), so a presenter cannot re-anchor a later expiry.
  --program <name>        Binding program discriminator (default: mpp)
  --nonce <id>            Opaque mandate/delegation id for your own audit
                          (default: random). UNSIGNED and unverified — not a
                          replay nonce and not tamper-evident; a spend mandate
                          is a standing authorization.
  --encoding <fmt>        Presentation encoding: base64url or json
                          (default: base64url)
  --out <path>            Write the presentation to a file (default: stdout)
  --help                  Show this help

Example:
  bolyra mandate issue \\
    --operator-key operator.key \\
    --agent shopper-bot \\
    --audience api.merchant.example \\
    --model opus-4.1 \\
    --tier small \\
    --expiry 30d
`;

export async function run(args: string[]): Promise<void> {
  let values;
  try {
    ({ values } = parseArgs({
      args,
      options: {
        'operator-key': { type: 'string' },
        agent: { type: 'string' },
        audience: { type: 'string' },
        model: { type: 'string' },
        tier: { type: 'string' },
        'max-usd': { type: 'string' },
        expiry: { type: 'string' },
        program: { type: 'string' },
        nonce: { type: 'string' },
        encoding: { type: 'string' },
        out: { type: 'string' },
        help: { type: 'boolean', default: false },
      },
      strict: true,
    }));
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
    return;
  }

  if (values.help) {
    console.log(HELP);
    return;
  }

  const required: Array<[string, string | undefined]> = [
    ['--operator-key', values['operator-key']],
    ['--agent', values.agent],
    ['--audience', values.audience],
    ['--model', values.model],
    ['--expiry', values.expiry],
  ];
  for (const [flag, val] of required) {
    if (!val) {
      console.error(`Error: ${flag} is required`);
      process.exitCode = 2;
      return;
    }
  }

  const hasTier = values.tier !== undefined;
  const hasMaxUsd = values['max-usd'] !== undefined;
  if (hasTier === hasMaxUsd) {
    console.error('Error: provide exactly one of --tier or --max-usd');
    process.exitCode = 2;
    return;
  }

  const encoding = (values.encoding ?? 'base64url') as MandateEncoding;
  if (encoding !== 'base64url' && encoding !== 'json') {
    console.error(`Error: invalid --encoding "${encoding}". Use: base64url, json`);
    process.exitCode = 2;
    return;
  }

  // Read the operator key file (raw 32 bytes or 64 hex chars).
  let operatorKey: Buffer;
  try {
    operatorKey = parseKeyFile(fs.readFileSync(values['operator-key'] as string));
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
    return;
  }

  // Parse expiry — a future-only duration or Unix timestamp (shared with
  // `cred create`), then convert to unix seconds for issuance.
  let expiry: number;
  try {
    expiry = Number(parseExpiry(values.expiry as string));
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
    return;
  }

  try {
    const mandate = await issueMandate({
      operatorPrivateKey: operatorKey,
      agentName: values.agent as string,
      audience: values.audience as string,
      model: values.model as string,
      program: values.program,
      ...(hasTier ? { tier: values.tier as FinancialTier } : { maxUsd: values['max-usd'] }),
      expiry,
      nonce: values.nonce,
      encoding,
    });

    if (values.out) {
      fs.writeFileSync(values.out, mandate.presentation + '\n', 'utf-8');
      console.error(`Mandate presentation written to: ${values.out}`);
    } else {
      // stdout: exactly the presentation, nothing else (pipe-clean).
      process.stdout.write(mandate.presentation + '\n');
    }

    // Human-readable summary → stderr (keeps stdout clean for piping).
    console.error(
      [
        'Issued spend mandate:',
        `  agent:        ${mandate.agentName}`,
        `  audience:     ${mandate.audience}`,
        `  model:        ${mandate.model}`,
        `  program:      ${mandate.program}`,
        `  tier:         ${mandate.tier}`,
        `  capabilities: ${mandate.capabilities.join(', ')}`,
        `  expiry:       ${mandate.expiry} (${new Date(mandate.expiry * 1000).toISOString()})`,
        `  nonce:        ${mandate.nonce}`,
        `  operator key: x=${mandate.operatorPublicKey.x}`,
        `                y=${mandate.operatorPublicKey.y}`,
        '',
        'Configure this operator key as a trusted issuer in your @bolyra/mpp gate:',
        `  trustedOperators: [{ x: "${mandate.operatorPublicKey.x}", y: "${mandate.operatorPublicKey.y}" }]`,
      ].join('\n'),
    );
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}
