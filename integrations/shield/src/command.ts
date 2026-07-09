/**
 * Split a server command string into argv tokens for shell-less spawn().
 * Respects single/double quotes so paths with spaces survive.
 */
export function splitCommand(command: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let inToken = false;

  for (const ch of command) {
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      inToken = true;
    } else if (/\s/.test(ch)) {
      if (inToken || current) {
        tokens.push(current);
        current = '';
        inToken = false;
      }
    } else {
      current += ch;
      inToken = true;
    }
  }

  if (quote) throw new Error(`Unterminated quote in server command: ${command}`);
  if (inToken || current) tokens.push(current);
  if (tokens.length === 0) throw new Error('Server command is empty');
  return tokens;
}
