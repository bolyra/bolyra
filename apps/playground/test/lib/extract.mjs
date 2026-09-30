/** Shared helpers for tests and the landing gate: pull the bundle out of the built page. */
const MARKER_RE = /<script id="playground-bundle">([\s\S]*?)<\/script>/g;

export function extractBundle(html) {
  const matches = [...html.matchAll(MARKER_RE)];
  if (matches.length !== 1) throw new Error(`expected exactly one playground-bundle marker, found ${matches.length}`);
  return matches[0][1];
}

/** Every external script src in the page (anything with a src= attribute). */
export function externalScripts(html) {
  return [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)].map((m) => m[1]);
}
