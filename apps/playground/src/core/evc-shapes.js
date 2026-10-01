/** EVC wire shapes extracted at build time (see build/spec-extract.mjs); injected via esbuild define. */
export const EVC_SHAPES = __EVC_SHAPES__;
export function shapeById(id) {
  const map = { 'request-example': EVC_SHAPES.request.example, 'request-schema': EVC_SHAPES.request.schema, 'real-request': EVC_SHAPES.realRequest.json, 'verdict-allow': EVC_SHAPES.verdict.allow, 'verdict-consume': EVC_SHAPES.verdict.allowConsume, 'verdict-deny': EVC_SHAPES.verdict.deny, 'verdict-schema': EVC_SHAPES.verdict.schema };
  return map[id];
}
