#!/usr/bin/env node
// inline-how.mjs — generate landing/video-how-it-works.html (the production page) from
// the dev sources: animations.jsx + system.jsx + scenes_how.jsx + timeline_how.jsx are
// inlined verbatim into ONE <script type="text/babel"> block, so the page has no
// external JSX and no analytics tag.
//
//   node landing/video/inline-how.mjs          # writes landing/video-how-it-works.html
//   node landing/video/inline-how.mjs --check  # exits 1 if the committed page drifts
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(here, '..', 'video-how-it-works.html');
const parts = ['animations.jsx', 'system.jsx', 'scenes_how.jsx', 'timeline_how.jsx'];

const banner = (name) =>
  `// ═══════════════════════════════════════════════════════════════════════════\n// ${name}\n// ═══════════════════════════════════════════════════════════════════════════\n`;

const body = parts
  .map((p) => banner(p) + fs.readFileSync(path.join(here, p), 'utf8').replace(/<\/script/gi, '<\\/script'))
  .join('\n\n');

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>How Bolyra Works</title>
<meta name="description" content="58-second interactive walkthrough: an operator signs a mandate, a relying party's gate verifies it before any payment logic runs, and every decision gets a signed receipt. Play, pause, scrub.">
<meta property="og:title" content="How Bolyra Works">
<meta property="og:description" content="Mandate in, verdict out, receipt signed. The question a relying party's gate asks, its checks in order, and where it applies.">
<meta property="og:type" content="video.other">
<meta property="og:url" content="https://bolyra.ai/video-how-it-works">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230a0c10'/%3E%3Cpath d='M32 10 14 17v15c0 11 7.7 20.3 18 24 10.3-3.7 18-13 18-24V17L32 10Z' stroke='%236366f1' stroke-width='4' stroke-linejoin='round' fill='rgba(99,102,241,0.15)'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
<style>
  html, body { margin: 0; padding: 0; height: 100%; background: #0a0c10; overflow: hidden; }
  #video-root { position: fixed; inset: 0; }
</style>
</head>
<body>
<div id="video-root"></div>

<script src="https://unpkg.com/react@18.3.1/umd/react.production.min.js" integrity="sha384-DGyLxAyjq0f9SPpVevD6IgztCFlnMF6oW/XQGmfe+IsZ8TqEiDrcHkMLKI6fiB/Z" crossorigin="anonymous"></script>
<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js" integrity="sha384-gTGxhz21lVGYNMcdJOyq01Edg0jhn/c22nsx0kyqP0TxaV5WVdsSH1fSDUf5YJj1" crossorigin="anonymous"></script>
<script src="https://unpkg.com/@babel/standalone@7.29.0/babel.min.js" integrity="sha384-m08KidiNqLdpJqLq95G/LEi8Qvjl/xUYll3QILypMoQ65QorJ9Lvtp2RXYGBFj1y" crossorigin="anonymous"></script>

<script type="text/babel">
${body}
</script>
</body>
</html>
`;

if (process.argv.includes('--check')) {
  const current = fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '';
  if (current !== html) {
    console.error(`DRIFT: ${path.relative(process.cwd(), out)} differs from its sources — run node landing/video/inline-how.mjs`);
    process.exit(1);
  }
  console.log('OK: video-how-it-works.html matches its sources');
} else {
  fs.writeFileSync(out, html);
  console.log(`wrote ${path.relative(process.cwd(), out)} (${html.length} bytes)`);
}
