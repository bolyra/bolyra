# Demo: `@bolyra/delegation`

A 4-scene runnable demo + a vhs recording script. Output is a clean ~20s GIF you can drop into cold DMs, Discord posts, or the package README.

## What it shows

1. Human signs a scoped receipt (`agent_alice`, `purchase`, `example.com`, $50 cap, 1h)
2. Agent invokes `purchase($25)` → ✓ ALLOWED
3. Agent invokes `purchase($75)` → ✗ REJECTED (`amount_exceeds_cap`)
4. Agent presents same receipt to `attacker.com` → ✗ REJECTED (`audience_mismatch`)

## Run it (no recording)

From a clean dir:

```bash
mkdir /tmp/bolyra-demo && cd /tmp/bolyra-demo
npm init -y
npm install @bolyra/delegation
curl -O https://raw.githubusercontent.com/bolyra/bolyra/main/delegation/demo/demo.js
node demo.js
```

Or from this repo (uses local `dist/` via the require fallback):

```bash
cd delegation
npm install      # if you haven't already
npm run build    # ensures dist/ exists
node demo/demo.js
```

## Record the GIF

Requires [vhs](https://github.com/charmbracelet/vhs):

```bash
brew install vhs
```

```bash
mkdir /tmp/bolyra-demo && cd /tmp/bolyra-demo
npm init -y
npm install @bolyra/delegation
cp /path/to/bolyra/delegation/demo/demo.js .
cp /path/to/bolyra/delegation/demo/demo.tape .
vhs demo.tape
```

Outputs `demo.gif` in the same dir. To also produce MP4 / WebM, uncomment the corresponding `Output` lines at the top of `demo.tape`.

## Alternatives if you don't have vhs

**asciinema + agg** (if you prefer authentic terminal feel):

```bash
brew install asciinema
cargo install --git https://github.com/asciinema/agg
asciinema rec demo.cast -c "node demo.js"
agg demo.cast demo.gif
```

**QuickTime screen recording** (manual, macOS built-in): Cmd+Shift+5 → record selection → run `node demo.js` → stop. Convert `.mov` to `.gif` via `ffmpeg -i demo.mov -vf "fps=15,scale=1100:-1:flags=lanczos" demo.gif` if needed.

## Notes

- `demo.js` requires `@bolyra/delegation` first, falls back to `../dist`. So it works both from a fresh install AND from inside this repo (after `npm run build`).
- Pacing is built into `demo.js` itself via `setTimeout`, not into `demo.tape`. This means asciinema and QuickTime recordings have the same pacing as vhs.
- The `demo/` directory is excluded from the npm tarball (the package.json `files` allowlist only ships `dist/`, `src/`, `LICENSE`, `NOTICE`, `README.md`).
