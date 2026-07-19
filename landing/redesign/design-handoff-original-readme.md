# Handoff: Bolyra.ai Landing Page

## Overview
Marketing landing page for Bolyra.ai, an AI-agents-for-operations product. Goal: drive demo bookings. Single dark-themed page: nav, hero, product console mockup, stats strip, feature grid, 3-step "how it works", testimonial, CTA, footer.

## Review instructions
Please review this design implementation with Codex (in addition to your own review): assess visual design quality, copy, information hierarchy, accessibility, and implementation approach before/while porting it.

## About the Design Files
`Bolyra Landing.dc.html` is a **design reference created in HTML** — a prototype showing intended look and behavior, not production code to copy directly. Recreate it in the target codebase's environment (React/Next.js etc.) using its established patterns; if no codebase exists yet, choose an appropriate framework. The file uses a proprietary "Design Component" wrapper: the markup lives inside `<x-dc>` with inline styles and `{{ }}` template holes; the data arrays live in the `class Component` script at the bottom. Read both together.

## Fidelity
**High-fidelity.** Colors, typography, spacing, and copy are final-intent. Recreate pixel-perfectly. All copy/stats/testimonial are placeholder positioning invented for the prototype — flagged inline where relevant; confirm with the product owner before shipping.

## Design Tokens
- Background: #0d0c0a (page), #131109 (raised panels), #1d1a15 (selected row)
- Borders/hairlines: #211e19, #2a261f, #38332b
- Text: #ece7df (primary), #c9c1b3 (body on panels), #a39a8c (secondary), #6b6355 (muted/mono)
- Accent: #ff6a4d (coral) — tweakable prop; user previewed #8b7ff0 (violet) as an alternative. Success green: #7a9e6b
- Fonts (Google Fonts): Instrument Serif (display, weight 400, italic accents), Instrument Sans (body/UI), IBM Plex Mono (labels/eyebrows/timestamps)
- Radius: 2px buttons, 4px list rows, 6px console frame; near-square aesthetic
- Type scale: h1 88px/1.02 serif; h2 52px serif; CTA h2 64px; quote 36px italic serif; body 14.5–19px; mono labels 11–12.5px uppercase, letter-spacing 1.2–1.5px

## Layout
Max content width 1160px, 56px horizontal padding. Sections:
1. **Nav** — flex space-between, 26px vertical padding, bottom hairline. Logo "bolyra.ai" serif 26px with coral dot. Links 14.5px muted. Primary button: light bg #ece7df, dark text, 10×20px padding.
2. **Hero** — mono eyebrow "NOW IN PRIVATE BETA" with pulsing coral dot; 88px serif headline with italic coral phrase; below: 460px-max paragraph left, two buttons right (filled coral + outlined), flex gap 64px, aligned to baseline. Radial coral glow (13% opacity) top-right, pointer-events none. Staggered rise-in animation on load (0/.08s/.16s delays, .7s ease, translateY 18px→0).
3. **Console mockup** — bordered frame, fake window chrome (3 dots + mono title), 2-col grid: 260px sidebar (agent list: name, count, status dot; active row bg #1d1a15) + audit trail (rows: mono timestamp 70px col, 8px status dot, message; hairline row dividers).
4. **Stats strip** — full-width hairlines top/bottom, 3-col grid, 52px serif value + 14px label.
5. **Feature grid** — eyebrow + 52px serif h2, then 3×2 grid with 1px gaps (gap-as-border via #211e19 background), cells #0d0c0a, hover #131109. Each: mono number, 19px semibold title, 14.5px body.
6. **How it works** — 2-col: heading left, 3 numbered steps right (34px serif coral number, title, body, hairline dividers).
7. **Quote** — full-width band bg #131109 with hairlines, centered 36px italic serif, attribution below (placeholder).
8. **CTA** — centered 64px serif headline, sub, coral button 18×40px; radial glow behind.
9. **Footer** — flex space-between: serif logo, muted links, mono copyright.

## Interactions & Behavior
- Buttons: coral↔light-bg swap on hover; outlined button border/text → coral on hover. Links: muted → coral on hover.
- Beta dot: 2.4s opacity pulse loop. Load: hero elements stagger-rise.
- Feature cells: bg lightens on hover.
- All hrefs are "#" placeholders — wire real routes.
- Responsive behavior not designed; desktop 1160px+ only. Add breakpoints as needed.

## State Management
None required — static marketing page. Content arrays (agents, trail, stats, features, steps) in the logic class can become props/CMS data.

## Assets
No images/icons; Google Fonts only (Instrument Serif, Instrument Sans, IBM Plex Mono).

## Files
- `Bolyra Landing.dc.html` — full design (template + data)
