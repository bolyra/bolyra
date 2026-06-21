# Teach Session: Animated Launch Video Import & Deployment

## 1. The Problem
- [x] Why the launch videos exist as a separate design artifact (Claude Design handoff bundle)
- [x] Why 2 of the 8 videos were missing from bolyra.ai while 6 were already live
- [x] Why each video page must be self-contained (single HTML file with all JS inlined)

## 2. The Solution
- [x] The architecture: Stage/Sprite/Timeline animation framework + system.jsx primitives + per-video scene files
- [x] Why the production pages inline everything vs the dev pages using separate `<script src>` imports
- [x] How deploy.sh works: S3 upload + CloudFront invalidation + post-deploy verification gate
- [x] Why both `.html` and extensionless versions are uploaded to S3 (e.g. `video-frameworks.html` AND `video-frameworks`)
- [x] What the verify.sh post-deploy gate actually checks and why it's non-negotiable

## 3. The Broader Context
- [x] How 8 launch videos map to Bolyra's product story (each video = one feature pillar)
- [x] Why the "Why Not OAuth?" video matters strategically for positioning
- [x] The deployment infrastructure: S3 + CloudFront static site, no build step, no framework
