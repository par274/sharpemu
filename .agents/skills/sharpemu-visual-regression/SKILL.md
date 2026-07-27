---
name: sharpemu-visual-regression
description: Investigate black, blank, frozen, corrupt, missing, or incorrectly colored SharpEmu output and compare two emulator runs, including shader, layout, depth, synchronization, and presentation symptoms. Do not use when no visual claim or run evidence is involved.
---

<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# SharpEmu visual regression

## Inputs

Accept one run ID for diagnosis or before/after run IDs for comparison. Require compatible capture source and resolution before making a direct pixel claim.

## Workflow

1. Prefer emulator-native final-swapchain capture. Treat `window-fallback` as nondeterministic and verify it belongs to the emulator process.
2. Run `visual analyze --run <run-id>` and inspect `visual.json`, every relevant PNG, and `contact-sheet.png` visually.
3. Classify exactly one state: no frame produced; capture failed; blank frame; frozen sequence; changing but visibly incorrect output; or apparently meaningful output.
4. For two runs, run `visual compare --before <before-id> --after <after-id>`. Reject silent baseline replacement and report incompatible source or resolution.
5. Compare luminance, near-black/white percentages, alpha anomalies, difference hash, changed-pixel ratio, and normalized difference. Metrics are evidence, not a correctness oracle.
6. Correlate pixels with `events.jsonl`, logs, command/profile, build fingerprint, shader output, and applicable specifications.
7. Treat `first-host-frame`, splash, and key-art presentation only as host-path evidence; require separate direct guest submission/render evidence for guest-graphics progress.
8. Keep screenshots, raw frames, and contact sheets under `.local/`; never add target-game images to Git.

## Output

Return capture source, frame count, inspected image paths, visible observations, classification, metric deltas, relevant events/logs, comparability limits, and confidence. Never accept a baseline automatically or call different pixels an improvement by themselves.
