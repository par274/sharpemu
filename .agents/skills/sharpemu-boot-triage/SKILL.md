---
name: sharpemu-boot-triage
description: Diagnose SharpEmu launch failures, crashes, hangs, unresolved imports, missing modules, guest exceptions, and failures through video initialization using bounded run artifacts. Do not use for general navigation, pixel-only regressions, research, or optimization.
---

<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# SharpEmu boot triage

## Inputs

Require a validated local profile and, for comparisons, a before-run ID. Keep target binaries and paths outside Git.

## Workflow

1. Run `.\scripts\agent-harness.ps1 doctor` and `profile validate --profile <profile>`.
2. Run the exact profile with `.\scripts\agent-harness.ps1 run --profile <profile>`. Do not relax its 180-second maximum or process-tree cleanup.
3. Read `run.json`, `events.jsonl`, `stdout.log`, `stderr.log`, and `emulator.log` from the reported `.local/runs/<run-id>/` directory.
4. Find the earliest structured milestone or error that differs from the before-run. Distinguish host crash, guest failure, timeout, unresolved import, shader failure, graphics failure, and no-frame evidence.
5. State one falsifiable hypothesis. Use the source index to locate the smallest owning source and nearest test surface.
6. Test actual guest-visible state, inputs, outputs, errors, and side effects. Never begin with a stub, fake success, suppressed error, or title-specific value.
7. Preserve the run before changing code; rerun the same profile afterward.

## Output

Return run IDs, commit SHAs, exact command/profile, duration, exit classification, highest proven milestone, earliest divergence, supporting log/event records, frame status, hypothesis, minimal source/test surface, and limitations.
