<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Demon’s Souls compatibility project

This fork advances SharpEmu toward correct, repeatable execution of Demon’s Souls v1.004.000 on Windows. The current milestone and baseline are defined in `docs/TARGET.md`.

Follow `CONTRIBUTING.md`. Improve general PS5 behavior when the evidence supports it; the target title is not permission to replace correct behavior with shortcuts.

## Maintainer philosophy

I like ambitious goals, simple systems, and software whose behavior is obvious. Do not preserve complexity because it exists or introduce machinery because it looks impressive. Understand the real constraint, then fight for the smallest model that makes the correct behavior unsurprising.

Channel both "measure twice, cut once" and "yagni". Work on the blocker in front of the current milestone. Do not reorganize unrelated systems during an investigation.

## Communication

Write concise, direct English. State the outcome first. Separate observation, inference, and uncertainty. Keep exact identifiers, commands, measurements, and source revisions.

## Evidence

Treat model output as a hypothesis, never as evidence. Follow `docs/RESEARCH_POLICY.md` and record durable external sources in `docs/SOURCES.md`.

Prefer evidence in this order: reproducible observation from a lawful local test, an official architecture or API specification, a focused synthetic experiment, a licensed open-source implementation, then a community source.

Do not use or add leaked SDK material, firmware, keys, proprietary Sony code, or copyrighted game assets. Keep local game data and raw game-derived artifacts outside Git. CI uses only authored or clearly redistributable fixtures.

## Emulator work

Reproduce the current blocker before changing it. Record the exact build, target version, configuration, hardware, logs, and measurable result.

Change the smallest semantic boundary supported by the evidence. Do not fabricate success, invent NIDs, suppress errors, skip required work, or add behavior only to advance the boot sequence.

A stub is valid only when the guest-observable contract is known and intentionally requires no effect. Otherwise fail visibly.

Prefer a general implementation. If a compatibility override is unavoidable, isolate it, document the observed reason and removal condition, and ask before adding it.

Do not merge another emulator architecture into this fork. Use compatible licensed projects as focused references only after checking the exact revision, provenance, license, and semantic fit.

## Context

`AGENTS.md`, `docs/TARGET.md`, `docs/ARCHITECTURE.md`, `docs/SOURCES.md`, and `docs/VERIFICATION.md` are curated context. Update one only when work changes durable truth that would affect a future decision. Do not record task history, plans, raw investigation logs, file inventories, or routine implementation details. Replace stale statements instead of appending change notes.

Changes to `AGENTS.md` require the maintainer’s approval of the exact wording.

## Verification

Add a synthetic regression whenever behavior can be reproduced without proprietary data. Validate emitted SPIR-V against the repository’s pinned Vulkan target.

Run the fast verification lane after non-graphics work and the shader lane when shader translation or GPU semantics change. For target work, use the controlled Windows runner. Run at least three comparable trials before drawing conclusions about memory or performance.

Before handoff, have a separate agent review the complete change and its evidence without editing. Resolve valid findings and rerun affected checks.

## GitHub

Work on a task branch. Keep `origin/main` releasable and preserve `upstream` as the SharpEmu source remote. Synchronize upstream through a dedicated reviewed change, not during an active compatibility experiment.

Do not open or merge a PR unless the maintainer asks.

## Handoff

Report the blocker, cause, behavior before and after, evidence, remaining uncertainty, and next frontier. Do not describe a later screen or higher frame rate as a correctness fix unless expected behavior is also preserved.
