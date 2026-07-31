<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Demon’s Souls target

This fork advances SharpEmu toward correct, repeatable execution of a lawfully obtained copy of Demon’s Souls v1.004.000 on Windows. Work follows SharpEmu’s general compatibility goals; the title is a focused source of evidence, not permission to replace general behavior with title-specific shortcuts.

## Target identity

The Windows setup must record the title ID, region, executable hash, base and update state, emulator commit, configuration, hardware, driver, and Vulkan version. Do not infer the title ID from another tester’s report. Store local paths and game-derived data only in ignored local files.

## Current upstream frontier

As of upstream commit `7c9740fee8a633e17b145c6bc6d794e41d46c73f`, public testing in [sharpemu/sharpemu#2](https://github.com/sharpemu/sharpemu/issues/2) reports v1.004 reaching character creation at roughly 2–3 FPS. Reported problems include severe native memory growth, low performance, visual artifacts, choppy audio, and incomplete text input. These reports are orientation, not this fork’s baseline.

The first Windows baseline must reproduce the route three times with the controlled runner before development claims rely on it. Its status and accepted summary belong in `docs/BASELINE.md`.

## Milestones

1. **Reproducible baseline:** Reach the current character-creation frontier in three consecutive controlled runs and capture comparable evidence.
2. **Stable frontier:** Bound native memory growth, make startup practical to investigate, correct material visual and audio faults, and replace automatic naming with the observed text-input contract.
3. **First controllable gameplay:** Finalize a character, load the first playable scene, accept controller input, render recognizable geometry and UI, produce stable audio, save correctly, and run for ten minutes without a crash.
4. **Vertical slice:** Complete the tutorial, reach the Nexus, enter an initial Archstone route, preserve save and load behavior, and complete a repeatable 30-minute session.
5. **Broader playability:** Preserve progression, combat, bosses, streaming, effects, cinematics, audio, and saves across a substantial portion of the game.

Reaching a later screen or increasing frame rate does not complete a milestone when required behavior is fabricated, skipped, or corrupted.

## First investigation

Reproduce and characterize native memory growth during the v1.004 startup route. Run at least three comparable trials, distinguish managed, native, driver, and Vulkan ownership, and produce evidence before changing behavior. The known upstream discussion is [sharpemu/sharpemu#639](https://github.com/sharpemu/sharpemu/issues/639).
