<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Configurable Diagnostics

SharpEmu diagnostics are disabled by default so tracing does not reduce guest, GPU, or video performance during normal use. Diagnostics can be configured globally or per game from the GUI. Per-game settings override the global selection.

## Profiles

| Profile | Enabled categories | Intended use |
| --- | --- | --- |
| `Off` | None | Normal gameplay and performance measurements |
| `Compatibility` | `Imports`, `AgcUnsupported` | Low-volume compatibility triage |
| `Full` | All categories | Short, targeted debugging sessions; may reduce performance |
| `Custom` | User-selected categories | Focused investigation of one subsystem |

Available categories are `Imports`, `AgcUnsupported`, `AgcShaders`, `AgcPackets`, `AgcDraws`, `Memory`, and `Video`.

Changing a profile applies to the next game launch. The active settings are stored with the global GUI configuration or the game's override file.

## Environment variables

Command-line launches can use the same configuration:

```text
SHARPEMU_DIAGNOSTICS_PROFILE=Compatibility
SHARPEMU_DIAGNOSTICS_CATEGORIES=AgcShaders,Video
```

`SHARPEMU_DIAGNOSTICS_CATEGORIES` is used only by the `Custom` profile. Names are case-insensitive; unknown names are ignored.

## Performance behavior

- Disabled categories skip interpolated argument evaluation and message allocation.
- Enabled messages use a bounded, non-blocking background queue.
- If the queue is full, new messages are dropped instead of stalling emulation threads.
- `Compatibility` records import and unsupported AGC activity without enabling packet, draw, shader, memory, or video traces.
- Use `Off` when comparing frame rates after a diagnostic session.

The diagnostic writer is drained during normal logger shutdown. Queue totals are exposed through `SharpEmuDiagnostics.EnqueuedMessages` and `SharpEmuDiagnostics.DroppedMessages` for tests and future telemetry.
