---
name: sharpemu-code-navigation
description: Locate SharpEmu implementations, symbols, subsystem ownership, long-file regions, and relevant tests with the tracked-file Roslyn source index. Use for code-flow or ownership questions. Do not use for runtime failure diagnosis, visual comparison, research, or performance measurement.
---

<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# SharpEmu code navigation

## Inputs

Accept a symbol, namespace, subsystem, tracked path, behavior, or test target. Ask for one only when none can be inferred.

## Workflow

1. Run `.\scripts\agent-harness.ps1 index status`. Run `index build` when missing or stale.
2. Begin with at most 20 results. Query a symbol with `index query --symbol <name> --limit 20`; filter with `--namespace` or `--kind` when useful.
3. Use `index outline --symbol <name>` or `index outline --path <tracked-path>` before reading a long file.
4. Use `index map --project <name>` for declared `ProjectReference` ownership. Label this relationship as MSBuild syntax, not a runtime call edge.
5. Use `index text --pattern <text> --limit 20`, then `rg`, only when syntax queries cannot answer the question. Label text occurrences as heuristic.
6. Read only the line ranges that contain the declaration, callers, state, and nearest tests. Expand when evidence requires it.
7. Verify conclusions against the checked-out source; do not infer semantics from a name alone.

## Output

Return the relative path, project, namespace, symbol, exact line range, relationship type (`syntax`, `declared project reference`, or `heuristic text`), nearest tests, and any uncertainty. Never dump a whole long source file.
