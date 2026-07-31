<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Demon’s Souls baseline

## Status

No baseline from this fork has been recorded. The first Windows setup must replace this pending state with evidence from three controlled runs. Do not copy measurements from upstream reports.

## Acceptance

The three runs must use the same clean repository commit, executable hash, title ID, region, v1.004.000 executable hash, emulator arguments, route, host, driver, Vulkan runtime, and limits. Each run must retain its local manifest, metrics, log, and inspected checkpoint under the ignored `artifacts-local/` directory.

The committed summary records:

- Exact emulator commit and target identity without local filesystem paths.
- CPU, GPU, operating system, driver, and Vulkan versions.
- Arguments, route, limits, duration, termination reason, observed checkpoint, and peak working and private memory for each run.
- Median timing and memory values when comparable.
- Material warnings, visible faults, variance, and remaining uncertainty.
- Local run IDs that let the Windows host locate the underlying evidence.

A dirty worktree, missing checkpoint inspection, changed configuration, or single successful run is not an accepted baseline.
