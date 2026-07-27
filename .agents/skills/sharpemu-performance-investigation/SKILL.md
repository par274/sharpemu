---
name: sharpemu-performance-investigation
description: Measure and diagnose SharpEmu frame-rate, startup-time, allocation, CPU-emulation, shader-translation, Vulkan synchronization, or presentation regressions. Do not use before correctness is established or for unmeasured optimization requests.
---

<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# SharpEmu performance investigation

## Inputs

Require a correctness-preserving local profile, a measurable symptom, and a baseline commit or run set.

## Workflow

1. Validate correctness and capture a baseline before optimizing.
2. Record commit, build configuration, profile, hardware fingerprint, GPU, driver, command, and relevant environment from run artifacts.
3. Separate compilation, startup, CPU emulation, allocation, shader translation, GPU work, synchronization, and presentation. Choose the smallest measurable boundary.
4. Warm up where applicable and collect multiple equivalent runs. Use wall time, process CPU time, peak memory, milestone times, and frame times only when actually available.
5. Compare matching builds, profiles, capture policy, and hardware. Report median, range, and run IDs; do not select a lucky run.
6. Use installed vendor tools only when they fit the measured boundary. Record their versions and collection settings.
7. Change code only after identifying a bottleneck. Preserve guest-visible behavior and keep disabled instrumentation off hot paths.
8. Repeat the same measurements and run correctness tests after the change. Separate observation from causal conclusion.

## Output

Return baseline and after run sets, configuration/fingerprint, raw measurements, median and spread, isolated cost center, hypothesis, correctness evidence, limitations, and confidence. Do not claim improvement from a single run.
