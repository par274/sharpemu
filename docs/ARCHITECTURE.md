<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Architecture

This document records the boundaries and invariants that matter when investigating the Demon’s Souls target. The source remains authoritative for implementation details.

## Runtime shape

SharpEmu loads PS4 and PS5 executables, maps guest memory, resolves imported modules to HLE exports, executes guest x86-64 code natively, translates guest GPU work to a host graphics API, and connects host input, display, audio, filesystem, and service behavior around that execution.

The principal flow is:

```text
CLI or GUI
  → runtime and loader
  → guest address space and module resolution
  → native x86-64 execution ↔ HLE exports
  → AGC and guest GPU commands
  → Gen5 shader decode and IR
  → SPIR-V translation
  → Vulkan resources, synchronization, and presentation
```

## Durable boundaries

- **Host entry and configuration:** `SharpEmu.CLI` and `SharpEmu.GUI` select a target and construct runtime, video, logging, and debugger options. Target measurement belongs outside these applications in the controlled runner.
- **Runtime, loader, CPU, and memory:** `SharpEmu.Core` owns executable loading, guest address-space behavior, native execution, dispatch, and the debugger seam. Guest x86-64 executes natively, so the supported target host is x64 and host process behavior can affect guest mappings.
- **HLE and guest-visible services:** `SharpEmu.HLE` provides ABI registration and shared host facilities. `SharpEmu.Libs` implements guest-visible libraries and services. An HLE call is correct only when its required state, outputs, side effects, callbacks, errors, and lifetime are represented.
- **GPU command path:** AGC and GPU code in `SharpEmu.Libs` interpret guest resources and commands. Do not diagnose this layer from the final image alone; preserve the command, resource, format, address, and synchronization evidence that reaches it.
- **Shader translation:** `SharpEmu.ShaderCompiler` decodes Gen5 shader behavior into an intermediate representation. Backend projects lower that representation to SPIR-V or MSL. Decoder, IR, lowering, and host-driver failures are different fault domains and require separate evidence.
- **Host graphics:** the Vulkan presenter owns host resources, pipelines, synchronization, submission, and presentation. Managed allocation measurements do not account for all memory owned by this boundary or its driver.
- **Media and audio:** guest-facing libraries coordinate host decoding and output. The Bink2 bridge uses a clean-room FFmpeg integration described in `docs/bink2-bridge.md`; proprietary RAD material is outside the project boundary.
- **Diagnostics:** logging, guest write watch, the debug server, synthetic shader dump, and GPU conformance tools observe behavior without becoming its implementation. Diagnostic output must not silently change guest-visible semantics.

## Investigation invariants

1. Identify the owning boundary before changing behavior. A symptom visible in Vulkan may originate in command decoding, resource metadata, shader translation, guest memory, or HLE state.
2. Keep guest-observable contracts separate from host conveniences. Host success is not proof that the guest received correct state or timing.
3. Preserve address, format, lifetime, synchronization, and error semantics across a boundary. Do not fix one by weakening another.
4. Add the lowest synthetic regression that reproduces the discovered contract. Retail-title evidence confirms integration but does not belong in CI.
5. Split a large implementation only when a proven boundary becomes easier to test and reason about. File size alone is not an architecture decision.
