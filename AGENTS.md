<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# SharpEmu agent guide

## Mission

Demon's Souls 01.004.000 is the priority compatibility target. Implement generic, accurate emulator behavior: model what a guest can observe instead of adding title-specific success paths. A visual change is evidence, not proof of correctness. Never fabricate “more progress” by suppressing errors, returning invented success, or bypassing required state.

## Read first

Read in this order for every task:

1. `AGENTS.md`
2. `ARCHITECTURE.md`
3. `README.md`
4. `CONTRIBUTING.md`
5. the nearest relevant source and tests

The checked-out source is authoritative. Keep private game files, keys, captures, logs, dumps, and research notes outside tracked files; generated harness material belongs under `.local/`.

## First five minutes

1. Run `git status --short --branch`; preserve unrelated work.
2. Run `.\scripts\agent-harness.ps1 doctor`.
3. Run `.\scripts\agent-harness.ps1 index status`; run `index build` when refresh is recommended.
4. Name the exact current milestone and evidence that proves it.
5. For runtime work, validate the local profile and collect an unchanged before-run.
6. State one falsifiable hypothesis before changing production code.

## Navigate with bounded context

Use the Roslyn index before reading a long file:

```powershell
.\scripts\agent-harness.ps1 index query --symbol VideoOut --limit 20
.\scripts\agent-harness.ps1 index outline --symbol VulkanVideoPresenter --limit 20
.\scripts\agent-harness.ps1 index outline --path src/SharpEmu.Core/Runtime/SharpEmuRuntime.cs --limit 20
.\scripts\agent-harness.ps1 index map --project SharpEmu.Core
.\scripts\agent-harness.ps1 index text --pattern DispatchEntry --limit 20
```

Use `rg` second, then read precise line ranges. Do not dump a long file merely to find a symbol or repeatedly reread files already indexed. Treat declarations and `ProjectReference` edges as syntax evidence; treat text occurrences as heuristics, not proven call edges. Review changes with `git diff` plus symbol-level context, expanding only when evidence requires it.

## Research hierarchy

Prefer sources in this order:

1. checked-out SharpEmu source and tests;
2. official public specifications and source;
3. AMD, Khronos, FreeBSD, System V ABI, and language/runtime references;
4. reproducible clean-room observations;
5. maintained open-source emulator implementations after license review;
6. community wikis as secondary leads only.

Do not use keys, leaked SDK material, proprietary modules, exploit repositories, unauthorized dumps, or access-control bypasses. Record public research evidence under `.local/research/`, with claim, source class, URL, access date, confidence, and license.

## Development discipline

- Change one hypothesis or tightly related problem at a time.
- Model real guest-visible inputs, outputs, errors, state, ordering, and side effects.
- Replace uncertainty with a failing test or explicit diagnostic, never a fake handle, zero, success return, or silent fallback.
- Avoid speculative export batches and title-specific magic values in core emulation.
- Add tests at the narrowest useful layer and preserve unrelated behavior.
- Keep production fast paths unchanged when optional instrumentation is disabled.
- Understand and review every generated line. Follow repository formatting and REUSE/SPDX rules.
- Never weaken a validation path just to reach a later boot milestone.

Runtime fixes require before/after run IDs, exact commit SHAs, exact command and profile, relevant logs and structured events, earliest changed milestone, graphics screenshot or explicit no-frame evidence, tests, known limitations, and an explanation of why the implementation is generic.

## Visual evidence

Use emulator-native final-swapchain raw capture first. Window client-area capture is a labelled, nondeterministic fallback and is not a stable pixel baseline. Inspect every material image, not only its hash or metrics. Never replace a baseline merely to pass comparison, and never equate changed pixels with improvement. Correlate pixels with logs, structured events, shader output, command/profile, build fingerprint, and specifications. Keep all target-game images local-only.

Distinguish no frame produced, capture failure, blank frame, frozen sequence, changing but visibly incorrect output, and apparently meaningful output. Use:

```powershell
.\scripts\agent-harness.ps1 visual analyze --run <run-id>
.\scripts\agent-harness.ps1 visual compare --before <before-id> --after <after-id>
```

## Performance evidence

Correctness comes first. Compare matching commits, build configurations, profiles, capture policies, and hardware fingerprints. Warm up when appropriate; measure multiple runs and report median plus spread instead of one favorable result. Separate compilation, startup, CPU emulation, allocation, shader translation, GPU work, synchronization, and presentation. Do not claim an optimization without measurements and unchanged correctness evidence.

## Validation matrix

Run the narrow row while iterating and the final row before completion.

| Change | Required commands |
|---|---|
| Documentation or skills only | `git diff --check`; `.\scripts\agent-harness.ps1 skills validate` |
| Harness or source index | `dotnet test tests/SharpEmu.Tools.AgentHarness.Tests/SharpEmu.Tools.AgentHarness.Tests.csproj`; `.\scripts\agent-harness.ps1 doctor`; `.\scripts\agent-harness.ps1 index build`; `.\scripts\agent-harness.ps1 synthetic visual` |
| Loader, Core, HLE, or libraries | `dotnet test tests/SharpEmu.Libs.Tests/SharpEmu.Libs.Tests.csproj` |
| Shader compiler | `dotnet test tests/SharpEmu.ShaderCompiler.Tests/SharpEmu.ShaderCompiler.Tests.csproj`; `dotnet test tests/SharpEmu.ShaderCompiler.Metal.Tests/SharpEmu.ShaderCompiler.Metal.Tests.csproj` |
| AGC, GPU, or VideoOut | `dotnet test tests/SharpEmu.Libs.Tests/SharpEmu.Libs.Tests.csproj --filter "FullyQualifiedName~Gpu|FullyQualifiedName~VideoOut|FullyQualifiedName~Agc"`; run and inspect the relevant local profile when the path is exercised |
| GUI or CLI | `dotnet build SharpEmu.slnx -c Debug`; exercise the changed command or UI path |
| Performance | `dotnet build SharpEmu.slnx -c Release`; collect repeated equivalent harness runs and their `.local/runs/*/metrics.json` |
| Final full validation | `dotnet restore SharpEmu.slnx`; `dotnet build SharpEmu.slnx -c Debug --no-restore`; `dotnet build SharpEmu.slnx -c Release --no-restore`; `dotnet test SharpEmu.slnx -c Debug --no-build --no-restore`; `reuse lint`; `git diff --check` |

Local target execution is always bounded:

```powershell
.\scripts\agent-harness.ps1 profile validate --profile .local\profiles\demons-souls-01.004.000.json
.\scripts\agent-harness.ps1 run --profile .local\profiles\demons-souls-01.004.000.json
```

Do not commit `.local/` output or private paths copied from it.

## Completion gate

Do not claim completion until targeted and required full tests pass, required builds pass, generated artifacts and material images are inspected, `git diff` is reviewed, private-data scanning is clean, and the final report names its evidence and limitations. A blocked game input does not justify weakening repository, harness, or synthetic validation.

## Review for emulator-specific hazards

- Replace fabricated emulator behavior with guest-visible state machines, documented errors, and narrow tests.
- Pair every state transition with tests for ordering, repeat calls, teardown, and error paths.
- Validate guest ranges, lengths, alignment, overflow, and access before reading or writing; copy through the repository memory boundary rather than trusting a guest pointer as a host pointer.
- Use checked arithmetic for offsets, sizes, pitches, counts, and address ranges before allocations or native calls.
- Keep guest virtual addresses distinct from translated or allocated host addresses; make conversions explicit at `PhysicalVirtualMemory` or the owning abstraction.
- Derive Vulkan layouts, stages, access masks, queue ownership, and resource lifetime from the producing and consuming operations; add validation-backed tests or captures.
- Surface unsupported shader semantics with structured diagnostics; implement and validate the real translation rather than silently substituting another instruction.
- Put generic platform behavior behind the owning subsystem and test it across inputs; keep title identifiers out of production decisions.
- Generate synthetic fixtures at test time and keep proprietary binaries, hashes, paths, screenshots, and logs outside Git; inspect staged files before committing.
- Guard diagnostics at the entry point and keep disabled branches allocation- and copy-free on normal hot paths; verify ordinary runs do not create harness artifacts.
