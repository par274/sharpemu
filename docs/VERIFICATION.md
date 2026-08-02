<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Verification

Repository checks and retail-title experiments are separate. CI proves behavior that can be exercised with authored or redistributable inputs. The ignored Windows target lane supplies integration evidence without publishing protected content.

## Windows setup

Use PowerShell 7.4 or later on x64 Windows. The repository pins .NET in `global.json`.

```powershell
./scripts/bootstrap.ps1
```

Bootstrap checks the host and creates `.local/target.json` from the committed example when needed. Complete every placeholder with the lawful local target, hashes, host graphics information, route, and limits. The configuration remains ignored.

## Fast lane

Run after changes outside shader translation and GPU semantics:

```powershell
./scripts/verify.ps1 -Lane Fast
```

The lane parses repository PowerShell and JSON inputs, restores dependencies, builds Release, and runs all solution tests. CI runs it on Windows.

## Shader lane

Run when shader decoding, intermediate representation, SPIR-V lowering, resource semantics, or related GPU behavior changes. Supply the pinned SPIRV-Tools `v2026.2` validator identified in `docs/SOURCES.md`:

```powershell
./scripts/verify.ps1 -Lane Shader -SpirvValidator C:\path\to\pinned\spirv-val.exe
```

This lane regenerates synthetic modules and validates each for Vulkan 1.2. CI builds the pinned validator from source and exposes this as a separate required job.

## Controlled target lane

Publish the Windows CLI, then run three comparable trials:

```powershell
dotnet publish ./src/SharpEmu.CLI/SharpEmu.CLI.csproj -c Release -r win-x64 --self-contained true
./scripts/run-target.ps1 -Runs 3
./scripts/compare-runs.ps1 -Latest 3
```

For an opt-in memory diagnostic stream whose per-run path remains comparable,
use the original placeholder in the additional argument template:

```powershell
./scripts/run-target.ps1 -Runs 3 -AdditionalArguments @('--memory-diagnostics={runDirectory}\memory-diagnostics.jsonl')
./scripts/compare-runs.ps1 -Latest 3
```

Each manifest preserves the expanded launched arguments in
`emulator.arguments` and records the original templates in
`emulator.comparisonArguments`. The comparison script hashes the stable field
and falls back to `emulator.arguments` for older manifests that predate the
stable field.

The runner verifies target and emulator hashes, records the clean or dirty commit state, and captures a trusted launcher identity directly from the `Process` object returned by `Start()` before the first process inventory query. That identity includes PID, normalized process start time, process name, and the configured executable path; successful samples add every observed supervised identity to the fallback set. On Windows, the controlled SharpEmu CLI is recorded as `expected-mitigated-child` unless `SHARPEMU_DISABLE_MITIGATION_RELAUNCH=1`; explicit direct launches are recorded as `direct-launch`. While the launcher is alive, the runner discovers a descendant carrying the exact `--sharpemu-mitigated-child` argument and promotes it only when its executable path or process name is compatible with the launcher. Directly launched executables remain their own actual-emulation root. Monitoring continues while either the launcher or the recorded actual child is alive; it does not treat launcher exit alone as `process-exited` and does not depend on the old parent relationship after handoff.

Each sample builds the live launcher-root and independently tracked child-root trees, validates retained root identities before sampling, deduplicates processes by PID plus start time, and records the current supervised identities, counter sources, launcher-tree totals, child-tree totals, actual-child counters, and aggregate working-set/private-memory totals. The configured wall-time, aggregate working-set, physical-headroom, and commit-headroom boundaries remain active through the handoff. PID reuse, missing process lookup, ambiguous child discovery, or unavailable identity evidence fails closed and records the uncertainty; cleanup never searches for or kills SharpEmu by name. If the expected child has not been promoted when the launcher disappears, the runner makes one final strict inventory attempt associated with the recorded launcher identity. An unconfirmed expected child is `supervision-failure`, never successful `process-exited`. Every termination boundary and `finally` cleanup attempts the launcher and independently tracked child roots separately, including roots already observed to have exited. If CIM inventory or tree enumeration fails, cleanup reports incomplete descendant enumeration and falls back to individually revalidating and targeting only recorded PID/start-time identities through `Get-Process`; cleanup failures are recorded without replacing the primary failure. The manifest's `supervision` section preserves expected mode, launcher/actual identities, discovery and exit times, handoff samples, all known supervised identities, identity failures, cleanup targets, and cleanup-enumeration failures. `minimumAvailablePhysicalGiB` and `minimumCommitHeadroomGiB` are optional safety thresholds; omitted or `null` disables that boundary. When a threshold is present, the runner calls the Windows `GetPerformanceInfo` API once per existing sample. Startup API failure and invalid configured thresholds fail closed before the target is launched; malformed sampled host data fails closed with guaranteed cleanup. The runner does not change the page file or Windows configuration.

Every metrics sample records `workingSetBytes`, `privateBytes`, `physicalAvailableBytes`, `commitTotalBytes`, `commitLimitBytes`, and calculated `commitHeadroomBytes` (plus the page size and physical total used for validation). The manifest records the configured threshold values in `limits`, startup physical and commit values, the run minimum physical availability and commit headroom under `hostMemory`, the final sampled host values, and a `terminationBoundary` with the distinct reason and sampled boundary value. The safety-boundary reasons are `working-set-limit`, `physical-headroom-limit`, `commit-headroom-limit`, `wall-time-limit`, and `process-exited`; `supervision-failure` marks a fail-closed process-identity or lookup error and is not a successful exit. Each trial writes a manifest, JSON-lines metrics, and SharpEmu log under ignored `artifacts-local/runs/`.

After inspecting each run, record the actually observed checkpoint and concise notes in its local manifest. Do not infer a checkpoint from exit code or elapsed time. Use screenshots or diagnostic captures locally when they are needed to support that observation.

When the three runs are comparable, replace the pending entry in `docs/BASELINE.md` with a sanitized summary. Never commit local paths, raw retail content, game-derived shaders, captures, dumps, or full logs.

## Change evidence

- Add a synthetic regression for a behavior that can be reproduced without protected data.
- Compare behavior before and after on the same configuration and host.
- Use at least three trials for memory, timing, or performance conclusions.
- Distinguish managed, native, driver, and Vulkan ownership before attributing memory.
- Preserve failed and high-variance results; do not select only the best run.
