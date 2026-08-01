<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup private-data ownership

Status: the investigation narrowed the remainder to a managed-runtime segment
hypothesis and an external Windows/Vulkan virtual-allocation boundary, but did
not identify a named owner with enough evidence to justify a memory correction.
The largest unresolved shape is a fully resident 512 MiB
`Read/Write/WriteCombine` region. It is not an exact guest mapping, does not
overlap a tracked Vulkan host-visible mapping, and was not requested by the
application's `VirtualAlloc` paths. The instance/device Vulkan callback probe
also saw no request larger than 133,120 bytes. The next boundary is an elevated
Windows Performance Recorder `VirtualAllocation` trace with allocation stacks.

This finding records observations, inferences, and uncertainty separately. It
does not call the remainder a native leak, managed leak, driver allocation, or
other owner without attribution evidence.

## Environment and target identity

The controlled runs used the existing ignored target configuration. Absolute
target and artifact paths are intentionally omitted from this tracked finding.

| Item | Value |
| --- | --- |
| Source baseline | `a0d9134cacea945713f96ea3824e7694733daf7e` |
| Diagnostic source revision | `b798a77fc47eb3cd8830012d31969745a918f106` |
| Title ID | `PPSA01341` |
| Region / target version | Europe (`EP9000`) / `1.004.000` |
| Target eboot SHA-256 | `22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306` |
| Route / checkpoint | startup-to-character-creation / character creation nickname prompt |
| Host | Windows 11 Pro `10.0.26200`, 16 GiB |
| CPU | 12th Gen Intel Core i5-12400F, 12 logical processors |
| GPU / driver | NVIDIA GeForce RTX 3070 Ti / `610.74` (WDDM `32.0.16.1074`) |
| Runtime | .NET `10.0.10` |
| Vulkan | loader/SDK `1.4.350`; device API `1.4.341`; NVIDIA `610.74` |
| Target arguments | `--cpu-engine=native --log-level=debug --window-mode=windowed --resolution=1280x720 --vsync=off` |
| Safety policy | 6 GiB process-tree working-set limit, existing page-file configuration, 900 s wall limit, 250 ms sampling |

The target identity, arguments, limit, and machine values are recorded in the
raw run manifests outside Git. The final committed diagnostic and control
publishes used the same emulator binary SHA-256:
`6C62ADEFFF6F9FBD9E7ACE405E1290915EDD8201338E2E456DB04F0682C2F9E0`.

## Method and tools

The first pass reused the retained valid VMMap exports and
`residency-attribution-corrected.json`. VMMap CSV values are KiB; the analysis
converted them to bytes before calculating MiB/GiB. A guest interval was
subtracted only when its base and reserved interval matched the recorded guest
mapping. A top-level VMMap `Private Data` row was considered unmatched when it
did not overlap any such interval. Vulkan device-local memory was never added
to process-private or resident-RAM totals.

The VMMap tool was Microsoft VMMap `3.4`, invoked by the existing runner as:

```text
vmmap64.exe -p <actual SharpEmu child PID> <output.csv>
```

The existing corrected arithmetic reports four retained valid captures with a
1.88–2.41 GiB `Private Data` working-set remainder. The new matrix added a
bounded, opt-in probe at the instance and device `VkAllocationCallbacks`
boundary. It records only scalar address, size, alignment, scope, ID, and
time-frontier metadata; it does not retain payloads, managed owners, Vulkan
objects, or stack traces. The bound is 16,384 active entries and 65,536 events.
The disabled path does not create the probe or pass callbacks to Vulkan.

The probe was deliberately limited to `vkCreateInstance`/`vkDestroyInstance`
and `vkCreateDevice`/`vkDestroyDevice`. Child Vulkan object creation calls
continue to use the default allocator. Under Vulkan's allocator contract, this
answers the instance/device callback boundary; it does not claim to account for
implementation virtual allocations outside those callbacks.

Before adding broader instrumentation, the installed Microsoft Windows
Performance Recorder was checked:

```text
Microsoft Windows Performance Recorder Version 10.0.26100
wpr -profiles
wpr -start VirtualAllocation -filemode
```

The `VirtualAllocation` start failed in the available non-elevated session with
`0x80070005 (Access is denied)`. No ETL was produced. No full heap dump or
`dotnet-gcdump` was started: the existing GC segment/counter evidence was
sufficient to choose a narrower next boundary, and a dump would add more
intrusion under the 6 GiB limit. The WPR profile and VMMap sources are indexed
in [SOURCES.md](SOURCES.md).

## Controlled run matrix

The control and final diagnostics were run after commit `b798a77`, with the
same published binary and unchanged target policy. Every run ended at the
existing working-set safety cutoff; none reached the requested checkpoint.

| Run | Diagnostics | VMMap captures | Duration | Peak process-tree WS | Peak private | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `20260801T172835190Z-b798a77-trial-01` | disabled control | 0 | 21.1 s | 6.051 GiB | 11.439 GiB | working-set-limit |
| `20260801T172921361Z-b798a77-trial-01` | enabled | 2 | 25.3 s | 6.108 GiB | 11.625 GiB | working-set-limit |
| `20260801T172946662Z-b798a77-trial-02` | enabled | 2 | 26.8 s | 6.286 GiB | 11.702 GiB | working-set-limit |
| `20260801T173013493Z-b798a77-trial-03` | enabled | 2 | 25.1 s | 7.129 GiB | 12.235 GiB | working-set-limit |

The runner does not permit VMMap-assisted capture when diagnostics are disabled,
so the clean control has no VMMap export. This is a runner constraint, not an
assumption that the control and diagnostic samples are synchronized.

The direct probe state in the three enabled runs was:

| Run | Active entries | Active requested bytes | Allocation IDs | Events | Dropped entries/events | Duplicate/untracked releases | Largest request |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `20260801T172921361Z-b798a77-trial-01` | 1,817 | 2,001,406 | 14,336 | 26,987 | 0 / 0 | 0 / 0 | 133,120 bytes |
| `20260801T172946662Z-b798a77-trial-02` | 1,861 | 2,034,670 | 14,883 | 28,034 | 0 / 0 | 0 / 0 | 133,120 bytes |
| `20260801T173013493Z-b798a77-trial-03` | 1,754 | 1,957,126 | 14,877 | 28,129 | 0 / 0 | 0 / 0 | 133,120 bytes |

The active-byte value is requested bytes in the callback ledger, not a VMMap
resident value. The diagnostic structures are bounded and the normal path is
disabled. Deterministic tests cover balance, reallocation, duplicate release,
bound drops, disabled behavior, and callback-session lifetime.

The process-tree peak is not a synchronized ownership measurement. The enabled
run peaks span 6.108–7.129 GiB, while the direct callback ledger stays near
2 MiB and the same region shapes recur in all six scans. The evidence supports
an unchanged ownership regime, not a claim of zero allocator perturbation. The
7.129 GiB trial is retained as an outlier and is not averaged into a matched
capture.

## Largest unmatched regions

The following table enumerates the three largest unmatched top-level
`Private Data` rows in every retained valid capture and every valid capture in
the final diagnostic matrix. Each region tuple is:

```text
address — reserved / committed / private / total WS / private WS MiB;
VMMap blocks; protection; Details
```

All listed `Details` fields were empty. The listed rows did not overlap an exact
guest mapping. The top-three share is calculated against that capture's
classification remainder, not against total process working set.

| Capture | Largest unmatched row | Second row | Third row | Remainder / top-three share |
| --- | --- | --- | --- | --- |
| `20260801T094524470Z-8342025-trial-01` corrected | `0x000001C4F2920000` — 32437.25 / 1529.65 / 1529.65 / 1528.98 / 1528.98; 65; RW | `0x000001CCF9960000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x000001C4A2260000` — 1024 / 76.06 / 76.06 / 68.98 / 68.98; 30; RW | 2.395 GiB / 86.0% |
| `20260801T094826414Z-8342025-trial-01` near cutoff | `0x0000023B43910000` — 32437.25 / 1554.67 / 1554.67 / 1550.55 / 1550.55; 67; RW | `0x000002437AF30000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x000002432EE50000` — 1024 / 76.06 / 76.06 / 68.89 / 68.89; 30; RW | 2.413 GiB / 86.3% |
| `20260801T094912261Z-8342025-trial-01` near cutoff | `0x000001B2639E0000` — 32437.25 / 1206.73 / 1206.73 / 1202.77 / 1202.77; 45; RW | `0x000001BA8F000000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x000001BA4EF20000` — 1024 / 70.62 / 70.62 / 63.05 / 63.05; 30; RW | 1.884 GiB / 92.2% |
| `20260801T095812249Z-8342025-trial-01` near cutoff | `0x000001BB35140000` — 32437.25 / 1334.28 / 1334.28 / 1333.24 / 1333.24; 59; RW | `0x000001C37B740000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x000001C320680000` — 1024 / 73.94 / 73.94 / 67.19 / 67.19; 34; RW | 2.146 GiB / 87.0% |
| `20260801T172921361Z-b798a77-trial-01` corrected | `0x0000021455E90000` — 32437.25 / 1228.56 / 1228.56 / 1227.07 / 1227.07; 45; RW | `0x0000021C814B0000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x0000021C413D0000` — 1024 / 74.44 / 74.44 / 66.84 / 66.84; 34; RW | 2.131 GiB / 82.8% |
| `20260801T172921361Z-b798a77-trial-01` near cutoff | same addresses — 32437.25 / 1112.05 / 1112.05 / 1110.56 / 1110.56; 45; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 80.69 / 80.69 / 73.11 / 73.11; 32; RW | 2.059 GiB / 80.4% |
| `20260801T172946662Z-b798a77-trial-02` corrected | `0x000002E2AFCB0000` — 32437.25 / 1067.25 / 1067.25 / 1063.96 / 1063.96; 57; RW | `0x000002EAF9CF0000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x000002EA9B1F0000` — 1024 / 74.69 / 74.69 / 67.10 / 67.10; 34; RW | 1.994 GiB / 80.5% |
| `20260801T172946662Z-b798a77-trial-02` near cutoff | same addresses — 32437.25 / 886.82 / 886.82 / 883.54 / 883.54; 47; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 76.38 / 76.38 / 68.73 / 68.73; 40; RW | 1.963 GiB / 72.8% |
| `20260801T173013493Z-b798a77-trial-03` corrected | `0x0000022AA4730000` — 32437.25 / 1544.80 / 1544.80 / 1543.47 / 1543.47; 71; RW | `0x00000232F9490000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x000002328FC70000` — 1024 / 73.75 / 73.75 / 66.52 / 66.52; 34; RW | 2.428 GiB / 85.3% |
| `20260801T173013493Z-b798a77-trial-03` near cutoff | same addresses — 32437.25 / 1430.95 / 1430.95 / 1429.64 / 1429.64; 63; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 76.31 / 76.31 / 68.83 / 68.83; 44; RW | 2.374 GiB / 82.7% |

The first region is stable in reserved size and stable in address within a
process, but its committed and resident portions move between matched
frontiers. Across processes its address changes, consistent with ASLR. The
512 MiB and 1 GiB signatures have the same within-process stability and
cross-process ASLR behavior. The next unmatched group contains 64 MiB and
32 MiB fully resident `Read/Write/WriteCombine` regions plus smaller related
regions. The top three explain 72.8–92.2% of the remainder in these captures;
a small number of stable shapes, not hundreds of unrelated tiny regions,
dominates the arithmetic.

No listed top region had a VMMap `Details` owner. The retained host-map
correlation found no top-region overlap. The final diagnostic captures found
0, 1, 2, 2, 0, and 0 host-map matches respectively, but those matches were
small and did not overlap the three listed rows.

## Time-aligned ownership evidence

These rows are each internally matched to the nearest diagnostics sample for
the completed VMMap scan. They must not be averaged across processes or
treated as a synchronized time series.

| Run / frontier | Process WS | VMMap Private Data WS | Exact guest Private Data WS | Exact guest Thread Stack WS | Exact guest total WS | GC committed / heap-used | Remainder |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `20260801T172921361Z-b798a77-trial-01` corrected, 14,016 ms | 4.794 GiB | 5,175.2 MiB | 2,993.0 MiB | 124.4 MiB | 3.044 GiB | 1,169.1 / 1,157.1 MiB | 2.131 GiB |
| same run near cutoff, 16,508 ms | 5.376 GiB | 5,120.6 MiB | 3,012.4 MiB | 124.6 MiB | 3.063 GiB | 1,229.7 / 1,112.2 MiB | 2.059 GiB |
| `20260801T172946662Z-b798a77-trial-02` corrected, 14,051 ms | 4.769 GiB | 5,052.4 MiB | 3,010.5 MiB | 130.9 MiB | 3.068 GiB | 1,066.7 / 793.8 MiB | 1.994 GiB |
| same run near cutoff, 18,539 ms | 5.235 GiB | 5,137.4 MiB | 3,127.3 MiB | 127.6 MiB | 3.179 GiB | 973.2 / 704.3 MiB | 1.963 GiB |
| `20260801T173013493Z-b798a77-trial-03` corrected, 13,522 ms | 4.324 GiB | 5,506.8 MiB | 3,021.0 MiB | 124.3 MiB | 3.072 GiB | 1,077.6 / 1,002.1 MiB | 2.428 GiB |
| same run near cutoff, 16,025 ms | 5.699 GiB | 5,475.6 MiB | 3,044.9 MiB | 124.7 MiB | 3.095 GiB | 1,418.6 / 1,033.0 MiB | 2.374 GiB |

The GC committed and heap-used values are runtime counters, not VMMap
categories. The 32,437.25 MiB region is therefore a managed GC/runtime
segment hypothesis supported by shape and frontier movement, not a second
additive owner. GC committed bytes are not assumed fully resident.

At the same matched frontiers, explicit Vulkan device memory was 0.556–2.550
GiB and mapped host-visible memory was 34.4–95.5 MiB. Device memory is a
separate device domain and is excluded from process-private/RAM reconciliation.
There were 56–144 tracked host maps; exact address correlation matched 0–2
small rows, with 0.0–28.5 MiB matched working set. The cache reached 594.8 MiB
image memory in the late plateau while staging stayed at 0.5 MiB; deferred
texture and translated-resource destruction stayed at zero. Queue payload was
zero at the late frontier except for one non-comparable corrected-frontier
sample, where it was 324.8 MiB and drained before the near-cutoff scan.

## Classification-safe reconciliation

The reconciliation is intentionally not a sum of every diagnostic counter:

| Category | Treatment |
| --- | --- |
| Total VMMap `Private Data` working set | The measured parent category, 5,052.4–5,506.8 MiB in the final matched scans. |
| Exact guest `Private Data` | Subtracted once by exact guest interval and VMMap type, 2,993.0–3,127.3 MiB. |
| Exact guest `Thread Stack` | Reported separately, 124.3–130.9 MiB; not subtracted from `Private Data` because it is a different VMMap class. |
| Managed GC/runtime | GC committed and heap-used counters are overlapping evidence for the large reserved segment; they are not added to the remainder and do not prove object retention. |
| CPU backend/generated code and data | Source audit found small stubs, TLS/control storage, context frames, and worker/abort stacks with matching frees. The largest identified worker stack reservation is 4 MiB; no source path explains the 512 MiB/1 GiB signatures. No separate large CPU-backend owner is claimed. |
| Explicit Vulkan device memory | Tracked separately in `vulkan.device-memory`; excluded from process-private/resident-RAM totals. |
| Vulkan mapped host-visible memory | Address-correlated separately; at most 28.5 MiB of matched working set in these scans and no overlap with a listed top region. |
| Vulkan instance/device callback ledger | At most 2,034,670 outstanding requested bytes; balanced across every final trial. This is a subset of callback allocations, not an additive VMMap owner. |
| Cache, staging, deferred destruction, queue | Cache image is device-local accounting; staging is 0.5 MiB; deferred is zero; late queue is zero. These counters are not added to the remainder. |
| Remaining classification remainder | 1.963–2.428 GiB per final matched capture, dominated by the stable region signatures above and not assigned to a named owner. |

The source audit also found no application `PAGE_WRITECOMBINE` request. The
Windows host-memory wrapper strips that modifier from its generic protection
mapping, while the application source has no other matching request. This is
evidence against an application-created WriteCombine region, not proof of a
driver owner.

## Observation, inference, and uncertainty

### Observed

* Three region signatures recur across four retained captures and six final
  captures. The largest has 32,437.25 MiB reserved; the second is 512 MiB,
  fully committed and resident, with `Read/Write/WriteCombine`; the third is
  1,024 MiB with approximately 63–73 MiB resident in the final matrix.
* The largest region's resident amount changes substantially between matched
  frontiers while its address and reserved size stay fixed within a process.
* The top regions are outside exact guest intervals and tracked host-map
  intervals. VMMap gives them no `Details` owner.
* The instance/device Vulkan callbacks had zero dropped records, zero duplicate
  releases, zero untracked releases, and a maximum request of 133,120 bytes in
  each final trial.
* Existing explicit Vulkan, cache, staging, deferred-destruction, queue, GC,
  and guest counters do not sum to the VMMap `Private Data` remainder without
  overlapping categories or crossing process frontiers.

### Inferred

* The 32,437.25 MiB shape is most consistent with a managed GC/runtime virtual
  segment. Its changing committed/resident portion and relationship to GC
  counters support that interpretation, but VMMap does not classify it as
  `.NET Managed Heap` and the evidence does not establish object ownership.
* The 512 MiB WriteCombine shape is most consistent with an external
  Windows/Vulkan implementation virtual-allocation boundary because the
  application source has no matching request and the root Vulkan callback
  ledger did not see it. “External” is a boundary classification, not a claim
  that the NVIDIA driver owns or leaked it.
* The 1 GiB and smaller WriteCombine/RW shapes are related candidates, but
  their owner remains unresolved.

### Uncertain

* The root callback probe does not cover child Vulkan object calls that pass a
  null allocator or implementation allocations outside `VkAllocationCallbacks`.
* The non-elevated WPR attempt did not produce allocation stacks. Without that
  evidence, the external boundary cannot be named more precisely.
* A .NET heap dump may be useful only if WPR or another lower-intrusion trace
  first attributes the large RW segment to managed object retention. It was not
  justified for this investigation.
* The process-tree peak outlier in diagnostic trial 3 prevents a claim that
  instrumentation has no effect on peak timing. It does not change the
  repeated region shapes or callback result.

## Ranked hypotheses and falsification

1. **Managed GC/runtime virtual segment — likely shape, not a leak finding.**
   Falsified if an address-aware trace attributes the 32,437.25 MiB reservation
   to a non-managed caller, or if the reservation/commit movement does not
   correlate with runtime segment activity across a matched frontier.
2. **External Windows/Vulkan virtual-allocation boundary — strongest unresolved
   owner boundary.** Falsified if WPR allocation stacks show SharpEmu or a
   managed allocator requesting the 512 MiB WriteCombine region, or if a
   synchronized child-object callback probe observes the same block.
3. **Related 1 GiB and 64/32 MiB regions from the same external or runtime
   boundary.** Falsified if address/stack attribution separates them into
   distinct known owners or if they disappear without a corresponding lifetime
   event.
4. **CPU backend, libc, or ordinary managed object retention as the dominant
   explanation.** Currently unsupported by source scale, matching releases,
   and the callback/GC evidence. Falsified in either direction by an address
   ledger or allocation stack that accounts for most of the remainder.

The investigation does not promote any hypothesis to “native leak,” “managed
leak,” or “driver allocation.”

## Recommended next boundary

Run one controlled, elevated WPR `VirtualAllocation` trace with the existing
target arguments and safety policy, preferably with the new probe disabled so
the trace observes the ordinary allocator boundary. Start the trace before the
emulator, stop it after the working-set cutoff, and inspect the address and
allocation stack for the 32,437.25 MiB, 512 MiB, 1 GiB, and related regions in
WPA. Keep the ETL and WPA workspace outside Git.

If WPR attributes the large reserved region to the .NET runtime but does not
answer whether objects are retained, use the smallest subsequent EventPipe or
GC diagnostic that can answer that specific question. If it attributes the
WriteCombine region to a Vulkan implementation boundary, repeat with the
narrowest valid loader/driver diagnostic available. Do not add Vulkan callbacks
for every child object until the trace shows that callback coverage is needed.

## Correction decision

No correction is justified by this evidence. Do not evict the texture cache,
release cached staging, decommit guest mappings, change queue/snapshot/shader/GPU
semantics, or alter the working-set/page-file policy. No lifecycle defect was
identified strongly enough to specify a safe correction.

If the next trace identifies a lifecycle defect, the implementation-ready
change should name the exact boundary, expected resident and committed-byte
effect, guest-observable risks, and a falsification condition before it is
implemented in a separate reviewed change.

## Verification

The narrow probe's focused deterministic tests passed: 5/5
`VulkanHostAllocationDiagnosticsTests`. The required Fast lane passed with
806/806 tests, zero warnings, and zero errors. The self-contained Windows
publish and final target matrix completed. `git diff --check` passed before the
documentation commit. The shader lane was not run because no shader or GPU
semantics changed.

Raw VMMap CSVs, JSONL diagnostics, manifests, logs, WPR output, and any target-
derived data remain outside Git under the investigation artifact root.

Related context: [startup memory ownership](STARTUP_MEMORY_OWNERSHIP.md),
[oversized detile work](OVERSIZED_DETILE_WORK.md),
[post-snapshot startup frontier](POST_SNAPSHOT_STARTUP_FRONTIER.md), and
[startup residency and resource lifetime](STARTUP_RESIDENCY_AND_RESOURCE_LIFETIME.md).
