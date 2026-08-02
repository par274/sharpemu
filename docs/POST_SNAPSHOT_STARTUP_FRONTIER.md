<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Post-snapshot startup frontier

Status: diagnostic finding from 2026-08-02. Commit `e2f88667114da6f7a3fbbdea318ea2435603515a`
adds the bounded, opt-in Windows guest-residency measurement described in
`docs/SOURCES.md`. No memory, guest-mapping, allocation, eviction, GC, Vulkan,
or page-file correction was implemented.

## Finding

The earlier name-reveal and character-creation runs diverged after the short
run's name-reveal frontier. The divergence is not reproducible as a simple
elapsed-time counter split: the two runs had different startup headroom and
different scene progress at the same elapsed times. In the character-creation
run, the main menu, offline prompt, and body-type screen were observed. At the
body-type sample, child working set was 9.213 GiB, physical availability was
1.871 GiB, and child private memory was 18.683 GiB. Regaining 2 GiB or 3 GiB
of physical availability at that instant would require observed working-set
deltas of at least 0.129 GiB or 1.129 GiB respectively, assuming the other
owners did not change. Those are counter deltas, not guaranteed reclaimable
bytes.

The three residency pilots used the same published executable,
target identity, arguments, host, and conservative policy. All three reached
the main-menu movie; runs 1 and 3 completed that movie, while run 2 stopped
while it was attached. None reached the offline prompt or character creation
under the 9 GiB / 2 GiB policy. This is consistent with a bounded measurement
at the requested frontier; it is not evidence that the diagnostic made the
title reach character creation.

One corrected, one-shot validation pilot later reached the character-creation
name prompt and then showed the entered name and class screen. The attended
target was stopped after that observation. This pilot validates the revised
measurement fields, but it is not one of the three comparable baseline runs:
the diagnostic executable came from the changed working tree, and the
runner's aggregate metrics ended at 117.968 s, before the 170 s residency
scan. No aggregate process-tree counter, physical-availability, or commit-
headroom sample is claimed for the scan instant.
The diagnostic identified the actual mitigated SharpEmu child as PID 10688;
the runner had two processes in its last samples.

The one-shot probe triggered on the actual SharpEmu child near 8 GiB working
set and queried the union represented by the pre-scan guest host-mapping
snapshot with Windows `QueryWorkingSetEx`. Every query completed without a
chunk failure:

| Trial | Child WS / private before query | Resident bytes attributed to pre-scan union | Apparent share* | Apparent remainder* | Queried / resident / nonresident-or-invalid pages | Scan / query |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `054629754` | 8.046 / 16.537 GiB | 4.824 GiB | 59.96% | 3.222 GiB | 2,700,346 / 1,264,633 / 1,435,713 | 233 / 225 ms |
| `055052157` | 8.265 / 17.119 GiB | 4.932 GiB | 59.67% | 3.334 GiB | 2,692,330 / 1,292,811 / 1,399,519 | 329 / 294 ms |
| `055347815` | 8.135 / 16.302 GiB | 4.870 GiB | 59.86% | 3.266 GiB | 2,700,282 / 1,276,534 / 1,423,748 | 246 / 238 ms |

Each query used at most 8,192 pages and a 131,072-byte working-set buffer.
The scan copied 1,340–1,381 current mapping records, normalized them into
the same number of disjoint ranges, and retained no per-page data after
producing the result. `QueryFailurePageCount` was zero in all three retained
results; the cleared `Valid` bit counts above are therefore
nonresident-or-invalid pages, not API call failures.

\* These pilots predate the temporal-boundary fields added by this patch. Each
retained result has one process counter sample before the query and no
after-query process sample or mapping snapshot. The apparent share and
remainder are arithmetic point estimates, not exact values: working-set
change during the 233–329 ms query interval was not captured, and mapping-set
stability was not captured. The revised diagnostic records both counter
samples, their derived range, and the before/after mapping comparison. The
measured pre-scan guest domain is large enough in aggregate that a proven
lifecycle or representation improvement could exceed 2 GiB, but its resident
pages are not thereby stale or disposable.

The corrected validation result was a complete bounded asynchronous
observation:

| Child WS before / after | Child private before / after | Mapping snapshot | Guest resident | Resident share range | Working-set-minus-guest range | Queried / resident / nonresident-or-invalid pages | Query failures; scan / query |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8.095 / 8.200 GiB | 16.415 / 16.819 GiB | 1,345 / 1,345; stable; 0 added, 0 removed, 0 changed | 4.459 GiB | 54.37–55.08% | 3.636–3.741 GiB | 2,700,858 / 1,168,798 / 1,532,060 | 0 pages; 254 / 233 ms |

Because the before and after mapping snapshots were identical and the query
failure count was zero, this result's resident total belongs to the exact
current mapping union at the query boundary. It remains asynchronous: the
working-set counters changed by 0.105 GiB during the 233 ms Windows query, so
the report retains a percentage and remainder range rather than a single
counter-derived value. The largest retained temporary query buffer was 128
KiB.

The runner's aggregate process-tree observations remained separate from the
child measurement:

| Trial | Termination | Peak tree WS / private | Minimum physical | Minimum commit headroom | Duration |
| --- | --- | ---: | ---: | ---: | ---: |
| `054629754` | physical-headroom limit | 8.383 / 16.803 GiB | 1.766 GiB | 22.929 GiB | 190.04 s |
| `055052157` | physical-headroom limit | 8.872 / 18.654 GiB | 1.892 GiB | 21.879 GiB | 153.04 s |
| `055347815` | working-set limit | 9.078 / 17.185 GiB | 2.028 GiB | 23.485 GiB | 185.45 s |

All launches passed the required preflight of at least 10 GiB physical
availability and 30 GiB commit headroom. The page file remained fixed at
32,768 / 32,768 MiB. No SharpEmu, VMMap, or WPR process remained after the
trials.

## Ownership and lifetime

The dominant recurring range is `0x0000000400000000`, reserved and committed
at `0xFFD90000` bytes (4,093.6 MiB). Its resident contribution was 1.832,
2.285, and 1.842 GiB in the three trials. The mapping event stream recorded
one full allocation at 3.030–3.137 s in every trial and no release before the
safety stop. Existing ownership evidence identifies this range as the
direct-memory path; the `0x0000000600000000` range is the known flexible guest
mapping. Both were non-executable, fully committed, and not reserve-only.

The source boundary is `sceKernelAllocateDirectMemory` /
`sceKernelMapDirectMemory` through `PhysicalVirtualMemory.AllocateAt` and its
tracked `MemoryRegion`. The 4,093.6 MiB direct mapping is below the current
large-reserve full-commit cutoff, so the host backing is committed at
allocation. The source comments preserve a guest contract in which titles
may walk guest memory through raw host pointers; the region remains guest
address-space state until an unmap/clear lifetime transition. The observed
allocation and persistence establish ownership and lifetime, not that the
guest has stopped accessing any page.

The retained raw `memory-diagnostics.jsonl` streams were rechecked around the
old scan windows. There were zero `guest-host-mapping` events in
`186775–189008 ms`, `147875–150204 ms`, and `180760–183006 ms` for trials 1–3
respectively. That is evidence that no mapping event was recorded in those
windows, but it is not a before/after mapping snapshot; mapping-set stability
was therefore not captured by the three historical pilots. In the corrected
validation pilot, the query-counter window was `168772–171005 ms`; it also
contained zero mapping events, with the last event before it at 166062 ms and
the first event after it at 176913 ms. The explicit before/after snapshots,
not the event absence alone, establish stability for that pilot.

Top resident mapping shapes recurred across the three ASLR-varying trials:

| Base / shape | Reserved = committed | Resident by trial |
| --- | ---: | ---: |
| `0x400000000` direct mapping | 4,093.6 MiB | 1.832 / 2.285 / 1.842 GiB |
| `0x102A400000` | 320.0 MiB | 320.0 / 320.0 / 320.0 MiB |
| Two additional ~320 MiB ranges per trial | 320.1 MiB each | ~320 MiB each when ranked |
| `0x1009000000` | 352.0 MiB | 153.9 MiB in every trial |
| `0x600000000` flexible mapping | 418.0 MiB | 141.4 / 136.6 / 140.7 MiB |

The ~320 MiB shapes moved in base address between trials, consistent with
ordinary allocation placement; the fixed direct and flexible ranges recurred.
This is address-correlated ownership evidence, not an inference that a large
resident range is stale.

The corrected pilot's top six ranked mappings were:

| Base | Reserved | Committed | Resident |
| --- | ---: | ---: | ---: |
| `0x400000000` | 4,093.6 MiB | 4,093.6 MiB | 1,886.3 MiB |
| `0x105EC00000` | 320.1 MiB | 320.1 MiB | 320.0 MiB |
| `0x102A400000` | 320.0 MiB | 320.0 MiB | 320.0 MiB |
| `0x1072D00000` | 320.0 MiB | 320.0 MiB | 320.0 MiB |
| `0x1009000000` | 352.0 MiB | 352.0 MiB | 154.0 MiB |
| `0x600000000` | 418.0 MiB | 418.0 MiB | 139.2 MiB |

The corrected pilot repeats the direct, flexible, 352 MiB, and approximately
320 MiB mapping shapes. The dominant owner shape therefore recurs across all
four observations; the lower corrected resident total does not identify a
different owner or justify a lifecycle change.

The nearest existing memory-diagnostics samples provide owner context. They
were enabled only for the requested GC, queue, cache, and Vulkan scalar state;
the pre-scan mapping ranges and residency observations came from the new
probe. Cumulative allocation counters are excluded from ownership arithmetic.

| Trial | GC heap / committed | Pending queue items / bytes | Texture cache entries; image / staging | Mapped host-visible Vulkan | Explicit device-local Vulkan |
| --- | ---: | ---: | ---: | ---: | ---: |
| `054629754` | 1.835 / 1.852 GiB | 0 / 0 | 28; 1.300 / 0.032 GiB | 0.282 GiB | 3.767 GiB |
| `055052157` | 1.088 / 2.017 GiB | 7 / 0 | 40; 1.661 / 0.032 GiB | 0.281 GiB | 4.865 GiB |
| `055347815` | 2.063 / 2.083 GiB | 0 / 0 | 27; 0.987 / 0.032 GiB | 0.290 GiB | 3.482 GiB |
| corrected validation | 1.856 / 1.879 GiB | 0 / 0 | 29; 1.284 / 0.032 GiB | 0.261 GiB | 3.693 GiB |

Device-local Vulkan bytes are a separate GPU allocation domain and are not
added to process working set or private memory. The apparent 3.222–3.334 GiB
remainder is not assigned to GC, queue, cache, or mapped host-visible Vulkan
solely from these counters; it remains a runtime/native/graphics boundary for
future allocation attribution. Because the retained pilots lack an after-scan
working-set counter, the remainder has no measured temporal range.

## Revisions, target, and protocol

The target was `PPSA01341`, Europe / `EP9000`, version `1.004.000`, with eboot
SHA-256
`22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`.
Arguments were `--cpu-engine=native --log-level=debug --window-mode=windowed
--resolution=1280x720 --vsync=off` on the Windows RTX 3070 Ti host.

The three historical pilots used the clean self-contained executable published
at commit `e2f8866` with SHA-256
`805AAA8A7D89034DA8720520B1DD5393EDDF4B9603CDEFC3B39E3725F13F99A7`.
The pilot used a 9 GiB aggregate working-set limit, 2 GiB minimum physical
availability, 4 GiB minimum commit headroom, 900 s wall time, and 250 ms
runner sampling. The one-shot child trigger was approximately 8 GiB actual
SharpEmu working set. No VMMap, WPR, or unrelated capture system was enabled.
The corrected pilot's preflight was 10.02 GiB available physical memory and
39.80 GiB commit headroom; the fixed page file remained 32,768 / 32,768 MiB.
The corrected validation pilot used the schema-2 executable published from the
instrumentation working tree at commit `30babd7` with SHA-256
`EBB56C3AB65824539277313CAE1E9514C5B7C5CBAB2892B77F4B03879638BC1E`.

## Conclusions and next boundary

1. The guest-mapping union is a major resident owner at the measured frontier:
   4.824–4.932 GiB in the three historical observations and 4.459 GiB in the
   corrected stable-snapshot validation, or 54.37–55.08% of that pilot's child
   working set. The old pilots' percentages remain temporally unbounded; the
   corrected pilot bounds its counter uncertainty.
2. The 4 GiB direct-memory range is a real guest-visible allocation with an
   observed allocation event and no release before the safety stop. Its
   resident contribution sometimes exceeds 2 GiB, but the source contract
   does not establish that those pages are no longer accessible.
3. The current evidence supports **0 GiB of implementation-ready recovery**.
   Decommit, sparse commitment, eviction, sharing, or representation changes
   would be guest-semantic changes until an access/lifetime experiment proves
   the affected pages are dead at this frontier.
4. The single narrow boundary for review is the direct-memory backing seam
   from `KernelMapDirectMemory` to `PhysicalVirtualMemory.AllocateAt`. It is a
   measurement-backed candidate for a future contract experiment, not a
   correction to implement from this task.

The expected recoverable resident memory under the current ownership and
access contract is therefore 0 GiB. The diagnosis would be falsified or
materially weakened by a matched late stable scan below 2 GiB in the guest
union with a named non-guest owner accounting for the remainder, or by an
access/lifetime trace proving that the direct mapping is dead at the proposed
release point. A correct future reduction must preserve raw guest-pointer
access, mapping identity, and unmap/clear semantics.

`docs/BASELINE.md` remains unchanged: one earlier clean run reached character
creation, but the baseline remains pending because three comparable successful
runs have not been completed. Raw target data, screenshots, diagnostics,
manifests, logs, and analysis artifacts remain outside Git.
