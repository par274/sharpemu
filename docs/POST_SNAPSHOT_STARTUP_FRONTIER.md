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

The three exact-residency pilots used the same published executable,
target identity, arguments, host, and conservative policy. All three reached
the main-menu movie; runs 1 and 3 completed that movie, while run 2 stopped
while it was attached. None reached the offline prompt or character creation
under the 9 GiB / 2 GiB policy. This is consistent with a bounded measurement
at the requested frontier; it is not evidence that the diagnostic made the
title reach character creation.

The one-shot probe triggered on the actual SharpEmu child near 8 GiB working
set and queried the exact union of current guest host-mapping ranges with
Windows `QueryWorkingSetEx`. Every query completed without a chunk failure:

| Trial | Child WS / private at measurement | Exact guest resident | Guest share of child WS | Remainder | Queried / resident / invalid pages | Scan / query |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `054629754` | 8.046 / 16.537 GiB | 4.824 GiB | 59.96% | 3.222 GiB | 2,700,346 / 1,264,633 / 1,435,713 | 233 / 225 ms |
| `055052157` | 8.265 / 17.119 GiB | 4.932 GiB | 59.67% | 3.334 GiB | 2,692,330 / 1,292,811 / 1,399,519 | 329 / 294 ms |
| `055347815` | 8.135 / 16.302 GiB | 4.870 GiB | 59.86% | 3.266 GiB | 2,700,282 / 1,276,534 / 1,423,748 | 246 / 238 ms |

Each query used at most 8,192 pages and a 131,072-byte working-set buffer.
The scan copied 1,340–1,381 current mapping records, normalized them into
the same number of disjoint ranges, and retained no per-page data after
producing the result. The measured exact guest domain is large enough in
aggregate that a proven lifecycle or representation improvement could exceed
2 GiB, but its resident pages are not thereby stale or disposable.

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

The nearest existing memory-diagnostics samples provide owner context. They
were enabled only for the requested GC, queue, cache, and Vulkan scalar state;
the exact mapping ranges and residency came from the new probe. Cumulative
allocation counters are excluded from ownership arithmetic.

| Trial | GC heap / committed | Pending queue items / bytes | Texture cache entries; image / staging | Mapped host-visible Vulkan | Explicit device-local Vulkan |
| --- | ---: | ---: | ---: | ---: | ---: |
| `054629754` | 1.835 / 1.852 GiB | 0 / 0 | 28; 1.300 / 0.032 GiB | 0.282 GiB | 3.767 GiB |
| `055052157` | 1.088 / 2.017 GiB | 7 / 0 | 40; 1.661 / 0.032 GiB | 0.281 GiB | 4.865 GiB |
| `055347815` | 2.063 / 2.083 GiB | 0 / 0 | 27; 0.987 / 0.032 GiB | 0.290 GiB | 3.482 GiB |

Device-local Vulkan bytes are a separate GPU allocation domain and are not
added to process working set or private memory. The 3.222–3.334 GiB remainder
is not assigned to GC, queue, cache, or mapped host-visible Vulkan solely from
these counters; it remains a runtime/native/graphics boundary for future
allocation attribution.

## Revisions, target, and protocol

The target was `PPSA01341`, Europe / `EP9000`, version `1.004.000`, with eboot
SHA-256
`22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`.
Arguments were `--cpu-engine=native --log-level=debug --window-mode=windowed
--resolution=1280x720 --vsync=off` on the Windows RTX 3070 Ti host.

The clean self-contained executable was published at commit `e2f8866` with
SHA-256
`805AAA8A7D89034DA8720520B1DD5393EDDF4B9603CDEFC3B39E3725F13F99A7`.
The pilot used a 9 GiB aggregate working-set limit, 2 GiB minimum physical
availability, 4 GiB minimum commit headroom, 900 s wall time, and 250 ms
runner sampling. The one-shot child trigger was approximately 8 GiB actual
SharpEmu working set. No VMMap, WPR, or unrelated capture system was enabled.

## Conclusions and next boundary

1. The exact guest-mapping union is a major resident owner at the measured
   frontier: 4.824–4.932 GiB, or about 60% of child working set.
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

The diagnosis is falsified or materially weakened if a matched late scan puts
less than 2 GiB in the exact guest union while a named non-guest owner accounts
for the remainder, or if a guest-access/lifetime trace shows that the direct
mapping remains live through the proposed release point. A correct future
reduction must preserve raw guest-pointer access, mapping identity, and
unmap/clear semantics.

`docs/BASELINE.md` remains unchanged because character creation was not
reached. Raw target data, screenshots, diagnostics, manifests, logs, and
analysis artifacts remain outside Git.
