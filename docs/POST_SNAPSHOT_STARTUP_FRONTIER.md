<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Post-snapshot startup frontier

Status: diagnostic finding from 2026-08-01. This document does not propose or
implement a compatibility or memory fix. The dispatch-local snapshot
correction is treated as established and is only followed here to identify
the next boundary.

## Finding

The corrected oversized dispatch is no longer the startup frontier. It reaches
`completed` in every run, with its retained payload returning to zero. The
first material post-correction growth is ordinary presenter resource
materialization: the current texture cache and explicit Vulkan allocations
rise sharply during the next few seconds. Later, guest host mappings commit
another roughly 0.18--0.32 GiB. The process then reaches the unchanged
working-set safety cutoff while guest work is still advancing.

This is a combined boundary, not a proven single-owner leak:

- The strongest explicitly tracked process-private candidate is the guest
  mapping domain, but `guest.host-committed` is a commitment total and does
  not prove that all of those pages are resident.
- The strongest explicitly retained Vulkan owner is the 20-entry texture
  cache at 624,199,168 bytes (595.3 MiB) of device allocation. Device-local
  Vulkan memory is a separate domain and is not added to process-private
  memory.
- Current GC memory, host-visible mapped Vulkan memory, and uninstrumented
  runtime/native allocations account for additional memory. The current
  instrumentation does not close the resident-working-set relationship or the
  complete native allocation gap.

There is therefore no evidence for a common blocked presenter wait or a
second oversized managed work item as the cause of the cutoff. Two of the
three diagnostic runs are idle at their final diagnostic sample; the third is
still executing an offscreen draw and has a run-specific overflow error.

## Controlled evidence

The control and diagnostic runs used target PPSA01341 Europe / EP9000
v1.004.000, eboot SHA-256
`22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`, the
same self-contained SharpEmu binary from commit `c9e9ef4`, the same arguments,
RTX 3070 Ti host, unchanged 6 GiB working-set policy, and unchanged page-file
configuration. The diagnostic argument was opt-in
`--memory-diagnostics={runDirectory}\memory-diagnostics.jsonl`. The expected
character-creation checkpoint was not observed.

Runner peak values are aggregate process-tree values. Presenter state and
ownership values below are from the SharpEmu child diagnostic stream.

| Role | Run | Corrected completion | First guest-frame event | Duration | Peak WS / private | Final diagnostic state |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| control | `20260801T075437581Z-c9e9ef4-trial-01` | 14,215 ms | 15,765 ms | 22,474 ms | 6.12 / 11.46 GiB | `presentation.idle`, queue and GPU empty |
| diagnostic 1 | `20260801T075621957Z-c9e9ef4-trial-01` | 15,064 ms | 17,050 ms | 26,953 ms | 6.53 / 11.68 GiB | `presentation.idle`, queue and GPU empty |
| diagnostic 2 | `20260801T075648930Z-c9e9ef4-trial-02` | 13,989 ms | 15,733 ms | 27,088 ms | 6.03 / 11.25 GiB | `presentation.idle`, queue and GPU empty |
| diagnostic 3 | `20260801T075716021Z-c9e9ef4-trial-03` | 14,611 ms | 16,186 ms | 24,796 ms | 6.12 / 11.50 GiB | offscreen draw active; 15 queued items |

The three diagnostic runs are comparable for the corrected lifecycle and the
early post-correction sequence. They are not interchangeable at the safety
cutoff: diagnostic 3 stops about 2.3 seconds earlier than diagnostic 2 while
an offscreen draw is active. Timing variance is reported rather than merged
into one causal state.

## Corrected dispatch and immediate successor

The dominant item is the established compute dispatch: shader address
`0x0000000448626400`, groups `27 x 15 x 72`, 40 textures, 12 global buffers,
queue `acb.compute[64]`, and payload 340,526,968 bytes (324.751823 MiB).
Across the three diagnostic runs its state sequence was:

| State | Diagnostic 1 | Diagnostic 2 | Diagnostic 3 |
| --- | ---: | ---: | ---: |
| `ready-head` | 14,778 ms | 13,654 ms | 14,294 ms |
| `taken` | 14,782 ms | 13,657 ms | 14,302 ms |
| `executing` | 14,783 ms | 13,658 ms | 14,303 ms |
| `completed` | 15,063 ms | 13,988 ms | 14,611 ms |

At completion, `pendingBytes` was zero and `completedContiguousSequence`
matched the corrected sequence in all three runs. The corrected execution
briefly entered `gpu.submission-capacity-wait` and `gpu.guest-fence-wait` in
each trace. Those waits resolved; one run recorded a guest-fence timeout and
retry before completing. This is a transient execution detail, not the later
cutoff state.

Immediately after `guest-work.complete`, the presenter executed several
ordered actions and queue-switch flushes. The first reproducible non-ordered
successor was another compute dispatch on `acb.compute[64]`, with the same
submission as the corrected item, shader address
`0x0000000448631600`, and groups `27 x 15 x 1` (sequences 772, 774, and 775
in the three runs). It completed. The following bounded trace contained the
same ordinary resource-producing chain: shaders
`0x0000000802933600`, `0x000000044861EC00`,
`0x0000000448620800`, `0x0000000448621400`, and
`0x00000004486B9500`, followed by graphics compute and offscreen work.

The first-frame milestone preceded the corrected dispatch. The first guest
frame event followed it in every run. The presenter then continued to consume
guest work rather than stopping at the corrected item.

## Last confirmed forward progress and cutoff state

The sample provider records current state, not cumulative work. At the last
diagnostic sample:

| Run | Sample time | Presenter phase / active item | Queue state | GPU state | Guest waits | Last confirmed work |
| --- | ---: | --- | --- | --- | ---: | --- |
| diagnostic 1 | 26,530 ms | `presentation.idle`, no active item | 0 bytes; completed 20,870 | 0 pending, timelines 3197/3197 | 9 outstanding; oldest 429 ms | `acquire_mem_flush`, dcb.graphics submission 68, sequence 20,870 |
| diagnostic 2 | 26,064 ms | `presentation.idle`, no active item | 0 bytes; completed 20,311 | 0 pending, timelines 3107/3107 | 3 outstanding; oldest 360 ms | compute `0x00000004485A7A00`, 2 x 1 x 1, sequence 20,311 |
| diagnostic 3 | 24,036 ms | `guest-work.enter`; offscreen draw `0x0000000448718B00`, one target | 1,902,104 bytes; completed 21,084, executing 21,085 | 1 pending, timelines 3218/3217 | 19 outstanding; oldest 37 ms | dcb.graphics submission 32, sequence 21,085 |

The guest wait counts are outstanding registry entries, not proof that the
presenter is blocked on one of them. The logs for these runs contain
`producer=none-observed; remaining-suspended` AGC wait warnings, but the idle
runs have no active presenter wait and their completed sequence continues to
advance. Diagnostic 3 also contains two existing offscreen-draw
`System.OverflowException` failures for the active 2048 x 2048 draw. Because
that item and error are not common to the other two cutoff states, they are a
timing-dependent alternative hypothesis, not the primary matrix finding.

## Time-aligned memory series

Values are current totals at the nearest 500 ms diagnostic sample. `GC heap /
committed` is current managed state. `guest queue` is currently retained
payload, not the cumulative enqueued counter. `Vulkan device` is explicit
`vkAllocateMemory` ownership; it is deliberately not added to process-private
memory.

| Run | First sample after completion | About +5 s | Last diagnostic sample |
| --- | --- | --- | --- |
| diagnostic 1 | 15,524 ms: WS 4.87 GiB; guest committed 6.72 GiB; GC 0.84 / 1.10 GiB; Vulkan 1.63 GiB / 35.5 MiB mapped; cache 407.5 MiB; queue 5.2 MiB | 20,027 ms: WS 5.39 GiB; guest 6.72 GiB; GC 0.91 / 1.05 GiB; Vulkan 2.54 GiB / 112.6 MiB; cache 595.3 MiB; queue 1.4 MiB | 26,530 ms: WS 6.38 GiB; guest 6.89 GiB; GC 1.04 / 1.59 GiB; Vulkan 2.56 GiB / 134.9 MiB; cache 595.3 MiB; queue 0 |
| diagnostic 2 | 14,067 ms: WS 4.71 GiB; guest committed 6.69 GiB; GC 0.79 / 1.02 GiB; Vulkan 1.56 GiB / 35.3 MiB mapped; cache 385.0 MiB; queue 0 | 19,091 ms: WS 5.63 GiB; guest 6.69 GiB; GC 0.98 / 1.48 GiB; Vulkan 2.50 GiB / 79.1 MiB; cache 595.3 MiB; queue 0 | 26,064 ms: WS 5.96 GiB; guest 6.88 GiB; GC 1.07 / 1.25 GiB; Vulkan 2.55 GiB / 124.4 MiB; cache 595.3 MiB; queue 0 |
| diagnostic 3 | 15,032 ms: WS 4.64 GiB; guest committed 6.58 GiB; GC 0.82 / 1.05 GiB; Vulkan 1.60 GiB / 35.6 MiB mapped; cache 385.0 MiB; queue 0 | 19,535 ms: WS 5.27 GiB; guest 6.66 GiB; GC 0.75 / 1.13 GiB; Vulkan 2.54 GiB / 91.8 MiB; cache 595.3 MiB; queue 0 | 24,036 ms: WS 5.95 GiB; guest 6.89 GiB; GC 1.21 / 1.39 GiB; Vulkan 2.60 GiB / 130.7 MiB; cache 595.3 MiB; queue 1.8 MiB |

The first clear post-correction step is the resource jump: cache ownership
reaches 624,199,168 bytes and 20 resources, while total explicit Vulkan
device allocation rises by roughly 0.9 GiB in about five seconds. The cache
then remains at that size. Guest host commitment is initially nearly flat in
diagnostics 1 and 2, then rises from 6.72/6.69 GiB to 6.89 GiB; diagnostic 3
shows the same late rise from 6.58 GiB. This separates the early resource
materialization from the later mapping growth.

## Ownership accounting at the cutoff

| Domain | Observed late value | Interpretation |
| --- | ---: | --- |
| Process working set / private committed | Runner peaks 6.03--6.53 / 11.25--11.68 GiB | Measurement of the cutoff, not an owner classification. WS is lower than several committed-domain totals. |
| Current GC heap / GC committed | 1.04--1.21 / 1.25--1.59 GiB at the final samples | Current managed state; not the cumulative allocation counters. A transient 2.03 GiB GC heap occurred in diagnostic 2 but was collected before its final sample. |
| Current managed guest queue | 0--1.8 MiB | Rules out the corrected 324.75 MiB payload and another retained oversized queue item as the common owner. |
| Current managed guest data pool | 47.8--51.1 MiB | Small retained pool; not dominant. |
| Cumulative managed allocations | Guest queue enqueued 3.73--3.87 GB; AGC texture counters 1.1--2.2 GB | Historical allocation counters. They must not be added to retained memory. |
| Guest host mappings | 6.88--6.89 GiB committed at final samples | Largest explicitly tracked process-private domain candidate. Commitment is retained accounting, not a residency measurement. |
| Explicit Vulkan device allocations | 2.55--2.60 GiB, including about 1.34--1.37 GiB detile, 0.60 GiB texture, and 0.44--0.45 GiB offscreen | Current device allocation domain. Do not add to process-private memory without host-driver evidence. |
| Host-visible mapped Vulkan allocations | 124.4--134.9 MiB, mostly guest-buffer mappings | A possible process working-set contributor, but the relationship to the process counters is not isolated. |
| Resource-cache ownership | 624,199,168 bytes, 20 texture resources | Current retained cache ownership; stable after the early jump. It is a material Vulkan owner but not enough to explain the total WS by itself. |
| Explicit native libc heap | No nonzero category in these samples | Does not rule out runtime, loader, driver, Vulkan implementation, or other native allocations outside this counter. |
| Pending/executing guest GPU work | 0/0 in diagnostics 1 and 2; 1/1 in diagnostic 3 | Not a common retained GPU backlog. The third state is run-specific. |

A crude subtraction of guest host committed and GC committed from process
private leaves roughly 3.1 GiB per late sample, but this is not a formal
ownership sum: mapped ranges, runtime segments, stacks, JIT/code, and native
allocations have not been proven disjoint from every counter. No Vulkan
device-local bytes were included in that subtraction. A matched late VMMap or
working-set query for the actual child would be needed to turn the guest
mapping candidate into a resident-working-set attribution.

## Hypotheses

| Hypothesis | Result |
| --- | --- |
| Corrected dispatch still retains its payload | Rejected. It completes in all runs and `pendingBytes` returns to zero. |
| A second oversized or repeated managed work item dominates | Not observed. No second oversized event appears; queue-retained bytes are zero or a few MiB at cutoff. |
| A presenter/GPU wait prevents forward progress | Rejected as the common cause. Guest sequences advance into the 20,000s, two runs are idle with completed GPU timelines, and the corrected dispatch wait resolves. |
| Retained texture/resource cache contributes | Established as a material current Vulkan owner: 20 resources and 595.3 MiB cache allocation. Whether those resources are guest-correctly live is unresolved. |
| Guest mappings contribute to the process working set | Strong candidate from the size and late commitment growth, but residency is not proven by the current category. |
| Native/runtime allocations explain the remainder | Unresolved attribution gap. Explicit libc accounting is zero, but it does not cover all native/runtime/driver ownership. |
| Diagnostic 3's offscreen draw is the common blocker | Rejected as the primary finding because diagnostics 1 and 2 reach later idle states without that active item or overflow. |

## Narrow next boundary and falsification

The narrowest safe implementation boundary for the next correction is the
ownership seam around startup-created `TextureResource` cache entries:
`_textureCache` insertion, the corresponding `vulkan.texture-cache-retained`
total, and deferred destruction. Any future behavior change should be limited
to a cache entry whose guest-visible lifetime is independently shown to have
ended; these runs do not justify a general eviction policy or a queue-budget
change.

The process-private side still needs one bounded experiment at
`PhysicalVirtualMemory` mapping commit/release identity and host working-set
residency before changing guest mapping behavior. That is the next diagnostic
boundary if the goal is to reduce the actual safety cutoff. No correction to
guest waits, the corrected payload accounting, the 6 GiB policy, or the
page-file configuration is justified by this evidence.

The diagnosis would be falsified or materially changed by any of the
following:

- a matched late VMMap/working-set capture showing the large guest mappings
  committed but predominantly nonresident, with another named domain carrying
  the WS;
- a bounded resource-lifetime trace showing the 20 cached resources are
  released before the WS rise, or showing a different resource owner growing
  after the cache plateau;
- three comparable runs stopping in the same guest-fence producer/completion
  wait with no sequence progress and no completed GPU timeline;
- a matched run in which queue-retained payload grows to hundreds of MiB or a
  second oversized item becomes reproducible; or
- reaching the nickname prompt under the unchanged safety policy, which would
  move the startup frontier even if the ownership attribution remained useful.

Raw target and diagnostic artifacts remain outside Git. `docs/BASELINE.md` is
unchanged because character creation was not reached. The historical
oversized-work finding remains in `docs/OVERSIZED_DETILE_WORK.md`.
