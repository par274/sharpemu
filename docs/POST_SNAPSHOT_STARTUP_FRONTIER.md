<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Post-snapshot startup frontier

Status: diagnostic finding from 2026-08-02. This document records the
post-cinematic frontier and does not propose or implement a memory or
compatibility correction. The corrected oversized dispatch remains
established; this experiment follows the later ownership boundary.

## Finding

The clean control and all three diagnostic trials reached the same
developer-confirmed visible frontier: the `Demon's Souls` name-reveal
animation after the cinematic. None reached the character-creation nickname
prompt. The main menu is the next visible screen after the name reveal, with
character creation after that, but character creation is not accepted as the
current baseline.

The dominant late-stage process-private owner is the existing guest host
mapping domain. At the last corrected-dispatch event, the child diagnostic
stream showed about 7.57, 7.65, and 7.63 GiB of committed guest host mappings.
At each run's post-event private-memory peak, that domain had grown to about
8.78, 9.67, and 10.22 GiB. The corresponding child `privateBytes` increases
were 1.22, 1.88, and 3.10 GiB. This is a strong commitment-level
reconciliation, not proof that every committed guest page was resident.

The late scene also materializes more retained Vulkan texture resources and
causes ordinary managed GC fluctuation. Those are real secondary domains but
do not explain the frontier as a single missed release:

- explicit Vulkan device allocation is a separate device-local domain and is
  not added to process-private memory;
- texture-cache lifetime records contain only `insert` events in these runs,
  with zero deferred or destroyed bytes, so the cache grows by retention and
  then stops changing near termination;
- AGC texture-source and linearized counters are cumulative allocation
  counters, not current ownership totals;
- the guest queue's retained payload returns to zero in diagnostics 1 and 3,
  and is only 17,839,264 bytes in diagnostic 2 at its cutoff; and
- no common blocked presenter/GPU wait or repeated texture recreation was
  observed.

The evidence supports expected later-scene working memory and retained
guest-address-space/resource materialization. It does not justify a memory or
compatibility correction.

## Revisions, target, and protocol

The worktree was clean before setup. `main` was fast-forwarded to merge commit
`89ec542` (PR #12, parent `178bc3a`) and the task branch is
`investigate/post-cinematic-memory-frontier`. The ignored lawful local target
configuration was preserved. The target is:

- title `PPSA01341`, Europe / `EP9000`, version `1.004.000`;
- eboot SHA-256
  `22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`;
- arguments `--cpu-engine=native --log-level=debug
  --window-mode=windowed --resolution=1280x720 --vsync=off`;
- host: Windows 11, RTX 3070 Ti, native CPU engine, normal Vulkan allocator,
  and unchanged page-file configuration.

The ordinary Release Windows control executable was published from
`89ec542` with SHA-256
`7A7F4E4761C3AB0BBBB3825C79DF9BF8BEC24EBD0A2DE58E56B8340542A2C639`.
The diagnostics were published from the runner-only protocol correction at
`1d59591` with SHA-256
`BDC38F7203F30D2A16A9573C84A693FD0E81ECC98E8E136DDF026C308DD9F2D5`.
The diagnostic trials are identical to one another in commit, executable,
target, arguments, host, safety limits, diagnostics, and VMMap settings.

The requested `7.0` GiB VMMap threshold was initially rejected by a stale
`ValidateRange(1.0, 5.9)` runner bound before any target process launched. The
separate runner-only correction `1d59591` removed only that upper bound,
retained finite-value and minimum `1.0` GiB validation, and preserved the
runtime invariant that the threshold is below the configured working-set
limit. Focused runner tests passed, including acceptance of `7.0` GiB with a
`10` GiB limit, rejection at or above the limit, and rejection below `1.0`
GiB. The Fast verification lane passed `801/801` tests. The experiment's
safety policy was unchanged:

| Working set | Minimum physical availability | Minimum commit headroom | Wall time | Runner sampling |
| ---: | ---: | ---: | ---: | ---: |
| 10 GiB | 1.5 GiB | 4 GiB | 900 s | 250 ms |

Every launch passed the required preflight of at least 5 GiB physical
availability and 6 GiB commit headroom. The control used no diagnostics,
VMMap, or WPR. Each diagnostic used one VMMap 3.4 capture in `near-cutoff`
mode at `7.0` GiB, the existing memory-diagnostics JSONL stream, and no WPR.
Host cleanup succeeded after every run; no SharpEmu or VMMap process remained.
After the final run, host recovery measured approximately 10.37 GiB physical
availability and 28.34 GiB commit headroom.

## Controlled runs

Runner peaks are aggregate process-tree values from the 250 ms safety stream.
They are kept separate from child-process diagnostic samples below.

| Role | Run | Revision / executable | Developer-confirmed checkpoint | Termination | Duration | Peak WS / private |
| --- | --- | --- | --- | --- | ---: | ---: |
| clean control | `20260802T033342512Z-89ec542-trial-01` | `89ec542` / `7A7F4E47...2A2C639` | Name-reveal animation; nickname prompt not reached | `commit-headroom-limit` | 165.755 s | 7.706 / 14.756 GiB |
| diagnostic 1 | `20260802T035523844Z-1d59591-trial-01` | `1d59591` / `BDC38F72...DD9F2D5` | Same name-reveal animation; nickname prompt not reached | `commit-headroom-limit` | 158.750 s | 7.795 / 14.067 GiB |
| diagnostic 2 | `20260802T040612791Z-1d59591-trial-01` | `1d59591` / `BDC38F72...DD9F2D5` | Same name-reveal animation; nickname prompt not reached | `commit-headroom-limit` | 154.011 s | 7.344 / 14.875 GiB |
| diagnostic 3 | `20260802T041255816Z-1d59591-trial-01` | `1d59591` / `BDC38F72...DD9F2D5` | Same animation remained visible longer; nickname prompt not reached | `commit-headroom-limit` | 189.286 s | 7.349 / 15.977 GiB |

Control and diagnostic 1 reached the same visible frontier, with diagnostic 1
ending about 7.0 seconds earlier and showing no material frontier regression.
Diagnostics 2 and 3 also reached the same visible frontier. Their different
host starting states and timing are why only the three identical diagnostics
are used for ownership comparison; the clean control is not treated as an
argument-identical trial.

Headroom values were:

| Run | Startup / minimum / final physical availability | Startup / minimum / final commit headroom |
| --- | ---: | ---: |
| control | 9.032 / 1.637 / 1.793 GiB | 18.901 / 3.923 / 3.923 GiB |
| diagnostic 1 | 8.576 / 1.858 / 2.065 GiB | 16.864 / 3.528 / 3.528 GiB |
| diagnostic 2 | 10.150 / 2.652 / 2.784 GiB | 18.323 / 3.138 / 3.138 GiB |
| diagnostic 3 | 10.615 / 3.094 / 3.094 GiB | 18.961 / 2.832 / 2.832 GiB |

Startup system commit totals were 9.437, 11.474, 10.016, and 9.378 GiB in
control / diagnostic 1 / diagnostic 2 / diagnostic 3 order. Final totals were
24.416, 24.811, 25.201, and 25.506 GiB against the same 28.340 GiB commit
limit.

All three diagnostic VMMap captures were valid, had exit code 0, and produced
exactly one CSV capture. The near-cutoff trigger is not synchronized with the
later commit-headroom termination; it is therefore used for VMMap arithmetic
only at its own capture instant. No WPR lifetime sum or historical run was
subtracted from any current sample.

The developer also reported a separate rendering/audio observation. The
PlayStation Studios phase was seen as flashing in one run and as a black
screen with laggy, segmented audio in others; the third diagnostic again had
black without flashing. A possible repeated splash sequence remains a
hypothesis. These observations are recorded for a future rendering/media
investigation, not used as memory attribution because no synchronized
frame/audio ownership counter exists here.

## Matched late-stage series

The following values are from the nearest 500 ms child diagnostic sample to
the last `guest-work-frontier` event with phase
`corrected-dispatch-complete`, followed by the highest child `privateBytes`
sample after that event. `GC heap / committed` is current managed state;
`guest.host-committed` is current committed guest host mapping ownership;
Vulkan is explicit `vkAllocateMemory` ownership. Values are GiB unless stated.

| Run | Corrected event | Child WS / private at event | Peak child private after event | Guest commit at event -> peak | GC heap / committed at event -> peak | Vulkan device at event -> peak | Cache entries; image / staging at event -> peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| diagnostic 1 | 152.674 s | 8.039 / 14.053 | 15.273 (+1.220) | 7.571 -> 8.776 (+1.205) | 0.937 / 2.457 -> 1.421 / 2.496 | 3.011 -> 3.365 (+0.353) | 25; 0.643 / 0.016 -> 28; 0.971 / 0.032 |
| diagnostic 2 | 147.021 s | 7.207 / 13.574 | 15.450 (+1.876) | 7.645 -> 9.665 (+2.020) | 1.176 / 1.607 -> 1.335 / 1.604 | 3.381 -> 3.484 (+0.103) | 24; 0.628 / 0.016 -> 27; 0.956 / 0.032 |
| diagnostic 3 | 165.525 s | 6.983 / 13.311 | 16.414 (+3.102) | 7.630 -> 10.221 (+2.592) | 1.035 / 1.232 -> 1.905 / 1.925 | 3.417 -> 3.522 (+0.105) | 30; 0.978 / 0.016 -> 32; 0.993 / 0.032 |

The late private rise is therefore closely tracked by current guest mapping
commitment. In diagnostic 3, the peak private rise was 3.102 GiB; guest
mapping commitment supplied 2.592 GiB of that change, and the GC committed
counter rose by 0.693 GiB. A non-overlapping conservative reconciliation uses
the guest mapping increase first and caps the GC contribution to the remaining
0.510 GiB; the unused GC increase is not added. This reconciles the observed
peak change without double counting, while leaving the normal VM/runtime/native
classification boundary explicit. The same pattern is present in diagnostics
1 and 2, with their smaller or more variable GC changes.

The cache did not remain at the earlier 20-entry plateau. Near the late
frontier each diagnostic inserted two or three additional retained resources;
the final counts were 28, 27, and 32. The late cache additions are material
Vulkan ownership, but their device-local byte increase is not process-private
memory and is too small to be the dominant private-growth owner.

## Current and peak ownership counters

The final diagnostic samples show the following current state. Parenthetical
values are the maximum observed child diagnostic value over the run where a
peak is meaningful.

| Domain | Diagnostic 1 | Diagnostic 2 | Diagnostic 3 |
| --- | ---: | ---: | ---: |
| GC heap used / committed | 1.421 / 2.496 GiB (2.571 / 2.847 peak) | 1.335 / 1.604 (2.505 / 2.615 peak) | 1.222 / 1.436 (2.610 / 2.645 peak) |
| GC allocation rate, final / maximum | 0.485 / 1.505 GiB/s | 0.538 / 1.554 GiB/s | 0.358 / 1.326 GiB/s |
| GC collections 0 / 1 / 2 | 1574 / 508 / 169 | 1540 / 483 / 156 | 1736 / 568 / 191 |
| AGC source / linearized allocated, cumulative | 11.099 / 3.078 GiB | 11.181 / 3.199 GiB | 12.259 / 3.198 GiB |
| AGC allocation increase after corrected event, source / linearized | 0.131 / 0.043 GiB | 0.326 / 0.058 GiB | 1.015 / 0.132 GiB |
| Guest queue enqueued, cumulative | 84.24 GiB | 83.53 GiB | 94.86 GiB |
| Guest queue retained / pending at final | 0 / 0 | 17.0 MiB / 8 | 0 / 0 |
| Guest host mappings committed / reserved | 8.776 / 8.776 GiB | 9.665 / 9.665 GiB | 10.221 / 10.221 GiB |
| Managed guest-data pool retained | 53.7 MiB | 54.0 MiB | 56.1 MiB |
| Explicit Vulkan device allocation total | 3.365 GiB | 3.484 GiB | 3.522 GiB |
| Mapped host-visible Vulkan memory | 319.0 MiB | 286.8 MiB | 291.3 MiB |
| Texture cache entries / image / staging | 28 / 0.971 / 0.032 GiB | 27 / 0.956 / 0.032 GiB | 32 / 0.993 / 0.032 GiB |
| Deferred texture / translated-resource destruction | 0 / 0 | 0 / 0 | 0 / 0 |

AGC source and linearized values above are historical allocation totals
maintained by the existing diagnostics. They are not retained byte counts and
must not be added to GC, process-private, or Vulkan values. The cumulative
guest-work counter is likewise not a queue-residency value.

The final explicit Vulkan device totals by category were:

| Category | Diagnostic 1 | Diagnostic 2 | Diagnostic 3 |
| --- | ---: | ---: | ---: |
| depth | 18.8 MiB | 18.8 MiB | 18.8 MiB |
| detile | 1.371 GiB | 1.371 GiB | 1.395 GiB |
| flip snapshot | 31.9 MiB | 31.9 MiB | 31.9 MiB |
| frame upload | 26.7 MiB | 26.7 MiB | 26.7 MiB |
| guest buffer | 252.9 MiB | 253.2 MiB | 257.0 MiB |
| host buffer | 38.3 MiB | 5.8 MiB | 6.4 MiB |
| host movie chroma / luma | 1.2 / 2.1 MiB | 1.2 / 2.1 MiB | 1.2 / 2.1 MiB |
| offscreen | 0.599 GiB | 0.765 GiB | 0.738 GiB |
| overlay / overlay staging | 384 / 517 KiB | 384 / 517 KiB | 384 / 517 KiB |
| presenter staging | 13.1 MiB | 13.1 MiB | 13.1 MiB |
| texture / texture staging | 0.986 / 32.4 MiB | 0.970 / 32.4 MiB | 1.008 / 32.4 MiB |

For rows containing three slash-separated values, the values are in
diagnostic 1 / diagnostic 2 / diagnostic 3 order. Zero-byte storage-scratch
and storage-texture-staging categories are omitted. Mapped host-visible
memory was mostly guest-buffer mappings: 252.9, 253.2, and 257.0 MiB at the
final samples; the remainder was host-persistent, frame-upload, and overlay
mapping.

At termination, presenter state was:

| Run | Phase / latest progress | Active sequence and queue | Pending guest work | Completed / executing sequence | GPU timelines |
| --- | --- | --- | ---: | ---: | ---: |
| diagnostic 1 | `presentation.idle` / `presentation.idle` | none | 0 bytes | 615069 / 0 | 89525 / 89525 |
| diagnostic 2 | `compute.resource-create` / `compute.resource-create` | 609114 / `dcb.graphics` | 8 items, 17,839,264 bytes | 609113 / 609114 | 88613 / 88613 |
| diagnostic 3 | `presentation.idle` / `presentation.idle` | none | 0 bytes | 690617 / 0 | 100765 / 100765 |

Diagnostic 2 was sampled while a resource-create item was still active. The
other two returned to idle, and all three had zero pending GPU submissions and
equal submit/completed timelines at their final samples. The traces therefore
show forward progress followed by idle or a small run-specific active tail,
not a common blocked queue. No repeated cache remove/reinsert cycle occurred.

## VMMap arithmetic

VMMap values are from the one near-cutoff CSV per diagnostic, in VMMap's KiB
units converted to bytes. They are not current final-run values and are not
subtracted from later samples. The guest rows were identified by the exact
guest mapping address ranges recorded by the runner at capture start.

| Run | VMMap total private / WS | `Private Data` private / WS | Guest mapping committed | Guest mapping resident WS | `Private Data` minus guest committed |
| --- | ---: | ---: | ---: | ---: | ---: |
| diagnostic 1 | 13.528 / 7.742 GiB | 13.056 / 7.429 GiB | 7.494 GiB | 3.780 GiB | 5.563 GiB private; 3.649 GiB WS |
| diagnostic 2 | 12.211 / 6.705 GiB | 11.750 / 6.399 GiB | 6.710 GiB | 3.240 GiB | 5.039 GiB private; 3.159 GiB WS |
| diagnostic 3 | 15.969 / 7.341 GiB | 15.467 / 6.983 GiB | 8.972 GiB | 4.253 GiB | 6.495 GiB private; 2.729 GiB WS |

The VMMap arithmetic confirms the important classification boundary: a large
part of guest mapping commitment is not resident at the capture instant. It
also leaves a material `Private Data` remainder containing GC segments,
runtime/JIT/code, stacks, graphics implementation allocations, and other
native ownership that these counters do not partition. The VMMap capture is
valid evidence for its own instant, but it does not answer the exact resident
owner at the later commit-headroom cutoff.

## Conclusions

1. The late growth between the corrected-dispatch phase and the name-reveal
   cutoff is dominated by retained guest host mapping commitment. Texture
   materialization and GC segment fluctuation are secondary.
2. At the diagnostic 3 child private peak, 3.102 GiB of private growth is
   conservatively reconciled as 2.592 GiB guest mapping commitment plus at
   most the 0.510 GiB residual of the GC committed increase. This caps the
   GC contribution and does not add Vulkan device-local memory or cumulative
   AGC allocation counters.
3. Guest mapping growth is retained committed address-space ownership, not
   merely a reservation; VMMap shows only 3.240--4.253 GiB of that domain
   resident at the three capture instants. GC is mixed transient/current
   state, the texture cache is retained, and AGC/queue allocation totals are
   cumulative.
4. Queues return to zero in diagnostics 1 and 3. Diagnostic 2 ends with a
   small active resource-create tail, not the corrected 335,582,376-byte
   payload backlog.
5. The cache continues materializing resources beyond the earlier 20-entry
   context and reaches 27--32 entries in these late runs, then remains stable
   through each run's final samples. There is no repeated recreation pattern.
6. Completed work releases its managed queue payload in diagnostics 1 and 3;
   diagnostic 2 is terminated with 17.0 MiB retained while its active item is
   still being processed.
7. The process is demonstrably advancing: completed guest sequences increase
   into the hundreds of thousands, GPU timelines complete, and two runs end
   idle. The third has a small active tail, not a common deadlock.
8. No lifecycle counter demonstrates an actual missed release. Texture
   lifetime has no remove/deferred/destroy event because the entries remain
   intentionally cached; guest mapping allocations remain part of the guest
   address space for the process lifetime; mapped Vulkan bytes are current
   map/unmap accounting. Forced safety termination prevents this matrix from
   observing normal process-teardown release events.
9. Clean and diagnostic runs reached comparable visible frontiers. The
   diagnostic overhead did not move the frontier earlier than the clean
   control; only diagnostics are used for matched ownership attribution.
10. A correction is not justified. The evidence is consistent with expected
    later-scene working memory and resource materialization, not a proven
    leak or compatibility defect.

## Instrumentation boundary and next frontier

The material unexplained boundary is the late-cutoff split of process
`Private Data` between resident guest mapping pages and the remaining
GC/runtime/native/graphics regions. Existing VMMap data measures that split
only at the one 7.0 GiB working-set trigger, while the process later reaches
the commit-headroom cutoff. No new instrumentation was added.

The single next frontier is a stable main-menu / character-creation
nickname-prompt run under the unchanged safety policy, paired with one
bounded scalar at the late cutoff: the resident working-set bytes of the
exact guest-mapping range union. That scalar would distinguish committed but
nonresident guest mappings from the remaining named or uninstrumented
`Private Data` owner. It is a proposal only; it is not implemented here.

`docs/BASELINE.md` remains unchanged because character creation was not
reached. Raw target data, screenshots, VMMap CSV files, diagnostics, manifests,
logs, and analysis artifacts remain outside Git.
