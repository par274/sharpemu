<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup memory ownership

Status: the ownership correction was verified on 2026-08-01 for the Windows
startup-to-first-frame route of Demon's Souls v1.004.000. The target still does
not meet the character-creation checkpoint or baseline acceptance conditions.
This records a reusable ownership finding, not a run diary or a minimum-RAM
claim.

## Finding

The growth has two dominant phases:

| Phase | Owner | Interpretation |
| --- | --- | --- |
| ~3.5–4 s | Host-committed guest mappings | The direct-memory path fully commits a 0xFFD90000 (~4 GiB) mapping, followed by other guest mappings. This is committed virtual memory, not merely a reservation or working-set change. |
| ~13–19 s | Managed guest-work payloads | AGC's GPU-detile path creates raw texture snapshots in `GuestDrawTexture.TiledSource`. Before the correction, the production guest-work budget counted `RgbaPixels` but omitted `TiledSource`; the corrected boundary counts both representations. |
| Variable late stage | Vulkan device memory | Explicit `vkAllocateMemory` totals can rise from roughly 0.23 GiB to 1.56 GiB. This is a separate device-memory domain and must not be added to Windows process-private memory without host-driver evidence. |

In the clean three-run AGC allocation matrix, texture-source allocations reached
5.346 GiB in 140 allocations in every trial; linearized texture allocations were
0.124 GiB in 110 allocations. At the same frontier, managed live memory was
about 5.36 GiB and GC committed memory was 5.46–5.68 GiB. Before the correction,
one late comparable run measured 5.01 GiB with complete queue accounting while
the production accounting reported only 7.5 MiB. That difference is the
`TiledSource` ownership defect addressed below.

The guest-data pool is not the dominant owner: it plateaued near 44 MiB with
about 40 MiB cumulative allocation. The managed queue payload is the raw
`TiledSource` lifecycle, not a generic .NET GC leak.

## VMMap interpretation

Microsoft VMMap snapshots independently classified the early 0x400000000 range
as `Private Data`, 4,191,808 KiB committed/private, matching the exact guest
mapping. The 0x600000000 range was 428,032 KiB committed/private; its VMMap
`Thread Stack` label is a host classification heuristic and the emulator's
address accounting identifies it as a flexible guest mapping.

In an independent earlier diagnostic run, the late VMMap snapshot reported
10,170,204 KiB process-private, with
9,711,276 KiB in `Private Data`, 28,404 KiB in native `Heap`, 43,332 KiB in
`Mapped File`, and 430,520 KiB in `Stack`. VMMap left `Managed Heap` blank for
.NET 10. The large 0x1B6C2200000 private region had 33,215,744 KiB reserved and
3,815,060 KiB committed; its coincidence with the runtime GC counters supports
the managed-segment interpretation, but that label is an inference rather than
a VMMap semantic classification. This VMMap snapshot is not the same process
sample as the later 14.04 GiB private-memory counter sample.

The late 14.04 GiB sample had 6.61 GiB host-committed guest mappings and
5.50 GiB committed GC memory, accounting for about 86% of process private
memory. The remaining roughly 1.93 GiB is not assigned by this investigation;
the live-GC comparison gives about 2.08 GiB because it includes a different
managed-memory view. Explicit Vulkan device-memory totals are separate from
Windows process-private memory. The instrumentation did not close out Vulkan
implementation host-allocation callbacks, FFmpeg/Bink allocations, or every
native allocation bucket, so those remain uncertainty rather than inferred
causes.

## Verified correction

Commit `0f0fc255777f9d4c09cb01e18a59cc5c6eefc49a` moves the ownership boundary
to one production payload calculation. It counts each reachable managed
`byte[]` once by reference within a pending work record, including:

- compute shader bytes, texture `RgbaPixels` and `TiledSource`, and global buffers;
- draw shader bytes, texture payloads, global buffers, vertex buffers, and the
  optional index buffer; and
- image-write pixels.

The total is calculated once at enqueue, stored in `PendingGuestWork`, and used
unchanged for admission, requeue, and completion. Requeueing does not add it a
second time; completion subtracts exactly that stored value. The old diagnostic
“actual” queue categories and their second complete traversal were removed, so
`managed.guest-queue-retained` is now the production total. Zero-payload
ordered work remains counted as an item but contributes no bytes. A single item
larger than the 256 MiB default is deliberately admitted when the queue has no
payload, preserving progress and the render-thread follow-up deadlock rule.

Focused synthetic tests cover both texture representations, shared references,
shader/global/vertex/index/image payloads, oversized admission, enqueue/requeue/
completion, and diagnostics enabled or disabled.

## Controlled result

The final inspected trials used the same clean commit, target identity, eboot
hash, arguments, host, 6 GiB working-set limit, and page-file policy:

| Run | SharpEmu child | Duration | Termination | Peak WS | Peak private | Retained queue max/end | Visible checkpoint |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |
| `20260801T023729539Z-0f0fc25-trial-01` | 5592 | 21.6 s | working-set-limit | 9.36 GiB | 14.24 GiB | 5,129.25 / 5,129.25 MiB | title splash frame |
| `20260801T023753333Z-0f0fc25-trial-01` | 21596 | 22.8 s | working-set-limit | 9.50 GiB | 14.38 GiB | 5,129.25 / 5,129.25 MiB | title splash frame |
| `20260801T023818283Z-0f0fc25-trial-01` | 20096 | 22.5 s | working-set-limit | 8.28 GiB | 12.57 GiB | 5,129.25 / 5,129.25 MiB | title splash frame |

The runner records aggregate process-tree peaks while enforcing the unchanged
6 GiB working-set stop, so the sampled peak can overshoot the stop threshold
during termination.

The diagnostic time series confirms that the corrected production total now
includes the late 5.01 GiB detile payload. Ordinary retained totals stayed at
or below 1.82 MiB before that late single oversized payload; the default budget
therefore throttles normal backlog while the deliberate oversized-item rule
admits the one work item. The retained count also includes zero-byte ordered
follow-ups. Completed smaller work released its exact retained total back to
zero in the traces. The old trials did not distinguish queue membership from
active ownership at the safety cutoff. Focused follow-up instrumentation shows
that the item was ready at the queue head, was taken, and was executing; its
corresponding release was not expected before the execution call returned. No
`managed.guest-queue-actual-*` category appeared, and the old ordinary-versus-
complete accounting gap is gone.

The three runs did not reach character creation. Captured windows showed the
first rendered Demon's Souls title splash frame; no later stable checkpoint was
visible. Peak GC committed memory was 5.71–5.82 GiB and peak process-private
memory was 12.57–14.38 GiB, so these trials do not demonstrate a material
working-set reduction at the previous failure frontier. The unchanged early
guest mapping and other non-queue owners remain separate contributors.

## Remaining uncertainty and next frontier

The correction is validated at the queue ownership boundary, but it does not
make the 256 MiB budget a hard cap for one oversized payload. The focused
follow-up finding is recorded in OVERSIZED_DETILE_WORK.md: the item is a ready
queue head taken by the presenter, and sixteen distinct TiledSource arrays
refer to one guest source range with compatible recorded metadata because image
bindings are materialized eagerly without a dispatch-local snapshot table. The
next implementation frontier is that producer-side repeated capture, while
preserving resource visibility and render-thread follow-up safety. This change
does not address suspended
AGC waits, zero-dimension dispatches, descriptor divergence, scalar-pointer
fallback, shaders, or unrelated compatibility behavior. The early guest-commit
diagnosis remains separate and is falsified only by a matched VMMap snapshot
showing the 0xFFD90000 range reserved but not committed.
