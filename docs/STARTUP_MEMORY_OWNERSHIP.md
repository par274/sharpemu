<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup memory ownership

Status: verified on 2026-08-01 for the Windows startup-to-first-frame route of
Demon's Souls v1.004.000. This records a reusable ownership finding, not a run
diary or a minimum-RAM claim.

## Finding

The growth has two dominant phases:

| Phase | Owner | Interpretation |
| --- | --- | --- |
| ~3.5–4 s | Host-committed guest mappings | The direct-memory path fully commits a 0xFFD90000 (~4 GiB) mapping, followed by other guest mappings. This is committed virtual memory, not merely a reservation or working-set change. |
| ~13–19 s | Managed guest-work payloads | AGC's GPU-detile path creates raw texture snapshots in `GuestDrawTexture.TiledSource`. The guest-work byte budget counts `RgbaPixels` but omits `TiledSource`, so the queue can retain multi-GiB managed arrays while believing it is under the byte limit. |
| Variable late stage | Vulkan device memory | Explicit `vkAllocateMemory` totals can rise from roughly 0.23 GiB to 1.56 GiB. This is a separate device-memory domain and must not be added to Windows process-private memory without host-driver evidence. |

In the clean three-run AGC allocation matrix, texture-source allocations reached
5.346 GiB in 140 allocations in every trial; linearized texture allocations were
0.124 GiB in 110 allocations. At the same frontier, managed live memory was
about 5.36 GiB and GC committed memory was 5.46–5.68 GiB. In a late comparable
run, complete queue accounting measured 5.01 GiB retained and 5.26 GiB ever
enqueued, while the existing accounting reported only 7.5 MiB. This accounts for
the managed ownership of the late private-memory rise and explains why the
existing safety budget does not stop it.

The guest-data pool and the ordinary reported guest-work payload are not the
dominant owners: the pool plateaued near 44 MiB with about 40 MiB cumulative
allocation, and the reported queue payload stayed below 8 MiB at the late
frontier. The managed queue payload is therefore the raw `TiledSource` lifecycle,
not a generic .NET GC leak.

## VMMap interpretation

Microsoft VMMap snapshots independently classified the early 0x400000000 range
as `Private Data`, 4,191,808 KiB committed/private, matching the exact guest
mapping. The 0x600000000 range was 428,032 KiB committed/private; its VMMap
`Thread Stack` label is a host classification heuristic and the emulator's
address accounting identifies it as a flexible guest mapping.

At the late snapshot, VMMap reported 10,170,204 KiB process-private, with
9,711,276 KiB in `Private Data`, 28,404 KiB in native `Heap`, 43,332 KiB in
`Mapped File`, and 430,520 KiB in `Stack`. VMMap left `Managed Heap` blank for
.NET 10. The large 0x1B6C2200000 private region had 33,215,744 KiB reserved and
3,815,060 KiB committed; its coincidence with the runtime GC counters supports
the managed-segment interpretation, but that label is an inference rather than
a VMMap semantic classification.

## Recommendation and falsifier

The smallest implementation-ready correction is at the existing guest-work
payload boundary: include every owned texture byte array, including
`TiledSource`, in the byte budget and completion accounting, then verify that
completed work releases the arrays. Do not change the safety cap or page file as
the correction. The early guest commit is a separate allocator-policy question;
evaluate lazy commitment of the large direct mapping independently and only
after guest virtual-memory semantics are verified.

The queue diagnosis is falsified if complete payload accounting stays below the
measured GC live total while the same texture-source counter continues to rise,
or if releasing completed `TiledSource` ownership leaves private and managed
memory unchanged. The early guest-commit diagnosis is falsified if a matched
VMMap snapshot shows the 0xFFD90000 range reserved but not committed.
