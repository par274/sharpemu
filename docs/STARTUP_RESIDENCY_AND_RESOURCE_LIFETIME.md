<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup residency and resource lifetime

Status: diagnostic finding for SharpEmu commit `8342025d3e3fb483012cc6f9da3b42d723d3c89b`.
No cache, staging, guest-memory, compatibility, or safety-policy correction was
implemented from this experiment.

## Scope and method

The target was Demon’s Souls v1.004.000, PPSA01341, Europe / EP9000, with
eboot SHA-256
`22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`.
Runs used the existing native CPU configuration at 1280x720 with vsync off on
the 16 GiB Windows host with an RTX 3070 Ti. The controlled runner retained the
6 GiB process-tree working-set limit and existing page-file configuration.

VMMap was the official Microsoft Sysinternals VMMap 3.4 binary. Its verified
command was:

```text
vmmap64.exe -p <actual SharpEmu child PID> <output.csv>
```

See the [official VMMap documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap).
Raw `.mmp`/CSV-equivalent exports, logs, manifests, and diagnostics remain
outside Git under `C:\sharpemu-investigation`.
The classification-grouped recomputation is retained there as
`residency-attribution-corrected.json`; the incomplete 110/172 scan is excluded.

The presenter diagnostics gate now enables two bounded ledgers. Guest mappings
are matched to VMMap only by exact base address and reserved size. Resource
lifetime records contain scalar texture identity and allocation/lifecycle data;
they do not retain guest payloads or `TextureResource` objects. The limits are
256 resource entries, 2,048 lifecycle events, and 4,096 guest-mapping events.

VMMap is intrusive. The nearest diagnostics sample is recorded with each scan,
but the VMMap classification is the completed scan, not a timing benchmark.

## Run matrix

All target runs stopped at the unchanged working-set safety boundary; none
reached verified character creation. The three lifetime runs reached different
guest sequence frontiers, so their absolute sequence values are not combined
into one causal state.

| Role | Run | Result | Peak WS / private | Frontier at last sample |
| --- | --- | --- | ---: | ---: |
| Clean control | `20260801T093752131Z-8342025-trial-01` | working-set limit | 6.28 / 12.24 GiB | not recorded |
| Lifetime 1 | `20260801T093934207Z-8342025-trial-01` | working-set limit | 6.04 / 11.58 GiB | 19,303 |
| Lifetime 2 | `20260801T094002711Z-8342025-trial-02` | working-set limit | 6.18 / 11.56 GiB | 23,937 |
| Lifetime 3 | `20260801T094029482Z-8342025-trial-03` | working-set limit | 6.12 / 11.56 GiB | 12,930 |
| VMMap corrected frontier | `20260801T094524470Z-8342025-trial-01` | valid, 3,115 ms scan | 6.55 / 11.94 GiB | attribution sample 18,524 ms |
| VMMap late | `20260801T094826414Z-8342025-trial-01` | valid, 3,658 ms scan | 6.02 / 11.45 GiB | attribution sample 21,526 ms |
| VMMap late | `20260801T094912261Z-8342025-trial-01` | valid, 2,568 ms scan | 6.09 / 11.64 GiB | attribution sample 16,524 ms |
| VMMap late with host-map state | `20260801T095812249Z-8342025-trial-01` | valid, 3,746 ms scan | 6.04 / 11.41 GiB | attribution sample 12,525 ms |

The first VMMap run also requested a late scan, but that CSV was incomplete
(110/172 exact guest regions) and is excluded. A concurrent three-scan attempt,
the diagnostics-omitted raw scan, and the later all-checkpoint attempt with a
process-tree shutdown failure are also excluded from causal attribution.

## Matched VMMap attribution

The complete VMMap scans classified the resident set as follows. Values are
from the VMMap scan. The two `exact guest` columns group the working set of
exact base-and-size guest matches by the region-level VMMap type; `total exact
guest resident` is their sum. `Unattributed Private Data` is calculated only as
`Private Data WS - exact guest WS classified as Private Data`.

| Capture | VMMap total WS | Private Data WS | Stack WS | Heap WS | Image WS | Mapped File WS | Shareable WS | Guest committed | Exact guest: Private Data | Exact guest: Thread Stack | Total exact guest resident | Unattributed Private Data |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Corrected frontier | 5.64 GiB | 5.35 GiB | 134.0 MiB | 27.2 MiB | 43.3 MiB | 1.9 MiB | 97.0 MiB | 6.70 GiB | 3,020.3 MiB | 132.4 MiB | 3.08 GiB (172/172) | 2.40 GiB |
| Late, `094826414` | 5.65 GiB | 5.36 GiB | 127.1 MiB | 27.7 MiB | 43.3 MiB | 1.9 MiB | 97.4 MiB | 6.70 GiB | 3,020.8 MiB | 125.6 MiB | 3.07 GiB (167/167) | 2.41 GiB |
| Late, `094912261` | 4.83 GiB | 4.54 GiB | 128.0 MiB | 26.5 MiB | 43.3 MiB | 1.9 MiB | 96.2 MiB | 6.68 GiB | 2,719.0 MiB | 126.4 MiB | 2.78 GiB (162/162) | 1.88 GiB |
| Late, `095812249` | 5.24 GiB | 4.95 GiB | 133.8 MiB | 28.2 MiB | 43.3 MiB | 1.9 MiB | 96.5 MiB | 6.70 GiB | 2,868.5 MiB | 132.2 MiB | 2.93 GiB (165/165) | 2.15 GiB |

For the complete `094826414` late scan, the raw VMMap classification was:

| VMMap type | Size / reserved | Committed | Private | Total WS | Private WS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Private Data | 47,070.3 MiB | 10,803.1 MiB | 10,802.8 MiB | 5,491.2 MiB | 5,491.2 MiB |
| Stack | 540.5 MiB | 430.3 MiB | 430.3 MiB | 127.1 MiB | 127.1 MiB |
| Heap | 35.4 MiB | 28.3 MiB | 28.3 MiB | 27.7 MiB | 27.7 MiB |
| Image | 244.6 MiB | 243.5 MiB | 10.8 MiB | 43.3 MiB | 3.9 MiB |
| Mapped File | 43.8 MiB | 43.8 MiB | 0 MiB | 1.9 MiB | 0 MiB |
| Shareable | 140.4 MiB | 116.9 MiB | 0 MiB | 97.4 MiB | 0 MiB |
| Managed Heap | 0 MiB | 0 MiB | 0 MiB | 0 MiB | 0 MiB |
| **Total** | **48,141.9 MiB** | **11,666.0 MiB** | **11,272.3 MiB** | **5,788.7 MiB** | **5,650.0 MiB** |

The exact matches include two important known mappings:

* `0x0000000400000000`, 4,093.6 MiB committed, classified as `Private Data`,
  with 1,261–1,413 MiB resident across the valid scans.
* `0x0000000600000000`, 418.0 MiB committed, classified as `Thread Stack`,
  with 116–122 MiB resident.

The largest exact guest ranges observed resident at and after the corrected
frontier were `0x0000000400000000` (1,261–1,413 MiB),
`0x0000001063300000`, `0x0000001078B00000`, and `0x000000102A400000`
(approximately 320 MiB each), `0x0000000600000000` (116–122 MiB),
`0x0000001009000000` (approximately 107 MiB), and smaller private-data
ranges including `0x0000000800000000` (approximately 54 MiB). These are
address-correlated observations, not size-based ownership guesses.

Thus guest mapping commitment is not residency: roughly 2.78–3.08 GiB of the
approximately 6.7 GiB committed guest mappings was resident in these scans.
The dominant VMMap class is `Private Data`. The exact guest subset classified
as `Private Data` was 2.66–2.95 GiB, while 125.6–132.4 MiB of exact guest
working set was classified at the region level as `Thread Stack` (the VMMap
summary reports this aggregate under `Stack`). The classification-safe
remainder of `Private Data` was 1.88–2.41 GiB. This is VMMap-classification
remainder, not a named native/runtime owner: it must not be described as one
until a separate allocation ledger or address correlation identifies it.
VMMap did not label a managed heap on .NET 10; GC heap and GC committed
counters are therefore an inference about managed segments, not an additional
VMMap category. They must not be added to VMMap totals.

The host-visible Vulkan mapping total was 118–135 MiB in the late diagnostic
samples. Device-local Vulkan allocation was 2.54–2.63 GiB and is not added to
process-private or resident memory. In the host-map-aware run, 58 active
host-map records were captured at VMMap start. None had an exact or containing
VMMap region in the completed scan. This is evidence that the mappings churned
or that the driver’s mapping is not represented one-for-one in that later
snapshot; it is not proof that the driver cannot mirror an allocation in
process memory.

## Time-aligned corrected-frontier to cutoff samples

This table uses lifetime run 1 because it has the clearest corrected-frontier,
cache-plateau, and cutoff sequence. Guest resident bytes are only available at
the intrusive exact-match VMMap checkpoints; a dash means that the safety run
did not take another VMMap snapshot at that point.

| Phase | WS | Private | Guest committed / resident | VMMap Private Data / exact guest Private Data / Thread Stack | GC heap / committed | Cache image / staging | Other Vulkan total | Host mapped | Deferred texture / translated | Queue payload | Presenter phase |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Corrected dispatch complete, 18,526 ms | 4.68 GiB | 9.66 GiB | 6.73 / 3.08 GiB* | 5.35 GiB / 3,020.3 MiB / 132.4 MiB | 0.89 / 1.09 GiB | 384.5 / 0.5 MiB | 1.57 GiB | 35.6 MiB | 0 / 0 MiB | 0.1 MiB | `compute.resource-create` |
| Cache plateau, 21,030 ms | 4.95 GiB | 10.42 GiB | 6.73 / — | — | 0.65 / 0.82 GiB | 594.8 / 0.5 MiB | 2.51 GiB | 94.5 MiB | 0 / 0 MiB | 0 MiB | `presentation.idle` |
| Near cutoff, 28,026 ms | 6.21 GiB | 11.67 GiB | 6.84 / — | — | 0.72 / 1.64 GiB | 594.8 / 0.5 MiB | 2.57 GiB | 132.3 MiB | 0 / 0 MiB | 0 MiB | `guest-work.enter` |

`*` The corrected-frontier resident value is the exact-match result from the
3,115 ms VMMap scan whose nearest sample was 18,524 ms; it is not a second
diagnostics sample at 18,526 ms. The VMMap scan itself reported 5.64 GiB WS.
The VMMap column uses that same completed scan; its two exact-guest values are
grouped by VMMap region classification and are not inferred from the adjacent
diagnostics sample.

At the cutoff, the labeled Vulkan subcategories included approximately
1,372 MiB detile, 446 MiB offscreen, 124 MiB guest buffers, and 610 MiB texture
allocations. These are diagnostic views within the 2.57 GiB explicit Vulkan
total, not additive owners. The 594.8 MiB cache image is a subset of the
texture allocation view, and the 0.5 MiB cache staging allocation is represented
in the staging category.

## Texture and staging lifetime

In all three non-VMMap lifetime runs the cache reached 20 entries and
594.8 MiB of image memory before the cutoff. The plateau began at 21,030 ms,
17,036 ms, and 17,540 ms respectively; each run then continued with the cache
image and staging totals unchanged while working set/private memory grew.

The final complete lifetime snapshot contained 20 bounded entries:

* 19 entries had at least one observed cache hit; one entry had no cache hit.
* 17 entries had a later use timestamp than insertion. At millisecond
  resolution, entries 10, 13, and 14 had no later timestamp; entry 14 also had
  zero cache hits. Equal insertion/use timestamps are not evidence of absence
  of a same-timestamp use.
* The entries retained 594.8 MiB of image memory and 0.5 MiB of staging.
  Only resource 7 owned staging, and it had 159 cache hits.
* All 20 entries had upload submission and completion timelines, and all
  staging was unmapped in the snapshot. The cache-hit path returns the cached
  image directly; the upload path sets `NeedsUpload` false and documents that
  later draws reuse the image without restaging. This establishes that the
  retained staging allocation is not observed to be needed for cache hits, but
  does not establish a guest-visible eviction rule.
* No cache removal, deferred texture destruction, deferred translated-resource
  destruction, or actual resource destruction occurred before the safety kill.
  Device-teardown lifecycle recording and deferred/actual transitions are
  covered by deterministic tests, but they were not observed in these target
  runs because no eviction or graceful shutdown was reached.

The trace distinguishes cache image, cache staging, transient staging,
host-buffer pool, deferred texture, deferred translated-resource, guest-image,
offscreen, and detile ownership. DeviceMemory handles are deduplicated before
translated-resource totals are recorded; counters are clamped/guarded against
double release and negative values.

## Finding and next boundary

The current working-set cutoff is materially associated with resident
`Private Data`, not with guest committed bytes alone. Guest mappings are a
large resident contributor, but 1.88–2.41 GiB of late VMMap `Private Data`
remains after subtracting only exact guest mappings that VMMap classified as
`Private Data`. Exact guest mappings classified as `Thread Stack` are reported
separately and are not subtracted from `Private Data`; the remainder is still
not a named owner. The texture image cache is large in device-local Vulkan
accounting but plateaus before working set continues to grow. Cached staging is
only 0.5 MiB. Deferred destruction was not active.

Ranked candidates:

1. **No memory correction yet.** Attribute the 1.88–2.41 GiB VMMap
   classification remainder to a named native/runtime owner before changing
   ownership.
2. If that ledger identifies a retained native/runtime owner, correct that
   owner at its allocation/lifetime boundary.
3. Releasing cached staging after upload completion is a plausible cleanup but
   is not supported as the working-set correction: the measured retained amount
   is only 0.5 MiB.
4. A guest-mapping decommit/residency policy is not supported by this evidence;
   most committed guest pages were already nonresident, and changing that
   policy would require a separate guest-observable contract.
5. Correcting deferred destruction is not indicated by these runs because its
   measured retained total was zero.

The scalar Vulkan host-allocation probe and its reconciliation are recorded in
[startup private-data ownership](STARTUP_PRIVATE_DATA_OWNERSHIP.md). It is
balanced and bounded, but its instance/device `VkAllocationCallbacks` ledger
observed no request larger than 133,120 bytes across three trials. That rules
out this callback boundary as the owner of the 512 MiB and 1 GiB unmatched
regions; it does not cover implementation virtual allocations made outside
those callbacks. The next boundary is an elevated Windows Performance Recorder
`VirtualAllocation` trace that can provide allocation addresses and stacks.
Do not implement a cache, staging, or guest-memory correction from this finding
alone.

## Falsification conditions

* The guest-residency conclusion is falsified if a matched scan shows most of
  the cutoff working set in exact guest mappings, or if committed guest pages
  become predominantly resident without another owner growing. The
  classification arithmetic is falsified if most VMMap `Private Data` working
  set is accounted for by exact guest mappings that VMMap also classifies as
  `Private Data`; a `Thread Stack` or other VMMap class does not satisfy that
  condition.
* The staging conclusion is falsified if a comparable run retains materially
  more staging, remaps staging on cache hits, or shows staging growth after the
  image plateau.
* The cache-plateau conclusion is falsified if cache image bytes continue
  growing after the reported plateau while the working set rises, or if cache
  removal/deferred bytes become the matching late owner.
* The Private Data next-boundary conclusion is falsified if a synchronized
  allocation ledger or VMMap correlation attributes the classification
  remainder to a different named runtime, mapped-file, shareable, or
  driver-backed owner.
* The deferred-destruction observation is falsified by a run that reaches an
  eviction or normal shutdown and records deferred bytes that remain after the
  corresponding timeline completes.
* The host-mapping limitation is falsified by an exact/containing host-map
  address match in a synchronized VMMap scan, or by an authoritative driver
  allocation report that accounts for the private/resident gap.
* The diagnostic attribution is weakened if three comparable diagnostic runs
  change the memory regime or if a control run reaches character creation under
  the unchanged policy. The current runs did not reach that checkpoint.

Related historical findings: [startup memory ownership](STARTUP_MEMORY_OWNERSHIP.md),
[oversized detile work](OVERSIZED_DETILE_WORK.md), and
[post-snapshot startup frontier](POST_SNAPSHOT_STARTUP_FRONTIER.md).
