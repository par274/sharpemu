<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup private-data ownership

Status: the elevated WPR `VirtualAllocation` trace identified the commit
boundary for the large reserved shape as .NET GC segment management and the
512 MiB, 1 GiB, and visible 64/32 MiB shapes as Vulkan/graphics
implementation virtual-allocation boundaries. It did not prove the owner of
the large reservation event itself, physical placement of Vulkan memory, or an
incorrect lifetime, so no memory correction is justified.
The Vulkan host-allocation probe was a completed temporary experiment and is
not retained on the final PR head. It did not identify the dominant owner, and
its allocator and partial-lifecycle machinery added risk without resolving the
1.675–2.173 GiB remainder. Normal execution continues to use Vulkan's default
host allocator. The WPR trace observed the normal allocator path through the
existing `VulkanMemoryDiagnostics` seam, which calls Vulkan with null
allocation callbacks.
The largest previously-unresolved shape is a fully resident 512 MiB
`Read/Write/WriteCombine` region. It is not an exact guest mapping, does not
overlap a tracked Vulkan host-visible mapping, and was not requested by the
application's direct `VirtualAlloc` paths; WPR attributes its commit to an
explicit `vkAllocateMemory` call. The instance/device `pfnAllocation`,
`pfnReallocation`, and `pfnFree` request ledger still saw no request larger
than 133,120 bytes, and the informational internal-allocation callbacks
reported zero notifications. The WPR result is recorded below.

This finding records observations, inferences, and uncertainty separately. It
does not call the remainder a native leak, managed leak, driver allocation, or
other owner without attribution evidence.

## Environment and target identity

The controlled runs used the existing ignored target configuration. Absolute
target and artifact paths are intentionally omitted from this tracked finding.

| Item | Value |
| --- | --- |
| Source baseline | `a899e62d55f5e5ec7f690f897867e9c6df29123c` |
| Diagnostic source revisions | `b798a77fc47eb3cd8830012d31969745a918f106` introduced the probe; `766a44db0d470069b3038701df12d738805d6487` hardened it for the temporary experiment. |
| Experiment finding revisions | `20182fa77363a9dc7d999b3eabdb1306ae0e07de`, `1162336cf8bc651ae118173f9a89e6f9fadfee13` |
| Probe cleanup revision | `5776346a012171b5f67d89c31405948aa71d971b` |
| Title ID | `PPSA01341` |
| Region / target version | Europe (`EP9000`) / `1.004.000` |
| Target eboot SHA-256 | `22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306` |
| Published executable SHA-256 | `4955155317A1F096B46A34DC4B43BF7B0F5F37E61018B1A5B25424A1B4C3F893` |
| Route / checkpoint | startup-to-character-creation / character creation nickname prompt |
| Host | Windows 11 Pro `10.0.26200`, 16 GiB |
| CPU | 12th Gen Intel Core i5-12400F, 12 logical processors |
| GPU / driver | NVIDIA GeForce RTX 3070 Ti / `610.74` (WDDM `32.0.16.1074`) |
| Runtime | .NET `10.0.10` |
| Vulkan | loader/SDK `1.4.350`; device API `1.4.341`; NVIDIA `610.74` |
| Target arguments | `--cpu-engine=native --log-level=debug --window-mode=windowed --resolution=1280x720 --vsync=off` |
| Safety policy | 6 GiB process-tree working-set limit, existing page-file configuration, 900 s wall limit, 250 ms sampling |

The target identity, arguments, limit, and machine values are recorded in the
raw run manifests outside Git. The control and trace used the published
binary SHA-256 recorded above. A local portable-PDB build was made only for
WPA symbol lookup; it did not replace or instrument the published executable.

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

The existing corrected arithmetic reports a 1.675–2.173 GiB `Private Data`
working-set remainder in the current baseline matrix. The historical
correction matrix added a bounded, opt-in probe at the instance and device `VkAllocationCallbacks`
roots. Its `pfnAllocation`/`pfnReallocation`/`pfnFree` ledger records only
scalar address, size, alignment, scope, ID, and time-frontier metadata. Its
`pfnInternalAllocation`/`pfnInternalFree` path records only bounded scalar
notification counters and largest-allocation metadata; it never allocates,
frees, or retains the reported pointer. Neither path retains payloads, managed
owners, Vulkan objects, or stack traces. The bound is 16,384 active entries
and 65,536 events. The disabled path does not create the probe or pass
callbacks to Vulkan.

The probe was deliberately limited to callbacks supplied at
`vkCreateInstance`/`vkDestroyInstance` and `vkCreateDevice`/`vkDestroyDevice`.
Child-object allocators and implementation/driver allocations outside this
callback coverage remain unresolved. The probe therefore answers the
instance/device callback boundary, not all Vulkan or driver allocations.

The probe was removed after the experiment because its largest request was only
133,120 bytes, its outstanding bookkeeping stayed near 2 MiB, and internal
notifications were zero while the dominant remainder stayed unresolved. The
extra allocator and partial-initialization lifecycle machinery was not
justified for a boundary that still required elevated WPR attribution. The
final PR head passes null allocation callbacks to instance/device creation and
destruction, restoring the normal Vulkan default-allocation path.

The elevated WPR run was checked and recorded as follows:

```text
Microsoft Windows Performance Recorder Version 10.0.26100
wpr -status                         -> WPR is not recording
wpr -start VirtualAllocation -filemode
wpr -status                         -> Dropped event: 0; Logging mode: File
wpr -stop <trace.etl> "SharpEmu startup VirtualAllocation attribution"
wpr -status                         -> WPR is not recording
```

The trace used WPR `10.0.26100.8875`, WPA `11.8.423.12582` (Store package
`11.8.423.0`), and VMMap `3.4`. The WPR system collector reported
`VirtualAllocation` and stack collection with `Events Lost: 0`. WPA's official
exporter successfully produced the required `VirtualAlloc Commit LifeTimes`
and `Total Commit` tables after loading Microsoft symbols and the local SharpEmu
PDBs. The in-app WPA GUI control path was unavailable in this session; this
exporter is the same WPA analysis engine and the exported tables contain the
required columns and stacks. No full heap dump or `dotnet-gcdump` was started.
The WPR profile and VMMap sources are indexed in [SOURCES.md](SOURCES.md).

## Controlled run matrix

The control and final diagnostics were historical experiment runs after commit
`766a44d`, with the same published binary and unchanged target policy. They are
not measurements from the final cleanup head. Every run ended at the existing
working-set safety cutoff; none reached the requested checkpoint.

| Run | Diagnostics | VMMap captures | Duration | Peak process-tree WS | Peak private | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `20260801T180004351Z-766a44d-trial-01` | disabled control | 0 | 33.0 s | 6.015 GiB | 11.377 GiB | working-set-limit |
| `20260801T180049134Z-766a44d-trial-01` | enabled | 2 | 33.0 s | 6.100 GiB | 11.389 GiB | working-set-limit |
| `20260801T180122195Z-766a44d-trial-02` | enabled | 3 | 30.8 s | 6.026 GiB | 11.376 GiB | working-set-limit |
| `20260801T180153026Z-766a44d-trial-03` | enabled | 3 | 36.5 s | 6.499 GiB | 11.884 GiB | working-set-limit |

The runner does not permit VMMap-assisted capture when diagnostics are disabled,
so the clean control has no VMMap export. This is a runner constraint, not an
assumption that the control and diagnostic samples are synchronized.

The historical direct `pfnAllocation` request ledger state at each matched VMMap
frontier in the three enabled runs was:

| Run | Active entries | Active requested bytes | Allocation IDs | Events | Dropped entries/events | Duplicate/untracked releases | Largest request |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `20260801T180049134Z-766a44d-trial-01` corrected / near | 835 / 1,150 | 1,184,686 / 1,561,470 | 12,047 / 12,488 | 23,390 / 23,957 | 0 / 0 | 0 / 0 | 133,120 bytes |
| `20260801T180122195Z-766a44d-trial-02` corrected / near / plateau | 872 / 1,206 / 1,552 | 1,217,590 / 1,618,526 / 1,871,478 | 12,096 / 12,551 / 13,281 | 23,449 / 24,025 / 25,139 | 0 / 0 / 0 | 0 / 0 / 0 | 133,120 bytes |
| `20260801T180153026Z-766a44d-trial-03` corrected / near / plateau | 892 / 1,371 / 1,541 | 1,228,310 / 1,737,798 / 1,866,838 | 12,083 / 12,792 / 13,384 | 23,401 / 24,340 / 25,354 | 0 / 0 / 0 | 0 / 0 / 0 | 133,120 bytes |

The informational `pfnInternalAllocation`/`pfnInternalFree` counters stayed at
zero in every sample of all three diagnostic runs: allocation count, free
count, current bytes, peak bytes, largest notification, dropped notifications,
and unmatched frees were all zero. The absence is an observation about this
loader/driver path, not proof that implementation allocations do not exist
outside the callback coverage.

The active-byte value is requested bytes in the historical callback ledger, not
a VMMap resident value. The diagnostic structures were bounded and disabled
on the normal path. Historical deterministic tests covered balance,
reallocation, duplicate release, bound drops, disabled behavior, callback
contract failures, internal notifications, and callback-session lifetime. The
probe and those focused tests are absent from the final PR head.

The process-tree peak is not a synchronized ownership measurement. The enabled
run peaks span 6.026–6.499 GiB versus 6.015 GiB for the control. The first two
diagnostic peaks are within 1.4% of control; trial 3 is an 8.0% peak outlier.
The median diagnostic peak is 6.026 GiB, 0.2% above control. The direct request
ledger stays below 1.9 MiB and the same region shapes recur in all eight
correction scans. The evidence supports an unchanged ownership regime, with
the outlier retained rather than averaged away.

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
| `20260801T180049134Z-766a44d-trial-01` corrected | `0x0000023C3CBC0000` — 32437.25 / 1223.82 / 1223.82 / 1220.42 / 1220.42; 45; RW | `0x000002447A100000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x0000024428100000` — 1024 / 70.12 / 70.12 / 63.19 / 63.19; 40; RW | 1.946 GiB / 90.1% |
| `20260801T180049134Z-766a44d-trial-01` near cutoff | same addresses — 32437.25 / 1295.75 / 1295.75 / 1292.82 / 1292.82; 55; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 73.38 / 73.38 / 66.02 / 66.02; 38; RW | 2.173 GiB / 84.1% |
| `20260801T180122195Z-766a44d-trial-02` corrected | `0x00000209F67E0000` — 32437.25 / 1218.16 / 1218.16 / 1213.30 / 1213.30; 45; RW | `0x00000211F9740000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x00000209A2180000` — 1024 / 71.94 / 71.94 / 64.88 / 64.88; 32; RW | 1.984 GiB / 88.1% |
| `20260801T180122195Z-766a44d-trial-02` near cutoff | same addresses — 32437.25 / 939.43 / 939.43 / 935.20 / 935.20; 51; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 73.81 / 73.81 / 66.53 / 66.53; 36; RW | 1.845 GiB / 80.1% |
| `20260801T180122195Z-766a44d-trial-02` cache plateau | same addresses — 32437.25 / 728.43 / 728.43 / 726.29 / 726.29; 35; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 76.31 / 76.31 / 68.69 / 68.69; 42; RW | 1.675 GiB / 76.2% |
| `20260801T180153026Z-766a44d-trial-03` corrected | `0x000002A310AD0000` — 32437.25 / 1303.90 / 1303.90 / 1301.70 / 1301.70; 49; RW | `0x000002AB7FE70000` — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | `0x000002AB1E060000` — 1024 / 72.81 / 72.81 / 65.56 / 65.56; 28; RW | 2.122 GiB / 86.5% |
| `20260801T180153026Z-766a44d-trial-03` near cutoff | same addresses — 32437.25 / 940.68 / 940.68 / 938.57 / 938.57; 49; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 74.06 / 74.06 / 66.64 / 66.64; 28; RW | 1.872 GiB / 79.2% |
| `20260801T180153026Z-766a44d-trial-03` cache plateau | same addresses — 32437.25 / 822.49 / 822.49 / 820.51 / 820.51; 49; RW | same address — 512 / 512 / 512 / 512 / 512; 1; RW/WriteCombine | same address — 1024 / 76.50 / 76.50 / 68.73 / 68.73; 36; RW | 1.833 GiB / 74.6% |

The first region is stable in reserved size and stable in address within a
process, but its committed and resident portions move between matched
frontiers. Across processes its address changes, consistent with ASLR. The
512 MiB and 1 GiB signatures have the same within-process stability and
cross-process ASLR behavior. The next unmatched group contains 64 MiB and
32 MiB fully resident `Read/Write/WriteCombine` regions plus smaller related
regions. A separate approximately 4,096 MiB `Reserved` row had zero committed
and working-set bytes and therefore does not contribute to the remainder or
the top-three working-set list. The top three explain 74.6–92.2% of the
remainder in the retained and correction captures; a small number of stable
shapes, not hundreds of unrelated tiny regions, dominates the arithmetic.

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
| `20260801T180049134Z-766a44d-trial-01` corrected, 20,542 ms | 4.173 GiB | 4,767.1 MiB | 2,774.6 MiB | 130.7 MiB | 2.837 GiB | 835.0 / 817.0 MiB | 1.946 GiB |
| same run near cutoff, 22,529 ms | 5.251 GiB | 5,239.4 MiB | 3,014.0 MiB | 130.8 MiB | 3.071 GiB | 1,168.4 / 1,140.8 MiB | 2.173 GiB |
| `20260801T180122195Z-766a44d-trial-02` corrected, 20,551 ms | 4.756 GiB | 4,844.9 MiB | 2,813.1 MiB | 132.2 MiB | 2.876 GiB | 1,144.0 / 974.8 MiB | 1.984 GiB |
| same run near cutoff, 22,043 ms | 5.231 GiB | 4,896.6 MiB | 3,007.6 MiB | 130.3 MiB | 3.064 GiB | 864.1 / 695.1 MiB | 1.845 GiB |
| same run cache plateau, 25,548 ms | 4.914 GiB | 4,792.8 MiB | 3,078.0 MiB | 132.7 MiB | 3.135 GiB | 748.1 / 628.0 MiB | 1.675 GiB |
| `20260801T180153026Z-766a44d-trial-03` corrected, 21,529 ms | 4.711 GiB | 4,909.6 MiB | 2,736.7 MiB | 130.7 MiB | 2.800 GiB | 1,092.3 / 826.3 MiB | 2.122 GiB |
| same run near cutoff, 23,040 ms | 5.358 GiB | 4,810.8 MiB | 2,894.4 MiB | 130.8 MiB | 2.954 GiB | 937.7 / 673.0 MiB | 1.872 GiB |
| same run cache plateau, 26,043 ms | 4.977 GiB | 4,817.6 MiB | 2,940.4 MiB | 131.2 MiB | 3.000 GiB | 865.8 / 572.5 MiB | 1.833 GiB |

The GC committed and heap-used values are runtime counters, not VMMap
categories. The 32,437.25 MiB region is therefore a managed GC/runtime
segment hypothesis supported by shape and frontier movement, not a second
additive owner. GC committed bytes are not assumed fully resident.

At the same matched frontiers, explicit Vulkan device memory was 0.227–2.565
GiB and mapped host-visible memory was 35.0–111.3 MiB. Device memory is a
separate device domain and is excluded from process-private/RAM reconciliation.
There were 54–147 tracked host maps; exact address correlation matched 0–2
small rows, with 0.0–12.0 MiB matched working set. The cache reached 594.8 MiB
image memory in the late plateau while staging stayed at 0.5 MiB; deferred
texture and translated-resource destruction stayed at zero. Queue payload was
zero at all correction frontiers except the final diagnostic sample of trial
3, where it was 17.5 MiB at a cache-plateau frontier and was not a common
retained owner.

## Classification-safe reconciliation

The reconciliation is intentionally not a sum of every diagnostic counter:

| Category | Treatment |
| --- | --- |
| Total VMMap `Private Data` working set | The control capture measured 5,195.641 MiB; the trace capture measured 5,407.508 MiB. These are capture frontiers, not owner totals. |
| Exact guest `Private Data` | Subtracted once by exact guest interval and VMMap type: 3,009.254 MiB in control and 2,875.957 MiB in the trace. |
| Exact guest `Thread Stack` | Reported separately: 131.344 MiB in control and 130.781 MiB in the trace; not subtracted from `Private Data` because it is a different VMMap class. |
| Managed GC/runtime | GC committed and heap-used counters are overlapping evidence for the large reserved segment; they are not added to the remainder and do not prove object retention. |
| CPU backend/generated code and data | Source audit found small stubs, TLS/control storage, context frames, and worker/abort stacks with matching frees. The largest identified worker stack reservation is 4 MiB; no source path explains the 512 MiB/1 GiB signatures. No separate large CPU-backend owner is claimed. |
| Explicit Vulkan device memory | Tracked separately in `vulkan.device-memory`; excluded from process-private/resident-RAM totals. |
| Vulkan mapped host-visible memory | 81.908 MiB in the control sample and 53.081 MiB in the trace sample; 82 trace mappings had zero address overlap with the target regions. |
| Vulkan instance/device `pfnAllocation` request ledger | At most 1,871,478 outstanding requested bytes in the correction matrix; zero bookkeeping failures, drops, duplicate releases, and untracked releases. This is a subset of callback requests, not an additive VMMap owner. |
| Vulkan `pfnInternalAllocation` notifications | Zero allocation/free notifications and zero current/peak/largest/dropped/unmatched counters in all three diagnostic runs. These callbacks are informational and do not account for implementation allocations outside their coverage. |
| Cache, staging, deferred destruction, queue | Cache image is device-local accounting; staging is 0.5 MiB; deferred is zero; late queue is zero. These counters are not added to the remainder. |
| Target-region contribution | In the trace VMMap, the three primary regions contributed 2,139.164 MiB of private working set. The 44 visible related 64/32 MiB regions contributed another 235.523 MiB: 172.656 MiB WriteCombine and 62.867 MiB RW. The combined 2,374.688 MiB is a VMMap contribution, not an additional diagnostic counter. |
| Remaining classification remainder | Control: 2,186.387 MiB (2.135 GiB); trace: 2,531.551 MiB (2.472 GiB). The control is within the established 1.675–2.173 GiB range; the trace was a different, WPR-instrumented frontier and is not averaged with prior runs. |

The source audit also found no application `PAGE_WRITECOMBINE` request. The
Windows host-memory wrapper strips that modifier from its generic protection
mapping, while the application source has no other matching request. This is
evidence against an application-created WriteCombine region, not proof of a
driver owner.

## Observation, inference, and uncertainty

### Observed

* Three region signatures recur across four retained captures and eight
  correction captures. The largest has 32,437.25 MiB reserved; the
  second is 512 MiB, fully committed and resident, with
  `Read/Write/WriteCombine`; the third is 1,024 MiB with approximately 63–77
  MiB resident in the correction matrix.
* The largest region's resident amount changes substantially between matched
  frontiers while its address and reserved size stay fixed within a process.
* The top regions are outside exact guest intervals and tracked host-map
  intervals. VMMap gives them no `Details` owner.
* The trace child was PID `20204`. The WPR CSV contained a separate
  `SharpEmu.exe (1836)` process, but all attribution below was filtered to the
  exact VMMap child instance `SharpEmu.exe (20204)`.
* The 32,437.25 MiB VMMap row had base `0x000001F687CD0000`. WPR's commit
  lifetime view had no reservation row at that base, but all 5,864 recorded
  commits whose addresses fell inside the VMMap interval had .NET GC segment
  frames. The interval was 1,562.352 MiB committed and 1,558.805 MiB private
  working set in the paired VMMap capture.
* The 512 MiB row at `0x000001FEFF190000` matched one WPR commit lifetime of
  512 MiB. Its stack reached `VulkanMemoryDiagnostics::Allocate`,
  `Silk.NET.Vulkan.Vk::AllocateMemory`, `vulkan-1.dll`, and
  `nvoglv64.dll`.
* The 1 GiB row at `0x000001FE95370000` matched 427 smaller WPR commit
  lifetimes totaling 90.502 MiB over their lifetimes. The VMMap row was
  75.625 MiB committed and 68.359 MiB resident. Most stacks crossed SDL3,
  the Vulkan loader, and NVIDIA graphics implementation; nine rows also
  crossed the explicit SharpEmu Vulkan allocation seam.
* Forty-four visible related 64/32 MiB rows had 304 matching WPR commit
  lifetimes. Every row reached either the explicit SharpEmu Vulkan allocation
  seam or the SDL/Vulkan/graphics implementation boundary. No target or
  related row had a WPR lifetime without a recorded decommit.
* The instance/device `pfnAllocation` request ledger had zero dropped records,
  zero duplicate releases, zero untracked releases, zero bookkeeping failures,
  and a maximum request of 133,120 bytes in each correction trial. The
  `pfnInternalAllocation`/`pfnInternalFree` callbacks reported zero events,
  bytes, drops, and unmatched frees in every diagnostic sample.
* Existing explicit Vulkan, cache, staging, deferred-destruction, queue, GC,
  and guest counters do not sum to the VMMap `Private Data` remainder without
  overlapping categories or crossing process frontiers.

### Inferred

* The 32,437.25 MiB shape's recorded commit boundary is the .NET GC runtime:
  representative stacks are `SharpEmu.exe!GCInterface_AllocateNewArray` ->
  `WKS::gc_heap::grow_heap_segment` -> `GCToOSInterface::VirtualCommit` ->
  `KernelBase.dll!VirtualAlloc`, and
  `SharpEmu.exe!RhpNewVariableSizeObject` -> `WKS::GCHeap::Alloc`. This
  identifies managed segment management for the commits, not retained-object
  ownership and not the reservation call itself.
* The 512 MiB shape is an explicit Vulkan `vkAllocateMemory` call boundary
  from `SharpEmu.Libs.dll!SharpEmu.Libs.VideoOut.VulkanMemoryDiagnostics::Allocate`
  through `Silk.NET.Vulkan.dll!Silk.NET.Vulkan.Vk::AllocateMemory`, the
  `vulkan-1.dll` loader, and `nvoglv64.dll`. This is a process-private virtual
  backing allocation associated with Vulkan device-memory work; it is not the
  separate `vulkan.device-memory` counter domain. It does not prove NVIDIA
  ownership or an incorrect driver lifetime.
* The 1 GiB and visible 64/32 MiB shapes have the same Vulkan/graphics
  implementation boundary. The 1 GiB interval is mostly implementation-side
  commit activity reached through SDL3/loader/NVIDIA frames, with a smaller
  set of explicit `vkAllocateMemory` frames. The related rows are predominantly
  explicit Vulkan allocation frames.

### Uncertain

* WPR `VirtualAllocation Commit LifeTimes` attributes commits, not a
  reservation-only call. The large row's reservation owner is therefore not
  named by this trace even though every recorded commit inside it has a GC
  segment stack.
* `vulkan-1.dll` and `nvoglv64.dll` frames report `<PDB not found>`; SDL3
  frames report `<Missing ImageId event>`. Public symbols resolved the Windows
  and kernel frames, and local SharpEmu PDBs resolved the application frames.
  No module-plus-offset was available for the NVIDIA implementation in this
  trace.
* WPR decommit at process termination establishes that the traced lifetimes
  were not still live at ETL end. It does not prove that the corresponding
  application or driver release happened during normal teardown, so it cannot
  establish an incorrect lifetime.
* A .NET EventPipe or GC experiment is warranted only later, and only to
  distinguish normal segment management from retained objects after this WPR
  boundary. It was not performed here.
* The 6.499 GiB process-tree peak in correction diagnostic trial 3 prevents a
  claim that instrumentation has no effect on peak timing. It does not change
  the repeated region shapes, zero internal notifications, or balanced request
  ledger.

## WPR result and next boundary

### Run and validity

The required minimum matrix used the same Release publish, target arguments,
diagnostics placeholder, near-cutoff VMMap capture, and safety policy:

| Run | Run ID | Exact VMMap child | Result | Peak WS / private | VMMap |
| --- | --- | ---: | --- | ---: | --- |
| Normal control | `20260801T202928523Z-a899e62-trial-01` | `15436` | working-set limit; 47,236 ms | 6.330 / 11.535 GiB | exit 0, near-cutoff capture |
| Elevated WPR trace | `20260801T203126586Z-a899e62-trial-01` | `20204` | working-set limit; 34,178 ms | 6.644 / 12.201 GiB | exit 0, near-cutoff capture |

The trace ETL is valid: it was saved by `wpr -stop`, is 349,175,808 bytes, and
the WPR status and active system collector both reported zero dropped/lost
events. The exact WPR process filter was `SharpEmu.exe (20204)`; the trace also
contained `SharpEmu.exe (1836)`, which was excluded. WPA exported both required
tables for that exact child. No WPR session was active before start, and no
SharpEmu, VMMap, or WPR process remained after cleanup. The control had no WPR
session by design.

The paired trace VMMap category arithmetic was 5,407.508 MiB `Private Data`
working set minus 2,875.957 MiB of exact guest `Private Data`, or 2,531.551
MiB (2.472 GiB) of classification remainder. The paired control was 5,195.641
minus 3,009.254 = 2,186.387 MiB (2.135 GiB), within the established baseline
range. The trace frontier is not averaged with the control or prior runs.

### Address correlation and attribution

The trace-side VMMap CSV and WPR `VirtualAlloc Commit LifeTimes` table were
joined by exact child PID and address interval. WPR `Size` is a committed
lifetime amount; it is not resident RAM. VMMap supplies the current committed
and resident values.

| VMMap region | VMMap reserved / committed / private WS | Protection | WPR interval result | Release at ETL end |
| --- | ---: | --- | --- | --- |
| `0x000001F687CD0000` | 32,437.250 / 1,562.352 / 1,558.805 MiB | RW | 5,864 commits inside the interval; 3,093.921 MiB lifetime sum; commit 1.193–34.904 s; decommit 2.595–35.326 s | All rows decommitted during process cleanup; reservation-only owner not present in this commit view |
| `0x000001FEFF190000` | 512 / 512 / 512 MiB | RW/WriteCombine | One 512 MiB commit at 19.189 s; decommit 35.283 s | No live row at ETL end; process-cleanup decommit, not proof of normal `vkFreeMemory` timing |
| `0x000001FE95370000` | 1,024 / 75.625 / 68.359 MiB | RW | 427 commits inside the interval; 90.502 MiB lifetime sum; commit 7.177–34.901 s; decommit 18.415–35.326 s | All rows decommitted during process cleanup |
| 44 related 64/32 MiB rows, including `0x000001FF6B5D0000` (64 MiB) and `0x000001FF67610000` (63.75 MiB) | 1,471.500 / 1,460.148 / 235.523 MiB aggregate | 42 WC, 2 RW | 304 commits; 1,460.865 MiB lifetime sum; commit 7.380–22.317 s; decommit 7.380–35.326 s | No live row at ETL end |

The large reservation itself had no exact WPR reservation row at its VMMap
base. Its 5,864 address-contained commit rows all had a .NET GC boundary. A
representative stack was:

```text
SharpEmu.exe!GCInterface_AllocateNewArray
  -> SharpEmu.exe!WKS::GCHeap::Alloc
  -> SharpEmu.exe!WKS::gc_heap::grow_heap_segment
  -> SharpEmu.exe!WKS::gc_heap::virtual_commit
  -> SharpEmu.exe!GCToOSInterface::VirtualCommit
  -> KernelBase.dll!VirtualAlloc
```

Other rows reached `SharpEmu.exe!RhpNewVariableSizeObject` /
`RhpGcAlloc` from AGC or presenter work before entering the same GC heap
segment path. This is managed segment commitment evidence, not evidence that a
particular object retained the pages.

The exact 512 MiB stack was:

```text
SharpEmu.Libs.dll!SharpEmu.Libs.VideoOut.VulkanMemoryDiagnostics::Allocate
  -> Silk.NET.Vulkan.dll!Silk.NET.Vulkan.Vk::AllocateMemory
  -> vulkan-1.dll!<PDB not found>
  -> nvoglv64.dll!<PDB not found>
  -> DXCore.dll!D3DKMTCreateAllocation
  -> dxgkrnl.sys!DxgkCreateAllocation
  -> dxgmms2.sys!VIDMM_RECYCLE_HEAP_MGR::Allocate
```

The existing source seam calls `vkAllocateMemory` with a null allocator and
only records explicit Vulkan device-memory objects when diagnostics are
enabled. The VMMap 512 MiB private working set is therefore associated with a
normal explicit Vulkan allocation path, while the paired diagnostics sample's
`vulkan.device-memory` value (1.787 GiB) remains a separate device domain and
is not added to process-private memory.

The 1 GiB interval's exact base commit was 0.188 MiB and started in
`VulkanVideoPresenter` / `SdlHostWindow::CreateWindow`, then crossed
`SDL3.dll!<Missing ImageId event>`, `vulkan-1.dll!<PDB not found>`, and
`nvoglv64.dll!<PDB not found>`. Nine of the 427 interval rows (1.004 MiB
lifetime) also had the explicit `VulkanMemoryDiagnostics::Allocate` ->
`Vk::AllocateMemory` stack. The remaining 418 rows (89.498 MiB lifetime) were
at the SDL/Vulkan/NVIDIA graphics-implementation boundary. WPR therefore did
not record a single 1 GiB Vulkan allocation; it recorded many smaller commits
inside the VMMap reservation.

The 44 related rows had the same two stack families: 234 rows / 1,417.966 MiB
lifetime through `VulkanMemoryDiagnostics::Allocate` and 70 rows / 42.899 MiB
lifetime through SDL/Vulkan/NVIDIA or graphics initialization. Examples
include the 64 MiB `0x000001FF6B5D0000` row, which reached the explicit
`vkAllocateMemory` seam through `VulkanDetilePass::CreateBuffer`, and the RW
32 MiB `0x000001FED8580000` row, whose dominant 101 commits reached the same
seam. No related row had a managed-GC or guest-host-memory stack.

### `Total Commit` cross-check

For `SharpEmu.exe (20204)`, WPA's `Memory > Total Commit` export contained only
`Commit Type = Virtual Alloc`. Its largest rows were the known 4,093.563 MiB
guest mapping through `KernelMapDirectMemory`, the 512 MiB Vulkan row above,
the known 418 MiB guest stack mapping, and the known 352 MiB guest virtual
range. This confirms the process/commit-stack view and separates the exact
guest mappings from the Vulkan interval join; it does not turn commit size
into resident size.

### Observation, inference, uncertainty, and remaining questions

Observed: the control and trace independently reproduce the same three size
signatures and the trace's 44 visible related rows. The WPR interval joins
name a .NET GC commit boundary for the large row and Vulkan/graphics
implementation boundaries for all other target rows. The 82 trace host-visible
mapping addresses have zero overlap with the target VMMap intervals.

Inferred: the large row is normal-or-retained managed GC segment management;
the 512 MiB row is an explicit Vulkan allocation reaching the NVIDIA/DXG
implementation; the 1 GiB and related rows are implementation-side Vulkan
virtual backing reached through the same graphics boundary. These are
boundaries, not leak classifications.

Uncertain: the WPR profile did not attribute the large reservation-only event;
the NVIDIA and Vulkan loader frames have no public PDB/offset in this trace;
and process-exit decommit does not prove the normal source lifetime. WPR also
does not identify whether the Vulkan-backed pages are physically resident in
system RAM or device-local memory; VMMap only reports the process working set.

Remaining questions: the current attribution would be undermined only if the
exact PID/address join, exported WPR stack data, or VMMap correlation were
shown to be invalid. A reservation-aware trace can identify the owner of the
large reservation without changing the observed GC commit attribution.
EventPipe or GC analysis can answer object-retention questions; it does not
rewrite the commit stack. Normal-teardown tracing can answer Vulkan release
timing; it does not change the allocation origin. A repeat trace may reveal
additional allocation paths without invalidating the paths observed here.

Next boundary: if the large region remains operationally concerning, run the
smallest later EventPipe or GC segment/object experiment needed to distinguish
normal segment management from retained objects. Do not perform it as part of
this WPR finding. For the Vulkan shapes, preserve the existing normal allocator
and use a narrower loader/driver diagnostic only if a future question requires
physical placement or normal-destruction proof. No correction is justified.

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

### Historical temporary experiment

The probe revision `766a44d` passed 15/15
`VulkanHostAllocationDiagnosticsTests`, including allocation-contract fault
injection, internal-notification counters, and partial-root lifetime order.
Its self-contained Windows publish and four-run target matrix completed. Those
results are historical experiment evidence only.

### Current branch after probe removal

The final cleanup head removes the probe source and focused tests, restores
null Vulkan allocation callbacks, and restores the pre-probe lifecycle path.
The investigation source revision is `a899e62d55f5e5ec7f690f897867e9c6df29123c`.
The published Release build had
the SHA-256 recorded above and the symbol-only portable-PDB build did not
change production behavior. The required Fast lane produced 801/801 tests,
0 errors, and 0 warnings; no dedicated probe-focused tests remain. The control
and trace runs and WPR validity are recorded in the result section above.
`git diff --check` passed; no shader lane is applicable
because shader and GPU behavior were unchanged.

Raw VMMap CSVs, JSONL diagnostics, manifests, logs, WPR output, and any target-
derived data remain outside Git under the investigation artifact root.

Related context: [startup memory ownership](STARTUP_MEMORY_OWNERSHIP.md),
[oversized detile work](OVERSIZED_DETILE_WORK.md),
[post-snapshot startup frontier](POST_SNAPSHOT_STARTUP_FRONTIER.md), and
[startup residency and resource lifetime](STARTUP_RESIDENCY_AND_RESOURCE_LIFETIME.md).
