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
application's `VirtualAlloc` paths. The instance/device `pfnAllocation`,
`pfnReallocation`, and `pfnFree` request ledger still saw no request larger
than 133,120 bytes, and the informational internal-allocation callbacks
reported zero notifications. The next boundary is an elevated Windows
Performance Recorder `VirtualAllocation` trace with allocation stacks.

This finding records observations, inferences, and uncertainty separately. It
does not call the remainder a native leak, managed leak, driver allocation, or
other owner without attribution evidence.

## Environment and target identity

The controlled runs used the existing ignored target configuration. Absolute
target and artifact paths are intentionally omitted from this tracked finding.

| Item | Value |
| --- | --- |
| Source baseline | `a0d9134cacea945713f96ea3824e7694733daf7e` |
| Diagnostic source revision | `766a44db0d470069b3038701df12d738805d6487` |
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
`61081837A19C4864C17CB49663B01479A654B7E17B68115330C5F064BB310F91`.

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
1.88–2.41 GiB `Private Data` working-set remainder. The correction matrix
added a bounded, opt-in probe at the instance and device `VkAllocationCallbacks`
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

The control and final diagnostics were run after commit `766a44d`, with the
same published binary and unchanged target policy. Every run ended at the
existing working-set safety cutoff; none reached the requested checkpoint.

| Run | Diagnostics | VMMap captures | Duration | Peak process-tree WS | Peak private | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `20260801T180004351Z-766a44d-trial-01` | disabled control | 0 | 33.0 s | 6.015 GiB | 11.377 GiB | working-set-limit |
| `20260801T180049134Z-766a44d-trial-01` | enabled | 2 | 33.0 s | 6.100 GiB | 11.389 GiB | working-set-limit |
| `20260801T180122195Z-766a44d-trial-02` | enabled | 3 | 30.8 s | 6.026 GiB | 11.376 GiB | working-set-limit |
| `20260801T180153026Z-766a44d-trial-03` | enabled | 3 | 36.5 s | 6.499 GiB | 11.884 GiB | working-set-limit |

The runner does not permit VMMap-assisted capture when diagnostics are disabled,
so the clean control has no VMMap export. This is a runner constraint, not an
assumption that the control and diagnostic samples are synchronized.

The direct `pfnAllocation` request ledger state at each matched VMMap
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

The active-byte value is requested bytes in the callback ledger, not a VMMap
resident value. The diagnostic structures are bounded and the normal path is
disabled. Deterministic tests cover balance, reallocation, duplicate release,
bound drops, disabled behavior, and callback-session lifetime.

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
| Total VMMap `Private Data` working set | The measured parent category, 4,792.8–5,239.4 MiB in the correction matrix; the retained prior captures were 5,052.4–5,506.8 MiB. |
| Exact guest `Private Data` | Subtracted once by exact guest interval and VMMap type, 2,736.7–3,078.0 MiB in the correction matrix. |
| Exact guest `Thread Stack` | Reported separately, 130.3–132.7 MiB in the correction matrix; not subtracted from `Private Data` because it is a different VMMap class. |
| Managed GC/runtime | GC committed and heap-used counters are overlapping evidence for the large reserved segment; they are not added to the remainder and do not prove object retention. |
| CPU backend/generated code and data | Source audit found small stubs, TLS/control storage, context frames, and worker/abort stacks with matching frees. The largest identified worker stack reservation is 4 MiB; no source path explains the 512 MiB/1 GiB signatures. No separate large CPU-backend owner is claimed. |
| Explicit Vulkan device memory | Tracked separately in `vulkan.device-memory`; excluded from process-private/resident-RAM totals. |
| Vulkan mapped host-visible memory | Address-correlated separately; at most 28.5 MiB of matched working set in these scans and no overlap with a listed top region. |
| Vulkan instance/device `pfnAllocation` request ledger | At most 1,871,478 outstanding requested bytes in the correction matrix; zero bookkeeping failures, drops, duplicate releases, and untracked releases. This is a subset of callback requests, not an additive VMMap owner. |
| Vulkan `pfnInternalAllocation` notifications | Zero allocation/free notifications and zero current/peak/largest/dropped/unmatched counters in all three diagnostic runs. These callbacks are informational and do not account for implementation allocations outside their coverage. |
| Cache, staging, deferred destruction, queue | Cache image is device-local accounting; staging is 0.5 MiB; deferred is zero; late queue is zero. These counters are not added to the remainder. |
| Remaining classification remainder | 1.675–2.173 GiB per correction-matrix matched capture, in addition to the retained prior 1.963–2.428 GiB range; dominated by the stable region signatures above and not assigned to a named owner. |

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
* The instance/device `pfnAllocation` request ledger had zero dropped records,
  zero duplicate releases, zero untracked releases, zero bookkeeping failures,
  and a maximum request of 133,120 bytes in each correction trial. The
  `pfnInternalAllocation`/`pfnInternalFree` callbacks reported zero events,
  bytes, drops, and unmatched frees in every diagnostic sample.
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
  application source has no matching request, the root `pfnAllocation` ledger
  did not see it, and the informational internal-allocation callbacks were
  silent. “External” is a boundary classification, not a claim that the
  NVIDIA driver owns or leaked it.
* The 1 GiB and smaller WriteCombine/RW shapes are related candidates, but
  their owner remains unresolved.

### Uncertain

* The root callback probe does not cover child Vulkan object calls that pass a
  null allocator or implementation/driver allocations outside the supplied
  `VkAllocationCallbacks` roots. The internal notification callbacks being
  silent does not close that boundary.
* The non-elevated WPR attempt did not produce allocation stacks. Without that
  evidence, the external boundary cannot be named more precisely.
* A .NET heap dump may be useful only if WPR or another lower-intrusion trace
  first attributes the large RW segment to managed object retention. It was not
  justified for this investigation.
* The 6.499 GiB process-tree peak in correction diagnostic trial 3 prevents a
  claim that instrumentation has no effect on peak timing. It does not change
  the repeated region shapes, zero internal notifications, or balanced request
  ledger.

## Ranked hypotheses and falsification

1. **Managed GC/runtime virtual segment — likely shape, not a leak finding.**
   Falsified if an address-aware trace attributes the 32,437.25 MiB reservation
   to a non-managed caller, or if the reservation/commit movement does not
   correlate with runtime segment activity across a matched frontier.
2. **External Windows/Vulkan virtual-allocation boundary — strongest unresolved
   owner boundary.** Falsified if WPR allocation stacks show SharpEmu or a
   managed allocator requesting the 512 MiB WriteCombine region, or if a
   synchronized child-object/implementation callback boundary observes the
   same block. The zero internal notifications do not falsify this hypothesis
   because those callbacks are informational and were not invoked here.
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
WPA. Keep the ETL and WPA workspace outside Git. The correction trials did not
expose any internal allocation notifications, so no narrower notification-led
follow-up is justified.

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

The narrow probe's focused deterministic tests passed: 15/15
`VulkanHostAllocationDiagnosticsTests`, including allocation-contract fault
injection, internal-notification counters, and partial-root lifetime order.
The self-contained Windows publish and final target matrix completed. The
required Fast lane and final `git diff --check` are recorded with the
documentation commit. The shader lane was not run because no shader or GPU
semantics changed.

Raw VMMap CSVs, JSONL diagnostics, manifests, logs, WPR output, and any target-
derived data remain outside Git under the investigation artifact root.

Related context: [startup memory ownership](STARTUP_MEMORY_OWNERSHIP.md),
[oversized detile work](OVERSIZED_DETILE_WORK.md),
[post-snapshot startup frontier](POST_SNAPSHOT_STARTUP_FRONTIER.md), and
[startup residency and resource lifetime](STARTUP_RESIDENCY_AND_RESOURCE_LIFETIME.md).
