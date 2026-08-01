<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Oversized detile work

Status: implementation and target validation complete on 2026-08-01. Commit
`c129d0f` implements the dispatch-local source-snapshot table described by the
investigation and the matched target trials below measure its effect.

## Conclusion

The approximately 5.01 GiB record is one VulkanComputeGuestDispatch for the
ACB compute queue. It is a ready, required queue head that was taken and is
still owned by the presenter while its execution call has not returned. It is
not waiting behind another item, blocked by a cross-queue dependency, or
rejected by the 256 MiB queue budget. The safety cutoff occurs before
CompleteGuestWork, so the retained-byte counter still includes the active
work even though the pending linked list no longer does.

Before the change, the payload was 5,378,410,360 bytes (5,129.251823 MiB,
5.009034984 GiB). Sixteen distinct 335,544,320-byte TiledSource arrays
accounted for 5,120 MiB. They were repeated compatible captures of one 320
MiB guest source range at sixteen image bindings. Ten distinct 524,288-byte
RgbaPixels arrays were repeated compatible captures of a second guest source
range and accounted for another 5 MiB.

The producer now keeps one dispatch-local table of immutable source snapshots
while `AgcExports.CreateGuestDrawTextures` constructs the bindings. The same
target work now retains one 335,544,320-byte TiledSource and one 524,288-byte
RgbaPixels array for those groups. The measured payload is 340,526,968 bytes
(324.751823 MiB), a reduction of 5,037,883,392 bytes (4,804.5 MiB). Each
binding still has its own descriptor, view metadata, and sampler state.

The dispatch completes through the existing queue lifecycle with exact payload
accounting. The remaining target blocker is later startup execution: all three
new trials reached the same first-frame checkpoint (and logged a guest frame),
but the unchanged 6 GiB working-set safety limit still terminated the process
before any nickname or character-creation evidence.

## Implemented invariant and compatibility key

The table is ownership of immutable source snapshots for one
`CreateGuestDrawTextures` invocation only. It is not a global cache and is not
retained after construction. A complete successful guest read or materialized
detile populates an entry; cache-hit, upload-known, fallback, and failed-read
paths do not. The consumer does not mutate the shared source arrays, so every
binding made from an entry observes the same captured bytes. A later binding
gets its own `GuestDrawTexture` and sampler conversion while reusing only the
immutable `RgbaPixels` or `TiledSource` array and snapshot metadata.

The actual `GuestTextureSnapshotKey` contains:

- the complete decoded `TextureDescriptor` (address, logical dimensions,
  physical size, format, number type, tile mode, type, mip range, pitch,
  destination selects, depth, array pitch/base, LOD, BC swizzle, metadata
  address, and descriptor flags);
- selected mip, storage and arrayed-view flags, normalized texture depth,
  source width, output layer count, base-mip byte offset, source address, and
  covered byte range;
- logical and physical source byte counts, per-slice byte count, slice stride,
  source layer count, base-mip-tail state and tail coordinates;
- representation (`RgbaPixels` or `TiledSource`), exact detile parameters when
  GPU detile is used, and the nullable tracked guest write generation.

Sampler state is deliberately not a key field because it is binding-specific.
Different ranges, views, mips, dimensions, formats, layouts, storage
semantics, layer behavior, detile interpretations, or known write generations
therefore cannot share. A tracked generation difference produces different
keys. On Windows the write tracker is normally unavailable. In that case the
nullable generation is part of the exact dispatch-local key: the first
complete read is authoritative for later compatible bindings in that one
construction. This is safe for exact aliases because sequential copies are an
implementation artifact, not separate guest-visible observations; the table
never crosses an invocation and uncertain/incompatible captures are not
generalized.

## Scope and evidence

Target identity was verified before the runs:

| Field | Value |
| --- | --- |
| Title ID | PPSA01341 |
| Region | Europe / EP9000 |
| Version | 1.004.000 |
| Eboot SHA-256 | 22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306 |
| Host | Windows, RTX 3070 Ti, NVIDIA 610.74 |
| Safety policy | 6 GiB working-set limit, unchanged page-file policy |
| Diagnostic commit | b67b143d7b90dcf72eb979246bd3d0afa547fd2e |
| Implementation commit | c129d0f |
| Route | startup to first rendered frame |

The diagnostic event is opt-in and bounded. It records scalar work and
descriptor metadata, reference-identity array accounting, and all 43 array
owners in this item. It does not retain source arrays, hash or compare
contents, record guest write generations, or dump texture contents.

## Work identity and lifecycle state before implementation

| Field | Observation |
| --- | --- |
| Concrete type | VulkanComputeGuestDispatch |
| Operation | compute-dispatch |
| Sequence | 765, 767, and 768 in the three comparable trials |
| Required sequence | 0; required sequence was complete |
| Logical queue | acb.compute[64] |
| Submission | 8 |
| Shader | guest address 0x0000000448626400; SPIR-V 1,824,536 bytes |
| Dispatch | groups 27 x 15 x 72; local size 8 x 8 x 1; direct dispatch |
| Writes global memory | false |
| Image/global bindings | 40 textures, 12 global buffers |
| Queue state at event | ready-head, then taken, then executing |
| Cutoff state | queue depth 0, pending count 0, pending bytes 5,378,410,360 |
| Completion | no completed event before the safety cutoff |

The state sequence answers the scheduling question. The item was at the head
with the preceding contiguous sequence complete. TryTakeGuestWork removed it
from the queue, after which the presenter marked it executing. The stored
payload is subtracted only when execution returns through CompleteGuestWork.
Therefore the old description "still pending" means active ownership in the
retained-byte accounting, not that the item was still waiting in the queue.

The instrumentation does not identify the exact inner phase after the
executing transition. It could be host resource creation, submission, a GPU
wait, or another operation inside the execution path. The evidence does
establish that the presenter had consumed the work and had not reached
completion; related wait messages are not sufficient to claim a shader hang.

## Complete payload composition before implementation

Payload accounting counts each reachable byte array once by reference. The
reference count is the number of field references, so it exposes the shared
zero-length placeholder without treating it as additional bytes.

| Category | Unique arrays | References | Unique bytes | MiB |
| --- | ---: | ---: | ---: | ---: |
| Compute shaders | 1 | 1 | 1,824,536 | 1.740013 |
| Vertex shaders | 0 | 0 | 0 | 0 |
| Pixel shaders | 0 | 0 | 0 | 0 |
| RgbaPixels | 14 | 40 | 5,384,192 | 5.134766 |
| TiledSource | 16 | 16 | 5,368,709,120 | 5,120.000000 |
| Global buffers | 12 | 12 | 2,492,512 | 2.377045 |
| Vertex buffers | 0 | 0 | 0 | 0 |
| Index buffers | 0 | 0 | 0 | 0 |
| Image-write pixels | 0 | 0 | 0 | 0 |
| **Total** | **43** | **69** | **5,378,410,360** | **5,129.251823** |

The global buffer lengths are complete: globalBuffer[0..4] are 262,144 bytes
each; [5] is 16; [6] is 32; [7] is 16; [8] is 32; [9] is 131,072; [10] is
1,048,576; and [11] is 2,048. The RgbaPixels payload is ten 524,288-byte
arrays, one 131,072-byte array, one 8,192-byte array, one 2,048-byte array,
and one zero-length array referenced 27 times.

The smallest set responsible for most of the item is the sixteen TiledSource
arrays: 99.819626% of the stored payload. The next largest individual array
is the 1,824,536-byte compute shader, followed by the 1,048,576-byte
globalBuffer[10]. The ten 524,288-byte RgbaPixels arrays are the next repeated
owners.

## Texture-array metadata before implementation

The event records one metadata row per image binding. The following groups
share a guest range and compatible recorded texture metadata/content-key
fields; byte identity and equal write generation were not established.
Multiplicity is the number of binding rows and each nonzero row has a separate
allocated array. Addresses are shown in hexadecimal. Source ranges use an
exclusive end.

| Binding indices | Count | Guest address and covered range | Descriptor fields | Mips/view/storage | Calculated source | Allocated arrays | Content identity |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| 14,15,16,17,18,19,20,21,23,24,26,27,29,30,32,33 | 16 | 0x102A400000 to 0x103E400000; 335,544,320 bytes | 1024 x 1024 x depth 1; pitch 1024; arrayLayers 80; format 4; numberType 7; tileMode 24; type 13 | mip 0, base 0, resource mips 1; arrayed true; storage false | logical/physical 335,544,320; slice/stride 4,194,304; source layers 80 | TiledSource IDs 7-14,16,17,19,20,22,23,25,26; each 335,544,320; RgbaPixels ID 2 is empty | address 0x102A400000, 1024 x 1024, format 4, numberType 7, dstSelect 0x924, tile 24, pitch 1024, sampler words 0x08004092/0x00FFF000/0x06500000/0x40000000, arrayed 80, type 13, depth 1 |
| 8,13,25,28,31,34,35,36,37,38 | 10 | resource address 0x1026C00000; source 0x1026C40000 to 0x1026CC0000; 524,288 bytes | 1024 x 1024 x depth 1; pitch 1024; arrayLayers 1; format 170; numberType 9; tileMode 9; type 13 | mip 0, base 0, resource mips 11; arrayed true; storage false | logical/physical 524,288; slice/stride 524,288; source layers 1 | RgbaPixels IDs 5,6,18,21,24,27,28,29,30,31; each 524,288; TiledSource 0 | address 0x1026C00000, 1024 x 1024, format 170, numberType 9, dstSelect 0xFAC, tile 9, pitch 1024, sampler words 0x08060400/0x00FFF000/0x0AF00000/0x40000000, arrayed 1, type 13, depth 1 |
| 4 | 1 | 0x448F90000 to 0x449010000; 524,288 bytes | 8 x 8 x depth 8; pitch 8; arrayLayers 1; format 4; numberType 4; tileMode 9; type 10 | mip 0, base 0, resource mips 1; arrayed false; storage false | logical 2,048; physical 524,288; slice/stride 524,288; source layers 1 | RgbaPixels ID 3, 2,048; TiledSource 0 | address 0x448F90000, 8 x 8, format 4, numberType 4, dstSelect 0x4, tile 9, pitch 8, sampler words all zero, arrayed false, type 10, depth 8 |
| 5 | 1 | 0x448FB0000 to 0x4491B0000; 2,097,152 bytes | 32 x 32 x depth 32; pitch 32; arrayLayers 1; format 4; numberType 4; tileMode 9; type 10 | mip 0, base 0, resource mips 1; arrayed false; storage false | logical 131,072; physical 2,097,152; slice/stride 2,097,152; source layers 1 | RgbaPixels ID 4, 131,072; TiledSource 0 | address 0x448FB0000, 32 x 32, format 4, numberType 4, dstSelect 0x4, tile 9, pitch 32, sampler words all zero, arrayed false, type 10, depth 32 |
| 22 | 1 | 0x1029800000 to 0x1029810000; 65,536 bytes | 128 x 128 x depth 1; pitch 128; arrayLayers 1; format 170; numberType 9; tileMode 9; type 11 | mip 0, base 0, resource mips 8; arrayed false; storage false | logical 8,192; physical 65,536; slice/stride 65,536; source layers 1 | RgbaPixels ID 15, 8,192; TiledSource 0 | address 0x1029800000, 128 x 128, format 170, numberType 9, dstSelect 0xFAC, tile 9, pitch 128, sampler words 0x08060400/0x00FFF000/0x0AF00000/0x40000000, arrayed false, type 11, depth 1 |

The remaining binding indices 0,1,2,3,6,7,9,10,11,12,39 have no nonzero
source array in this work. They reference the shared zero-length RgbaPixels
array (ID 2) where applicable. They do not add payload bytes. No texture
content was dumped.

## Duplicate and overlap analysis before implementation

The 16 TiledSource arrays in the first group have the same recorded guest
range, compatible descriptor fields, and content-key metadata. They are
different managed objects, each with reference count one. If guest
memory/write-generation semantics establish that they are the same source
snapshot, retaining one and reusing it for the other fifteen bindings would
avoid an estimated

    15 x 335,544,320 = 5,033,164,800 bytes.

The ten 524,288-byte RgbaPixels arrays in the second group have the same
recorded guest range and compatible content-key metadata. If they are the
same source snapshot under the dispatch's memory/write-generation semantics,
reusing one would avoid an estimated

    9 x 524,288 = 4,718,592 bytes.

Together, the repeated compatible captures represent an estimated removable
capture overhead of 5,037,883,392 bytes, or 4,804.5 MiB, conditional on the
source-snapshot equivalence described above. This is not a byte-for-byte
deduplication result: contents were not hashed or compared, and write
generation was not recorded.
There are no partial overlaps among the nonzero guest ranges. The two 3D
textures have physically padded source ranges, but their allocated RgbaPixels
lengths equal their calculated logical byte counts and their dimensions,
depths, and pitches explain the physical ranges. The 11-mip resource has a
524,288-byte selected source range; the event does not show a full mip-chain
copy. There is therefore no evidence for a dominant dimension, pitch, depth,
layer, or mip-count decode error.

The arrays are created together because one compute dispatch supplies a
40-entry image-binding list. CreateGuestDrawTextures materializes each
binding independently. Repeated bindings for the two same-range resource
descriptions carry compatible decoded descriptor and content-key metadata, but
the current path has no dispatch-local source-snapshot table. The host
texture-content cache is not
an already available source-array cache at this point, and it is populated on
the consumer side after host resource creation.

## Allocation and retention path before implementation

The observed path is:

1. ObserveComputeDispatch decodes the image bindings.
2. CreateGuestDrawTextures calls TryCreateGuestDrawTexture for every binding.
3. Each miss calculates the source size, checks the existing content lookup,
   allocates a new RgbaPixels or TiledSource byte array, and reads guest
   memory. The lookup is before each allocation, but the repeated keys are
   cold because this work has not reached the consumer and there is no
   work-local source cache.
4. SubmitComputeDispatch constructs VulkanComputeGuestDispatch and calls
   EnqueueGuestWorkLocked. Only then is the complete payload calculated and
   subjected to the pending-work budget. The arrays already exist.
5. The deliberate single-oversized-item rule admits this item because there
   was no payload outstanding. PendingGuestWork retains the work and its
   exact stored payload total.
6. TryTakeGuestWork removes the queue node but does not subtract the stored
   bytes. The presenter execution path owns the active work until it returns
   and CompleteGuestWork releases the accounting.

Snapshot ages in the event range from roughly 0.4 ms to 2,029 ms at enqueue,
which is direct evidence of eager materialization over the dispatch build
interval. The diagnostic object retains only scalar IDs and metadata; it does
not retain any byte array. The presenter cache and submission records retain
native host resources, not these source byte arrays. The inspected path found
no second managed owner for the original source arrays. After verified
completion the work and local references become unreachable, subject to normal
GC timing; cumulative source-allocation counters do not imply that those
arrays are still live.

This separates the hypotheses:

| Hypothesis | Result |
| --- | --- |
| Accounting omission | Corrected before this investigation; the event reconciles the stored total exactly. |
| Descriptor/source-size error | Rejected for the dominant owners: calculated and allocated lengths match; padded 3D cases are small and explainable. |
| Repeated compatible capture | Established for 16 TiledSource and 10 RgbaPixels arrays by recorded range and compatible metadata; byte identity is unverified. |
| Eager materialization | Proven; arrays exist before enqueue and range over about two seconds. |
| Queue-budget block | Rejected; the item is admitted as the intentional single oversized item. |
| Scheduling/dependency block | Rejected as the reason for non-consumption; required sequence is complete and the item is taken at the queue head. |
| Exact inner execution blocker | Unresolved; the state only proves execution has not returned by cutoff. |

## Controlled trials before implementation

The following three clean, comparable trials used the final diagnostic commit,
the exact target identity and eboot hash, the unchanged target configuration,
6 GiB working-set limit, and unchanged page-file policy. The process identity
is the SharpEmu child PID. The diagnostic event was identical in payload and
state sequence in all three.

| Run | Child PID | Duration | Oversized sequence | Sampled peak WS/private | Last retained count | Visible checkpoint |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| 20260801T033052405Z-b67b143-trial-01 | 14496 | 18,891 ms | 765 | 9.019 / 13.616 GiB | 6 | first rendered frame after splash; nickname prompt not reached |
| 20260801T033111309Z-b67b143-trial-02 | 21496 | 16,163 ms | 767 | 8.709 / 13.034 GiB | 5 | first rendered frame after splash; nickname prompt not reached |
| 20260801T033148289Z-b67b143-trial-04 | 22256 | 16,764 ms | 768 | 9.003 / 13.049 GiB | 5 | first rendered frame after splash; nickname prompt not reached |

All three logs contain the splash presentation, splash hide, and first-frame
presentation messages. None reached the character-creation nickname prompt.
The final five-run set also included two trials that hit the working-set safety
limit before this dispatch was enqueued and one process exit code 4 in resource
file gathering. Those runs are reported as timing variance, not combined with
the three event-bearing samples: the payload finding reproduces in all three
comparable event-bearing trials.

## Implemented producer boundary and regression coverage

`AgcExports.CreateGuestDrawTextures` now creates one
`GuestTextureSnapshotTable` and passes it through every
`TryCreateGuestDrawTexture` call. The table is populated only after a complete
read/materialization and is discarded when the invocation returns. GPU-detile
bindings reuse `TiledSource`; compatible CPU-materialized bindings reuse
`RgbaPixels`. Storage and array paths use the same key discipline, while
cache/upload-known behavior, fallback behavior, queue ordering, and sequence
completion remain unchanged.

The complete post-change payload composition for the dominant dispatch is:

| Category | Unique arrays | References | Unique bytes | Referenced bytes |
| --- | ---: | ---: | ---: | ---: |
| Compute shaders | 1 | 1 | 1,824,536 | 1,824,536 |
| RgbaPixels | 5 | 40 | 665,600 | 5,384,192 |
| TiledSource | 1 | 16 | 335,544,320 | 5,368,709,120 |
| Global buffers | 12 | 12 | 2,492,512 | 2,492,512 |
| **Total** | **19** | **69** | **340,526,968** | **5,378,410,360** |

Complete guest-work accounting uses reference identity, so the retained
payload is the unique-byte total, not the referenced-byte total. The table
therefore removes 5,037,883,392 bytes (4,804.5 MiB) from this work, measured
from the before and after diagnostics. The dominant dispatch still has the
same shader, `27 x 15 x 72` groups, `40` textures, `12` global buffers, and
`acb.compute[64]` queue identity. Its state sequence is
`ready-head,taken,executing,completed`; after completion its pending bytes are
zero.

The focused regressions cover production-boundary sharing of GPU-detile
`TiledSource` and CPU-materialized `RgbaPixels`, sampler preservation per
binding, reference-identity payload counting through take/complete, different
ranges, mip/view/format/layout/storage/layer/detile mismatches, known write
generation differences, the Windows untracked-generation exact-alias
invariant, failed-read fallback isolation, and per-invocation table lifetime.

## Matched target evidence after implementation

The following clean trials use the same target identity, eboot hash, host,
unchanged 6 GiB working-set policy, unchanged page-file policy, and the same
diagnostic route as the historical three event-bearing trials. The measured
payload is identical in all three. Runner-manifest peak values are shown in
GiB; timing is reported separately because it varies with startup scheduling.

| Run | Oversized sequence | Payload | Queue result | Peak WS / private | Duration | Checkpoint |
| --- | ---: | ---: | --- | --- | ---: | --- |
| 20260801T061920689Z-c129d0f-trial-01 | 768 | 340,526,968 bytes | completed; pending bytes 0 | 6.149 / 11.422 GiB | 50,619 ms | splash, first frame, and guest-frame logs; no nickname prompt |
| 20260801T062011318Z-c129d0f-trial-02 | 767 | 340,526,968 bytes | completed; pending bytes 0 | 6.274 / 11.653 GiB | 19,213 ms | splash, first frame, and guest-frame logs; no nickname prompt |
| 20260801T062030533Z-c129d0f-trial-03 | 768 | 340,526,968 bytes | completed; pending bytes 0 | 6.837 / 12.220 GiB | 20,069 ms | splash, first frame, and guest-frame logs; no nickname prompt |

Before implementation, the matched payload was 5,378,410,360 bytes
(5,129.251823 MiB), with peak WS/private values of 9.019/13.616,
8.709/13.034, and 9.003/13.049 GiB in the three event-bearing trials listed
above. Thus the payload reduction is measured, not predicted. The after
trials retain one 335,544,320-byte TiledSource referenced by sixteen bindings
and one 524,288-byte RgbaPixels array referenced by ten bindings, rather than
sixteen and ten separately allocated arrays.

At the sample immediately before the oversized event, managed GC heap/
committed memory was 807.5/820.7, 577.6/650.7, and 604.6/760.0 MiB after the
change. The corresponding before-implementation samples were 5,261.4/5,552.8,
5,278.5/5,620.7, and 5,168.1/5,380.1 MiB. These are event-adjacent memory
measurements, not timing-neutral performance benchmarks.

All three after trials reached the same first rendered frame after splash as
the before trials. They additionally logged a guest-frame presentation, but
there is no screenshot or log evidence of the nickname prompt or character
creation, so `docs/BASELINE.md` remains unchanged. The process still ends at
the unchanged working-set safety cutoff after this dispatch; the next frontier
is later startup execution and its remaining memory/wait behavior, not this
snapshot-ownership correction.

The post-correction startup frontier is measured separately in
`docs/POST_SNAPSHOT_STARTUP_FRONTIER.md`; this document remains the historical
record of the resolved dispatch-local snapshot boundary.

## Verification

The focused snapshot-sharing and guest-work lifecycle filter passed 15/15
tests, including the production `CreateGuestDrawTextures` boundary. The Fast
lane passed all 791 tests, and `git diff --check` passed. Three comparable
target trials reproduced the same dispatch identity, exact reduced payload,
queue completion, and first-frame checkpoint shown above. The shader lane was
not run because this change reuses already-produced byte arrays; it does not
change shader translation, SPIR-V, or GPU-detile shader semantics.
