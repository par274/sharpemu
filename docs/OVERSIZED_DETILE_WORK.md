<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Oversized detile work

Status: investigation complete on 2026-08-01. This is the focused finding
after the TiledSource accounting correction; it does not implement a memory
or scheduling correction.

## Conclusion

The approximately 5.01 GiB record is one VulkanComputeGuestDispatch for the
ACB compute queue. It is a ready, required queue head that was taken and is
still owned by the presenter while its execution call has not returned. It is
not waiting behind another item, blocked by a cross-queue dependency, or
rejected by the 256 MiB queue budget. The safety cutoff occurs before
CompleteGuestWork, so the retained-byte counter still includes the active
work even though the pending linked list no longer does.

The payload is 5,378,410,360 bytes (5,129.251823 MiB, 5.009034984 GiB).
Sixteen distinct 335,544,320-byte TiledSource arrays account for 5,120 MiB.
They are exact repeats of one 320 MiB guest array resource at sixteen image
bindings. Ten distinct 524,288-byte RgbaPixels arrays repeat a second guest
resource and account for another 5 MiB. The exact duplicate excess is
5,037,883,392 bytes (4,804.5 MiB). The observed payload would be
340,526,968 bytes (324.751823 MiB) if one immutable source snapshot were
reused for each repeated resource.

The narrowest correct next change is in the producer path that materializes
the image bindings: use a dispatch-local snapshot table in
AgcExports.CreateGuestDrawTextures/TryCreateGuestDrawTexture. Reuse only an
immutable source array whose complete guest range, selected view/mip,
descriptor, layout, storage semantics, and guest write generation match.
Keep a GuestDrawTexture per binding so view and sampler semantics remain
unchanged. This investigation does not make that change.

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
| Route | startup to first rendered frame |

The diagnostic event is opt-in and bounded. It records scalar work and
descriptor metadata, reference-identity array accounting, and all 43 array
owners in this item. It does not retain source arrays, hash contents, or dump
texture contents.

## Work identity and lifecycle state

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

## Complete payload composition

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

## Texture-array metadata

The event records one metadata row per image binding. The following groups
are equal by guest range and complete content identity; multiplicity is the
number of binding rows and each nonzero row has a separate allocated array.
Addresses are shown in hexadecimal. Source ranges use an exclusive end.

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

## Duplicate and overlap analysis

The 16 TiledSource arrays in the first group have the same exact guest range,
all descriptor fields, and content identity. They are different managed
objects, each with reference count one. Retaining one and reusing it for the
other fifteen bindings would remove

    15 x 335,544,320 = 5,033,164,800 bytes.

The ten 524,288-byte RgbaPixels arrays in the second group have the same
exact guest range and content identity. Reusing one would remove

    9 x 524,288 = 4,718,592 bytes.

Together the exact duplicate excess is 5,037,883,392 bytes, or 4,804.5 MiB.
There are no partial overlaps among the nonzero guest ranges. The two 3D
textures have physically padded source ranges, but their allocated RgbaPixels
lengths equal their calculated logical byte counts and their dimensions,
depths, and pitches explain the physical ranges. The 11-mip resource has a
524,288-byte selected source range; the event does not show a full mip-chain
copy. There is therefore no evidence for a dominant dimension, pitch, depth,
layer, or mip-count decode error.

The arrays are created together because one compute dispatch supplies a
40-entry image-binding list. CreateGuestDrawTextures materializes each
binding independently. Repeated bindings for the two exact resources carry
the same decoded descriptor and source identity, but the current path has no
dispatch-local source-snapshot table. The host texture-content cache is not
an already available source-array cache at this point, and it is populated on
the consumer side after host resource creation.

## Allocation and retention path

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
| Duplicate capture | Proven for 16 TiledSource and 10 RgbaPixels arrays by exact range plus complete content identity. |
| Eager materialization | Proven; arrays exist before enqueue and range over about two seconds. |
| Queue-budget block | Rejected; the item is admitted as the intentional single oversized item. |
| Scheduling/dependency block | Rejected as the reason for non-consumption; required sequence is complete and the item is taken at the queue head. |
| Exact inner execution blocker | Unresolved; the state only proves execution has not returned by cutoff. |

## Controlled trials

The following three clean, comparable trials used the final diagnostic commit,
the exact target identity and eboot hash, the unchanged target configuration,
6 GiB working-set limit, and unchanged page-file policy. The process identity
is the SharpEmu child PID. The diagnostic event was identical in payload and
state sequence in all three.

| Run | Child PID | Duration | Oversized sequence | Sampled peak WS/private | Last retained count | Visible checkpoint |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| 20260801T033052405Z-b67b143-trial-01 | 14496 | 18,891 ms | 765 | 9.157 / 14.094 GiB | 6 | first rendered frame after splash; nickname prompt not reached |
| 20260801T033111309Z-b67b143-trial-02 | 21496 | 16,163 ms | 767 | 9.353 / 14.276 GiB | 5 | first rendered frame after splash; nickname prompt not reached |
| 20260801T033148289Z-b67b143-trial-04 | 22256 | 16,764 ms | 768 | 9.366 / 14.284 GiB | 5 | first rendered frame after splash; nickname prompt not reached |

All three logs contain the splash presentation, splash hide, and first-frame
presentation messages. None reached the character-creation nickname prompt.
The final five-run set also included two trials that hit the working-set safety
limit before this dispatch was enqueued and one process exit code 4 in resource
file gathering. Those runs are reported as timing variance, not combined with
the three event-bearing samples: the payload finding reproduces in all three
comparable event-bearing trials.

## Implementation-ready recommendation

Change only the producer boundary that builds the image-binding snapshots:
AgcExports.CreateGuestDrawTextures and its TryCreateGuestDrawTexture helper.
Introduce a table scoped to one dispatch or one work construction. Its key
must include the exact source guest address and covered range, selected
view/mip and base mip, dimensions, depth, pitch, format, number type, tile
mode, texture type, array layout/layers, storage/write semantics, and a guest
write or dirty generation. On an exact match, construct the new binding record
with the binding's own descriptor and sampler fields but reuse the immutable
RgbaPixels or TiledSource reference. Do not make the table global or retain it
after work construction.

Expected target reduction is 4,804.5 MiB for this item, from
5,129.251823 MiB to about 324.751823 MiB. The change must preserve:

- guest queue order and sequence completion;
- resource visibility and write-generation semantics;
- selected texture-view, mip, array-layer, sampler, and storage behavior;
- immutable ownership of shared source arrays;
- no sharing across different source ranges or incompatible descriptors; and
- render-thread follow-up and deadlock safety.

Required synthetic regressions are repeated identical bindings sharing one
source array and being counted once, mismatched ranges/views/mips/storage
states refusing to share, array-layer TiledSource sizing, and queue
take/complete accounting with shared references. Target validation requires
at least three comparable runs with one 320 MiB TiledSource owner instead of
sixteen, one 512 KiB duplicate RgbaPixels owner instead of ten, unchanged
descriptor metadata, and an unchanged or improved visible checkpoint.

Other candidates are not the narrowest supported change. A global content
cache would broaden lifetime and invalidation rules. Deferring all capture
could alter guest visibility timing. Incremental detile or chunking would
need proof that queue order, resource views, and render-thread follow-up
remain valid. Reordering production cannot fix this instance because the
item was already ready and consumed.

The recommendation is falsified if later controlled samples show different
guest ranges or content for these bindings, a guest write occurs between
captures and sharing produces stale data, the backend mutates a supposedly
immutable source array, or deduplication leaves the same payload and
execution state. The exact post-take execution phase remains the next
separate investigation if the reduced payload still fails to complete.

## Verification

Focused diagnostics/accounting tests passed: 9/9. The shader lane was not run:
this commit changes only opt-in diagnostics and documentation, not shader
translation or GPU execution semantics. The required Fast lane and
git diff --check are recorded with the investigation change.
