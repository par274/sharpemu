<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup movie temporal boundary

Status: experiment-only finding. This change adds authored state-machine tests
and this contract record. It does not change retail decoder, audio, clock, or
presenter behavior.

The finding concerns host-decoded Bink video used by the Demon’s Souls v1.004.000
startup route. It is an emulator-owned contract. It does not claim to know the
PlayStation’s proprietary internal implementation.

## Established target evidence

The following facts were established before this experiment and are treated as
inputs, not as results inferred from the authored model:

- PR #17 fixed stale completed host-frame selection by invalidating the host
  movie generation at completion, close, replacement, and shutdown.
- PR #18 established the audio ownership and starvation boundary. The
  PlayStation Studios movie is a separate stream from AudioOut2 primary.
- Movie stream 2 decoded 408,960 source frames, converted 408,960 output
  frames, submitted all 408,960 frames to SDL, used 48 kHz stereo S16 input and
  48 kHz stereo F32 device output, used a 1.0 frequency ratio, and recorded no
  failed submission or conversion loss.
- `GuestAudioClock` was driven by `audio-out2-primary` stream 1. All 213
  reports from the movie stream were rejected because the shared furthest-value
  clock already retained the other stream's position.
- `MediaFramePlayback` enters `frame-buffer-wait` while all five RGBA frame
  buffers are owned. While it waits, `FfmpegVideoDecoder.TryDecodeNextFrame`
  cannot read more interleaved packets and therefore cannot pump later movie
  audio packets.
- Two measured waits began with approximately 100–130 ms of movie audio queued
  and resumed after the queue emptied. The consumer holding the fifth buffer was
  not isolated.
- `attract_movie.bk2` has no audio, but its host video follows the unrelated
  shared AudioOut2 clock and is heavily stretched. Wall-clock mode proves the
  shared-clock cause of the stretch; wall-clock mode alone is not an accepted
  correction.
- SDL queue arithmetic is an input-queue estimate, not a direct physical-device
  playback measurement. The grey transition and intermittent flashing remain
  separate rendering problems.

The target assets, raw traces, logs, manifests, and game-derived data remain
outside Git.

## Authored experiment

The experiment is test-only in
`tests/SharpEmu.Libs.Tests/Media/MovieAudioPumpExperiment.cs` and
`MovieTimelineExperiment.cs`. It uses no retail content, FFmpeg-generated file,
sleep, or wall-clock assertion. The timeline tests advance `FakeMonotonicTime`
explicitly.

The primary authored packet schedule is:

```text
V1 V2 V3 V4 V5 A6 V7 A8 V9 A10
```

`V1`–`V5` fill the five video destinations. The later audio packets are
deliberately interleaved with video packets after the destination pool is full.
The bound-pressure schedule is:

```text
V1 V2 V3 V4 V5 V6(4) V7(4) V8(5) A9
```

where the parenthesized values are authored compressed-packet byte sizes. The
candidate bound is two deferred video packets and eight retained bytes. The
model records packet identity, buffer identity, retained packet count, retained
bytes, EOF, failure, and disposal state.

Two current-behavior checks are intentionally separate from the candidate:

1. An actual `MediaFramePlayback` instance is rendezvoused after its fifth
   authored video frame. Its decoder has made five calls, submitted no later
   audio, and still has `A6 V7 A8` unread.
2. A deterministic replay of the current `MediaFramePlayback` and
   `IMediaFrameDecoder` contract makes the same boundary explicit without
   relying on thread scheduling.

The current shared-clock expression is also replayed separately: an unrelated
stream can supply the selected progress when it is ahead, or hold the selection
back when it is slow. The candidate movie-local clock tests must reject both
outcomes.

## Tested facts

### Current packet behavior

The current production contract is:

```text
if no free RGBA destination:
    wait
else:
    acquire one destination
    call TryDecodeNextFrame(destination)
```

`FfmpegVideoDecoder.TryFeedPacket` reads audio packets only inside that decoder
call. Consequently, after `V1`–`V5` are owned, the current decoder cannot reach
`A6`, `V7`, or any following packet. This is the measured starvation boundary;
it is not a conversion-loss, SDL-submit, or device-format finding.

### Candidate packet behavior

The authored candidate demonstrates that one demux context can continue
processing audio while all five video destinations are owned if it has a finite
compressed-video deferral queue:

- `A6`, `A8`, and `A10` are submitted while five decoded video buffers remain
  owned.
- `V7` and `V9` remain compressed and ordered in the deferral queue; no second
  decoded-frame queue is created.
- The queue never exceeds two packets or eight bytes in the authored bound
  test.
- When the count or byte bound is full, the next video packet is not consumed;
  the pump returns backpressure. A later audio packet behind that video packet
  is intentionally not skipped or reordered around the full boundary.
- Releasing buffer 0 decodes the oldest deferred packet into buffer 0; the
  experiment rejects any attempt to overwrite an owned buffer. The same holds
  for the next deferred packet and its released buffer.
- EOF is not completion until deferred compressed packets are drained. A
  device submission failure marks audio failed but does not create an unbounded
  video queue or prevent later video drain.
- Disposal clears all retained compressed packets, disposes the audio sink once,
  rejects further pump work, and leaves externally owned video buffers
  untouched.

These facts establish the narrow mechanism that can address the measured
startup audio starvation. They do not yet establish the target's final clock
owner.

### Candidate timeline behavior

The authored clock tests establish these emulator-owned rules:

1. A movie with its own audio uses that movie's local audio-progress estimate.
2. An audio-less movie uses its own monotonic wall-time origin.
3. Unrelated AudioOut and AudioOut2 progress is not an input to either policy.
4. A temporary movie-audio underrun holds the last movie-local audio position;
   it does not silently switch to wall time or to another stream.
5. A permanent audio-open or audio-device failure enters an explicit local
   wall-time fallback anchored at the last selected position, so it cannot
   freeze or jump at the transition.
6. Pause holds the selected position. Resume rebases a wall/fallback origin;
   audio is expected to be paused by the owning audio stream as well.
7. Completion, skip, replacement, and disposal terminate the old timeline.
8. Every host movie generation receives a new clock identity, including a
   same-path replacement.
9. Values are monotonic within one generation, even if an audio estimate
   regresses.
10. When timeline diagnostics are disabled, no authored diagnostic payload or
    event is constructed.

The tests cover a movie with audio, an audio-less movie, an unrelated AudioOut2
clock that is ahead, temporary underrun, permanent audio failure, pause, skip,
completion, replacement, same-path replacement, disposal, monotonicity, and
diagnostics-disabled execution.

## Evaluated alternatives

### A. Bounded compressed-video packet deferral in one demux context — selected

Ownership is unchanged for decoded video: exactly five RGBA destinations are
owned by the playback/consumer boundary, and a destination is returned only by
the consumer that owns it. A video packet encountered without a free
destination is retained as a referenced compressed packet, not decoded into a
new frame queue. Audio remains owned by the movie's audio decoder and host
stream.

The authored maximum is two packets and eight bytes of compressed payload. The
production implementation must use both a finite packet-count cap and a finite
byte cap; the exact production byte value is not claimed by this experiment
because a target packet-size histogram was not collected. At the bound, the
next video packet causes backpressure before `av_read_frame` consumes it. The
decoder resumes only after a video destination is released. This is a bounded
memory contract, not permission to grow the queue until EOF.

Demux/decode ordering is:

```text
oldest deferred video packet → oldest video destination when available
audio packet                → audio decoder/host stream immediately
new video packet             → defer if both bounds allow, otherwise backpressure
```

Video order is preserved within the video stream, audio order within the audio
stream, and no packet is dropped. Cross-stream execution intentionally permits
audio work after a deferred video packet; that is the behavior needed to cross
the measured starvation boundary. Movie video synchronization is supplied by
the separate movie-local clock contract above.

At EOF, the demux is marked exhausted, the audio decoder is drained, and
completion waits for the deferred video packets to acquire destinations and
drain. Cancellation wakes the pump, unreferences every retained packet, stops
audio submission, and does not reuse any externally owned destination. The
additional `FfmpegVideoDecoder` complexity is one bounded packet queue, one
full-boundary result, and a pump path that can run without a video destination.
Opening the asset twice is not required.

This is the smallest model that directly addresses the measured target wait.
Its important failure modes are a cap too small for an observed run of video
packets, leaked `AVPacket` references, decoding a deferred packet out of order,
or treating a full queue as EOF instead of backpressure. Those are all
synthetic-testable.

### B. Separate audio demux/decode context

The audio context would own its own `AVFormatContext`, audio codec, resampler,
and input progression. Video would retain the current five-buffer contract, so
there is no compressed-video deferral in the video context. Audio could continue
until its bounded host stream is full.

This requires opening the asset twice or creating a second independent input
context. Its memory cost is a second format/codec/resampler stack plus codec
buffers and the existing bounded audio stream; an exact byte cost was not
measured in this authored experiment. It has simpler per-context packet order
but two EOF/drain/cancel paths and a new synchronization problem between
independently positioned inputs. It would likely remove the measured starvation,
but adds duplicate file I/O, duplicated probing, and failure modes where the
audio and video contexts disagree about seek/EOF or cleanup. It is larger than
the selected one-queue change and is not required by the current evidence.

### C. Unbounded decoded-frame or packet queue

This would keep reading and put video frames or packets into a queue with no
finite bound. It could pump audio, but its memory cost is unbounded, its
ownership contract becomes harder to audit, and a slow consumer can turn a
temporary presentation delay into native memory growth. It is rejected.

### D. Wall clock as the timing correction

Wall clock explains why the current shared clock stretches `attract_movie.bk2`,
but it does not preserve the movie's own audio relationship and does not fix
the frame-buffer starvation. It remains a diagnostic comparison, not the
selected production contract.

## Selected clock contract

The movie-local timeline is owned by the active host movie generation. It is
created at attach/start and is never a static global clock. The timeline source
state is explicit:

| State | Source | Behavior |
| --- | --- | --- |
| Movie audio running | This movie's host audio progress estimate | Advance monotonically, capped at the movie's local wall origin so future audio cannot select future video. |
| Temporary underrun | Last movie-local audio value | Hold video; do not read AudioOut or AudioOut2 progress. |
| Audio unavailable or permanently failed | Movie-local monotonic wall time | Switch once to a wall fallback anchored at the last value; never freeze on a dead audio source. |
| No audio stream | Movie-local monotonic wall time | Advance independently of every guest audio stream. |
| Paused | Last selected value | Hold until the owning playback resumes; resume rebases wall/fallback time. |
| Completed or skipped | Terminal value | Stop selecting frames and tear down the generation. |
| Replaced or disposed | Old identity terminated | New playback always receives a new identity, even for the same path. |

An unrelated AudioOut or AudioOut2 stream can never legitimately advance a host
movie under this contract. The contract is intentionally narrower than the
current `GuestAudioClock` and does not assert that the PS5 uses the same model.

## Lifecycle and synchronization invariants

The next implementation must preserve all of these invariants:

1. A decoded RGBA destination has one owner. It is not overwritten, reused, or
   returned to the free pool until that owner releases it.
2. A deferred compressed packet has one queue owner. The queue holds a bounded
   `AVPacket` reference and releases it exactly once on decode, EOF drain,
   cancellation, replacement, or disposal.
3. The retained compressed packet count and bytes never exceed their hard caps.
   A full bound applies backpressure; it does not drop a packet or declare EOF.
4. Deferred video packets are decoded in packet order before later video input is
   accepted. Audio packets may be pumped while video is deferred.
5. EOF means demux exhaustion, not playback completion. Deferred video and
   decoder drain work must finish before completion is published.
6. Audio-device failure is observable to the movie timeline. A temporary
   underrun is not treated as permanent failure without an explicit state
   transition.
7. Pause, skip, completion, replacement, and disposal wake/cancel all pump
   waiters. No audio submission or packet read occurs after disposal wins.
8. The movie clock identity, audio source, frame ownership, and diagnostics all
   belong to the same host movie generation. A late callback from an old
   generation cannot update a replacement.
9. Diagnostics-disabled paths short-circuit before payload construction,
   formatting, event locking, or per-event accounting.

## Implementation-ready next change

This PR intentionally does not make this change. The next reviewed change
should be limited to the host movie boundary:

1. Add one small internal decoder capability, separate from the existing frame
   destination method, that lets `MediaFramePlayback` request audio/input pump
   progress without supplying a video destination. Non-FFmpeg decoders retain
   the current wait behavior.
2. In `FfmpegVideoDecoder`, add a bounded compressed-video packet queue. On a
   no-destination pump, consume audio packets immediately, retain video packets
   with owned `AVPacket` references, and return a distinct backpressure result
   when the packet or byte cap is full. Drain the oldest deferred packet before
   reading later video packets when a destination becomes available.
3. Keep decoded ownership at five buffers. Do not add a second decoded-frame
   queue. Add synthetic tests for packet order, both bounds, full-boundary
   backpressure, exact buffer reuse, EOF drain, audio failure, replacement, and
   disposal before enabling the path for retail movies.
4. Replace the movie's read of global `GuestAudioClock` with a generation-owned
   movie timeline. Feed it only the movie stream's local audio-progress estimate
   or the explicit no-audio/failure fallback. Keep `GuestAudioClock` unchanged
   for unrelated guest audio.
5. Make attach, pause, skip, complete, close, replacement, and disposal create
   or terminate the timeline identity atomically with the existing host movie
   generation. A same-path attach must clear all prior timeline state.
6. Add explicit audio state transitions for unavailable, running, temporary
   underrun, permanent failure, and normal audio end. The normal-end behavior
   must use the anchored fallback if video still has work to present.
7. Preserve the diagnostics short circuit and add no target-specific override.
   Validate the implementation with the authored suite before any controlled
   target run.

The packet-count and byte-cap values are deliberately one small measured design
choice, not a hidden unbounded fallback. This experiment proves the behavior at
two packets/eight authored bytes; the next change must choose and record a finite
production byte cap from a lawful packet-size trace before enabling retail
behavior. If one packet is enough for the trace, use one. If not, increase only
to the smallest cap that preserves the observed interleave.

## Remaining uncertainty

- The exact guest/render consumer holding the fifth buffer is still unknown.
- This experiment models packet ownership and ordering; it does not yet call
  FFmpeg against a committed synthetic media file. A local lawful FFmpeg probe
  may confirm packet interleave, but it is not a CI dependency.
- The target compressed-packet size distribution and the smallest production
  byte cap are not measured here.
- SDL queue arithmetic remains an estimate, so the local movie-audio progress
  source needs a precise host-stream contract in the implementation change.
- The criterion for distinguishing temporary audio underrun from permanent
  device/decoder failure must be tied to explicit host error/state transitions,
  not an arbitrary elapsed-time guess.
- The title's intended proprietary clock ownership remains unknown. The
  selected contract is justified by emulator ownership, target observations,
  and bounded behavior, not by a claim about Sony internals.

## Falsifiers

The selected model or timeline hypothesis must be revisited if any of these
occur:

- An authored or synthetic FFmpeg fixture requires audio packets after a full
  compressed-video bound but cannot make progress without an unbounded queue.
- A deferred packet is observed duplicated, dropped, decoded out of order, or
  released more than once.
- A full bound overwrites/reuses an owned RGBA destination or reports EOF before
  deferred packets drain.
- A target packet trace shows a required audio run consistently behind a bound
  that cannot be raised within the stated memory budget; this would reopen the
  separate-audio-context comparison.
- A controlled target run shows movie-local audio and video remain correctly
  synchronized while the global AudioOut2 clock is ahead/slow, or shows that a
  no-audio movie must follow a guest stream. That would falsify the selected
  clock owner.
- A temporary underrun demonstrably advances the title's expected movie video
  rather than holding, or permanent failure cannot transition to the anchored
  fallback without a jump.
- Completion, same-path replacement, skip, or disposal allows an old generation
  to advance a new generation's timeline.
- Diagnostics-disabled execution constructs payloads or performs event work.

## Verification

This experiment's focused lane is:

```powershell
dotnet test tests\SharpEmu.Libs.Tests\SharpEmu.Libs.Tests.csproj -c Release --filter "FullyQualifiedName~MovieAudioPumpContractTests|FullyQualifiedName~MovieTimelineContractTests"
```

The requested repository verification remains:

```powershell
./scripts/verify.ps1 -Lane Fast
git diff --check
```

Shader verification is unnecessary because this change touches no shader or
GPU semantics. No retail target run is required for this experiment.
