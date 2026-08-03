<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup movie temporal boundary

Status: cumulative target finding with the stale-generation correction and
movie-local timeline contract established. Lawful packet measurement falsified
the authored bounded compressed-packet queue as a practical target model. The
production direction is now the smaller decode-and-discard model: keep FFmpeg
codec state ordered, pump interleaved audio while video destinations are full,
retain at most one decoded next frame, and discard video that is late against
the movie-local timeline. The model is implemented; target validation remains
pending the controlled Release pilot and attended-run authorization.

The finding concerns host-decoded Bink video used by the Demon’s Souls v1.004.000
startup route. It is an emulator-owned contract. It does not claim to know the
PlayStation’s proprietary internal implementation.

## Evidence provenance

The consequential identifiers for the earlier target findings are:

- Target: `PPSA01341`, Europe, version `1.004.000`.
- Target eboot SHA-256:
  `22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`.
- PR #18 control run:
  `20260802T220619684Z-a7ee8a4-trial-01`.
- PR #18 diagnostic runs:
  `20260802T221008090Z-a7ee8a4-trial-01` and
  `20260802T221703483Z-a7ee8a4-trial-01`.
- Diagnostic Release executable SHA-256:
  `FAA5F39B1A1395873DE5577770671421FF0A955DB0CADD716A7EC4C7280DAF47`.
- Phase 1 offline packet probe: local FFmpeg runtime tag `3b502d4`, FFmpeg
  bindings `7.1.1`, run on 2026-08-03 against the six anonymous basenames
  below. The probe retained only scalar aggregates and ran from ignored local
  files; no packet payloads or target-derived output are committed.
- PR #17 implemented host-generation invalidation at completion, guest close,
  replacement, and shutdown. Attended validation showed the former stale-black
  interval became grey; the remaining grey transition is a separate unresolved
  output boundary.

Raw target assets, traces, logs, manifests, source samples, movie fingerprints,
and target paths remain outside Git.

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

## Evidence-gate coverage and production-facing tests

The rejected packet-cap arithmetic remains as a small test-only evidence helper
in `MoviePacketCapacityEvidenceTests.cs`; it is not a production queue. The
timeline and media-pump tests now exercise the production
`MovieTimeline`/`MediaFramePlayback` boundaries with fake monotonic time,
explicit gates, packet timestamps, and synthetic packets. The old experiment
model files were removed once the production types covered their distinct
contracts. No retail content, FFmpeg-generated fixture, sleep, or wall-clock
assertion is used by these tests.

The original authored packet schedule remains useful as a compact description of
the starvation boundary:

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
candidate bound was two deferred video packets and eight retained bytes. The
production test helper retains only scalar count/byte arithmetic; it does not
recreate a packet queue or retain packet identity.

The production-facing tests now cover the selected one-frame model with an
explicit five-destination gate, interleaved audio, timestamped late output,
complete slow-consumer input, and disposal. The rejected packet-cap arithmetic
is kept separately as evidence-gate coverage so its byte and count semantics do
not become production machinery.

## Tested facts

### Pre-change packet behavior

Before the selected production change, the production contract was:

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

### Lawful packet measurement and evidence gate

The ignored local probe opened each asset with the repository's FFmpeg-compatible
runtime, read the actual interleaved packet sequence, and retained only counts,
byte totals, timestamp aggregates, ordering counters, and consumer simulations.
The event timestamp used for demux-arrival windows and backlog simulation was
DTS when present, otherwise PTS. PTS and DTS were both reported independently;
all six assets had complete, monotonic PTS/DTS values. Video packet duration was
one 1/30-second time-base tick in every asset. The source durations reported by
FFmpeg were 8.5, 8, 12, 20, 20, and 117.366667 seconds for the requested files.

The per-stream aggregates were:

| Asset | Stream | Packets / bytes | Packet size min / median / p95 / p99 / max | PTS / DTS range | Duration range |
| --- | --- | ---: | ---: | --- | --- |
| `ps_studios_logo.bk2` | video 0 | 255 / 45,038,052 | 1,072 / 197,904 / 326,688 / 409,652 / 474,552 | 0–8.466667 s / 0–8.466667 s | 0.033333–0.033333 s |
|  | audio 1 | 195 / 120,128 | 84 / 592 / 728 / 804 / 10,036 | 0–8.48 s / 0–8.48 s | 0.04–0.04 s |
| `attract_movie.bk2` | video 0 | 3,521 / 680,480,616 | 1,072 / 205,172 / 234,908 / 286,356 / 620,088 | 0–117.333333 s / 0–117.333333 s | 0.033333–0.033333 s |
| `logo_intro.bk2` | video 0 | 360 / 71,053,168 | 3,304 / 206,732 / 250,520 / 306,968 / 324,192 | 0–11.966667 s / 0–11.966667 s | 0.033333–0.033333 s |
| `logo_intro_loop.bk2` | video 0 | 240 / 49,779,576 | 185,316 / 206,724 / 218,772 / 226,360 / 434,804 | 0–7.966667 s / 0–7.966667 s | 0.033333–0.033333 s |
| `main_menu.bk2` | video 0 | 600 / 124,417,148 | 19,432 / 172,768 / 477,944 / 878,440 / 1,464,704 | 0–19.966667 s / 0–19.966667 s | 0.033333–0.033333 s |
| `main_menu_ngp.bk2` | video 0 | 600 / 124,413,240 | 17,836 / 158,464 / 536,344 / 747,516 / 1,506,800 | 0–19.966667 s / 0–19.966667 s | 0.033333–0.033333 s |

`ps_studios_logo.bk2` is the only requested asset with an audio stream. Its
maximum run between audio packets was 23 video packets, 2,452,968 compressed
bytes, and 733.333 ms of video timestamps; adjacent audio packet timestamps
were at most 760 ms apart. This independently correlates the target's two
approximately 0.5–0.7-second `frame-buffer-wait` observations with the offline
sequence: after five destinations are owned, the decoder can be unable to reach
the next audio packet while traversing a video-only run of the same order of
magnitude. The target waits began with approximately 100–130 ms of movie audio
queued and resumed after that queue emptied; the offline sequence does not prove
which consumer held the fifth destination.

The cumulative video packet count/bytes encountered at source timestamps 100,
250, 500, 750, and 1,000 ms, followed by the complete asset, were:

| Asset | 100 ms | 250 ms | 500 ms | 750 ms | 1 s | Complete |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `ps_studios_logo.bk2` | 4 / 449,988 | 8 / 886,172 | 16 / 2,809,484 | 23 / 4,480,640 | 31 / 6,245,740 | 255 / 45,038,052 |
| `attract_movie.bk2` | 4 / 10,400 | 8 / 14,688 | 16 / 23,264 | 23 / 88,808 | 31 / 167,812 | 3,521 / 680,480,616 |
| `logo_intro.bk2` | 4 / 22,800 | 8 / 64,504 | 16 / 254,976 | 23 / 625,848 | 31 / 1,429,048 | 360 / 71,053,168 |
| `logo_intro_loop.bk2` | 4 / 997,436 | 8 / 1,745,296 | 16 / 3,243,740 | 23 / 4,717,512 | 31 / 6,433,688 | 240 / 49,779,576 |
| `main_menu.bk2` | 4 / 1,691,972 | 8 / 2,423,396 | 16 / 3,301,208 | 23 / 5,291,368 | 31 / 6,577,852 | 600 / 124,417,148 |
| `main_menu_ngp.bk2` | 4 / 1,653,468 | 8 / 2,081,924 | 16 / 3,387,556 | 23 / 4,881,312 | 31 / 6,629,668 | 600 / 124,413,240 |

The consumer simulation modeled five initially owned decoded destinations,
one video packet decoded per released destination, and packet arrivals at the
measured DTS/PTS timestamps. It did not assume that every stream packet is a
frame; it counted the actual video packets. The maximum retained compressed
backlog and the retained state when the source reached EOF were:

| Asset | Consumer | Max packets / bytes | At source end packets / bytes | End byte fraction |
| --- | ---: | ---: | ---: | ---: |
| `ps_studios_logo.bk2` | 2 FPS | 234 / 41,010,944 | 233 / 40,789,652 | 90.6% |
|  | 3 FPS | 225 / 39,006,628 | 225 / 39,006,628 | 86.6% |
|  | 4 FPS | 217 / 37,317,008 | 216 / 37,106,956 | 82.4% |
|  | 5 FPS | 208 / 35,578,028 | 208 / 35,414,180 | 78.6% |
|  | 10 FPS | 166 / 27,251,580 | 165 / 26,419,180 | 58.7% |
| `attract_movie.bk2` | 2 FPS | 3,282 / 670,038,816 | 3,282 / 669,300,192 | 98.4% |
|  | 3 FPS | 3,164 / 646,155,764 | 3,164 / 644,829,244 | 94.8% |
|  | 4 FPS | 3,047 / 622,186,284 | 3,047 / 620,611,948 | 91.2% |
|  | 5 FPS | 2,930 / 598,304,292 | 2,930 / 596,256,436 | 87.6% |
|  | 10 FPS | 2,343 / 478,670,536 | 2,343 / 474,557,316 | 69.7% |
| `logo_intro.bk2` | 2–5 FPS | 332 / 69,995,312; 320 / 67,981,140; 308 / 64,624,544; 296 / 61,548,840 | 331 / 69,882,356; 320 / 67,981,140; 307 / 64,314,632; 295 / 61,352,652 | 98.4%; 95.7%; 90.5%; 86.3% |
| `logo_intro_loop.bk2` | 2–5 FPS | 220 / 45,705,052; 212 / 43,964,956; 204 / 42,275,536; 196 / 40,604,688 | 219 / 45,490,328; 211 / 43,761,756; 203 / 42,057,692; 196 / 40,604,688 | 91.4%; 87.9%; 84.5%; 81.6% |
| `main_menu.bk2` | 2–5 FPS | 556 / 115,012,368; 536 / 111,056,104; 516 / 106,869,516; 496 / 103,003,316 | 555 / 114,893,628; 535 / 110,964,220; 515 / 106,681,164; 495 / 102,764,428 | 92.3%; 89.2%; 85.7%; 82.6% |
| `main_menu_ngp.bk2` | 2–5 FPS | 556 / 115,220,812; 536 / 110,918,964; 516 / 106,816,740; 496 / 103,184,804 | 555 / 114,842,276; 535 / 110,630,516; 515 / 106,709,764; 495 / 102,609,124 | 92.3%; 88.9%; 85.8%; 82.5% |

The four values in each `2–5 FPS` cell are ordered 2, 3, 4, and 5 FPS.
At 30 FPS the simulation retained no backlog; at 10 FPS it still retained
58.7–69.7% of the bytes for the assets with video. The 2–5 FPS backlog grows
with playback duration toward the complete asset, not toward a small stable
bound. It would require approximately 570 MiB for `attract_movie.bk2` at 5 FPS
and approximately 98 MiB for either main-menu asset at 5 FPS, before FFmpeg
reference overhead. A practical finite cap would therefore fill and reproduce
the measured audio starvation. The largest individual packet is 1,506,800
bytes, so no small byte cap can hide an oversized packet outside the bound.

The ignored local runtime smoke opened `ps_studios_logo.bk2` through the
production `FfmpegVideoDecoder` with the SDL dummy audio driver. Direct decode
reached all 255 video frames without late drops. A separate
`MediaFramePlayback` run held all five external destinations, reached the
interleaved audio pump, reported movie audio `Running`, and retained exactly
one next decoded frame with zero retained compressed packets. Direct smoke
decodes also opened `attract_movie.bk2` and `main_menu_ngp.bk2` and decoded 600
frames each. These are local runtime checks, not attended target results.

The authored two-packet/eight-byte candidate remains valid as a synthetic
ownership and backpressure experiment, but it is falsified as the production
target model by this evidence gate. It is rejected because the required
backlog is duration-dependent and material on the 16 GiB host, not because
FFmpeg reference counting is inherently unreliable.

### Selected timeline behavior

The production `MovieTimeline` and `MediaFramePlayback` tests establish these
emulator-owned rules:

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
10. Diagnostics-disabled execution retains the existing diagnostic short-circuit;
    production media code does not make the movie timeline depend on it.

The direct timeline tests cover audio ownership, no-audio wall time, temporary
underrun, permanent failure, pause/resume, completion, replacement identity,
and monotonicity. The media-pump tests cover the five-destination gate, audio
pumping, late-frame discard, EOF/disposal, and zero compressed-packet
retention.

## Evaluated alternatives

### A. Decode-and-discard late video output — selected

The packet measurement falsified compressed-packet deferral as the production
model. Alternative A keeps one demux and one video decoder, sends every video
packet to FFmpeg in demux order, and keeps the existing five externally owned
RGBA destinations. When those destinations are full, the decoder continues
through the interleaved input far enough to submit the next movie-audio packet.
Decoded video is compared with the movie-local time using the frame PTS and is
discarded only when its presentation interval is already late. At most one
decoded next `AVFrame` reference is retained; there is no compressed-video
queue and no decoded RGBA queue beyond the existing five destinations.

The exact production limits are therefore:

- five external BGRA/RGBA presentation destinations, each with one owner;
- one FFmpeg input `AVPacket`, unreferenced after every read;
- one decoder working `AVFrame`;
- zero retained compressed packets;
- at most one explicitly owned next decoded `AVFrame` reference;
- no target-specific packet, asset, or frame-name condition.

The pump order is:

```text
oldest retained next frame → convert only when a destination is available
audio packet              → audio decoder/host stream immediately
video packet              → send to the video decoder in input order
late decoded video        → unref/discard while preserving codec state
future decoded video      → retain only the single next frame, or discard
```

The future-frame rule is deliberately small: the earliest future decoded frame
is the only frame allowed to cross the no-destination boundary. Later frames are
decoded to preserve codec reference state and immediately released; they are not
copied into another queue. The demux continues through the following video run
until the next audio packet or EOF, so interleaved audio is reached without
retaining the run. This preserves codec reference state while keeping the
retained media bound independent of movie duration.

At EOF, the demux is marked exhausted, both decoders are drained, the retained
next frame is delivered or released, and only then can playback complete.
Cancellation, replacement, and disposal wake the pump, release the retained
frame exactly once, stop audio submission, and leave externally owned
destinations untouched. A full destination pool is a pump state, never false
EOF. This model is selected because its retained-media bound is independent of
movie duration and it directly addresses the measured starvation without the
570 MiB class backlog observed at 5 FPS.

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

The implementation preserves these invariants:

1. A decoded RGBA destination has one owner. It is not overwritten, reused, or
   returned to the free pool until that owner releases it.
2. The demux owns at most one live input `AVPacket`; every read is either sent,
   processed, or unreferenced before the next read.
3. The decoder owns at most one retained next `AVFrame` reference. The working
   frame and retained frame are unreferenced exactly once on delivery, late-frame
   discard, EOF drain, cancellation, replacement, or disposal.
4. No compressed-video queue exists. Video packets are sent in demux order,
   audio packets remain ordered, and decoded video may be discarded without
   skipping codec input or breaking reference state.
5. EOF means demux exhaustion, not playback completion. Audio, video decoder
   output, and the one retained next frame must drain before completion.
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

## Selected design and limits

The selected production mechanism is Alternative A: decode-and-discard late
video output in the existing one-demux context. It has no compressed-packet cap
because it retains no compressed packets. Its exact media limits are the five
external destinations, one working input packet, one working video frame, and at
most one retained next `AVFrame` reference described above. The selected clock
model remains a generation-owned movie-local timeline: movie audio supplies only
that movie's local progress, audio-less or failed playback uses the defined local
fallback, and unrelated `GuestAudioClock` values are never inputs.

The authored two-packet/eight-byte queue remains synthetic test coverage for
ownership and backpressure history, but it is not production code and does not
set a target limit. Production-facing tests cover late-frame discard, PTS
ordering, the one-frame bound, audio pumping while destinations are full,
complete slow-consumer input, and disposal ownership. The real FFmpeg path was
also exercised locally against the lawful assets without retaining payloads.

The audio seam must expose local estimated progress without depending on
`HostAudioDiagnostics`: no-track, running, temporary-underrun, normal completion,
permanent open/decoder/submission/device failure, and disposal. SDL queue
arithmetic remains an estimate of input removed from SDL's input queue, not a
measurement of physical or audible playback. Other host backends may return a
safe unavailable state until they implement equivalent progress.

The timeline must be created for each host movie generation and must use:

1. this movie's running audio estimate;
2. a held value during temporary underrun;
3. an anchored local wall continuation after normal audio completion with video
   remaining or after permanent audio failure;
4. local monotonic wall time for no-track movies;
5. a held value while paused, with resume rebasing the local wall origin;
6. a terminal old identity on skip, completion, replacement, and disposal.

This is a finite ownership model implemented and covered by deterministic
synthetic testing. It has no target-specific override and does not require a
separate audio context.

## Remaining uncertainty

- The exact guest/render consumer holding the fifth buffer is still unknown.
- The lawful probe establishes packet order and scalar size/timestamp aggregates,
  not the host runtime's exact scheduling or which consumer owns a destination.
- SDL queue arithmetic remains an estimate, so the local movie-audio progress
  source must retain its calibrated non-audible terminology.
- The criterion for distinguishing temporary audio underrun from permanent
  device/decoder failure must be tied to explicit host error/state transitions,
  not an arbitrary elapsed-time guess.
- The selected one-frame late-discard path has not yet been attended on the
  target; its frame-drop distribution, exact movie/audio visual alignment, and
  wall-duration effect remain target validation questions.
- The title's intended proprietary clock ownership remains unknown. The
  selected contract is justified by emulator ownership, target observations,
  and bounded behavior, not by a claim about Sony internals.

## Falsifiers

The selected model or timeline hypothesis must be revisited if any of these
occur:

- A synthetic or lawful FFmpeg fixture shows that one retained next frame cannot
  reach the next required audio packet without a duration-growing queue; this
  would reopen the separate-audio-context comparison.
- A video packet is skipped before being sent to FFmpeg, codec reference state
  becomes invalid, or PTS order is not preserved at the decoder input.
- A late-frame discard overwrites or reuses an owned RGBA destination, retains
  more than one decoded next frame, or reports EOF before the retained frame and
  decoder output drain.
- Audio remains starved while the destination pool is full, or a permanent
  failure cannot transition to the anchored fallback without a jump.
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
dotnet test tests\SharpEmu.Libs.Tests\SharpEmu.Libs.Tests.csproj -c Release --filter "FullyQualifiedName~MediaFramePlaybackTests|FullyQualifiedName~MovieAudioPumpContractTests|FullyQualifiedName~MovieTimelineContractTests|FullyQualifiedName~MoviePacketCapacityEvidenceTests"
```

The requested repository verification remains:

```powershell
./scripts/verify.ps1 -Lane Fast
git diff --check
```

Shader verification is unnecessary because this change touches no shader or
GPU semantics. Target validation is pending the controlled Release pilot and
attended-run authorization.

### Release pilot preflight

The clean self-contained Windows Release artifact was published from commit
`15f6944e283bd643e405a40c1d8d7b34a03015bb` on 2026-08-03. Its `SharpEmu.exe`
SHA-256 is:

```text
F62A41247BD76A541964DD486477D9193A45BCDDAFE8AD4445E71D4FBD4A7880
```

The read-only preflight preserved target `PPSA01341`, Europe, `1.004.000`,
and the expected eboot SHA-256 above. Windows reported automatic page-file
management disabled and a 32,768 MiB page file; the configured runner limits
remain 9 GiB working set, 2 GiB minimum available physical memory, and 4 GiB
minimum commit headroom. No attended target run has been launched for this
phase; the pilot is waiting for readiness authorization.
