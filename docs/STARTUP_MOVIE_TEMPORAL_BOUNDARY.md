<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup movie temporal boundary

Status: cumulative target finding with the stale-generation correction and
movie-local timeline contract established. Lawful packet measurement falsified
the authored bounded compressed-packet queue as a practical target model. The
first one-demux decode-and-discard implementation then failed target validation:
it lost required future video frames. A bounded demux-boundary repair preserved
one packet and one next frame but stalled at the first future frame and crossed
the physical-memory safety boundary. A focused independent-context probe then
supported a separately bounded movie-audio demux/decode context, and the
production boundary now uses it for movies with audio. The first targeted retail
listening run reached the later host movies and main menu, but audible artifacts
and the physical-memory safety boundary prevent accepting the correction; no
claim is made until comparable confirmation runs pass.

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
- First attended pilot: `20260803T042151858Z-ebb9e72-trial-01`, Release
  executable SHA-256 `F62A41247BD76A541964DD486477D9193A45BCDDAFE8AD4445E71D4FBD4A7880`.
- Bounded demux-boundary follow-up pilot:
  `20260803T043935358Z-ebb9e72-trial-01`, executable SHA-256
  `641419B207D507E3F37285B1479B29EA328667CAE858B6120D9B6347BA99211C`.
  The follow-up was intentionally run from a dirty working tree containing
  only the bounded-boundary probe; its raw manifest records that fact.
- Final evidence-only clean Release from commit
  `b86f4f8f48fcc35560f1915d0f4d077f5fdceb54`: executable SHA-256
  `28E541E64E53F6AF05827B7CD5E043E8FD398A586D5B65B3CF52B8B522AF053D`.
  It was not attended on the target because the pump model had already been
  falsified and the runner safety boundary had been crossed by the follow-up.
- PR #17 implemented host-generation invalidation at completion, guest close,
  replacement, and shutdown. Attended validation showed the former stale-black
  interval became grey; the remaining grey transition is a separate unresolved
  output boundary.
- First targeted listening run of the independent-context implementation:
  `20260803T055628280Z-c19e6f0-trial-01`, commit
  `c19e6f00416fe31cf70ed3a116802b27e270018c`, executable SHA-256
  `F0F16F2EFF1B88E0926F0D2B81FE4F4F8C16E7FF3F5CAEE33C0178250B4B5ADE`.
  Optional per-event movie and memory diagnostics were disabled for this
  listening-only run; runner metrics and the emulator log remain outside Git.

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

The independent movie-audio context phase established these additional durable
facts using the lawful target asset and scalar-only measurements:

- `ps_studios_logo.bk2` opens through two independent FFmpeg input contexts
  with distinct format, codec, packet, frame, and resampler state. Both
  contexts report format start `0` and duration `8,500,000` microseconds; the
  first video and audio packet timestamps are both `0`, with video time base
  `1/30` and audio time base `1/48000`.
- The second context owns the selected audio stream and its own decoder,
  resampler, one live packet, one live frame, fixed 16 KiB PCM conversion
  storage, and a host stream requested at a 32 KiB queue cap. Audio packets and
  decoded frames remain ordered; the video context remains the only video
  decoder and keeps its five externally owned destinations.
- Three fresh scalar probe trials measured approximately 16.2–16.6 MiB
  additional working set, 12.4–13.4 MiB additional private memory, and one
  additional process handle for the second FFmpeg context. The dummy host
  stream added approximately 2.7–3.0 MiB working set and 30 handles; that
  device cost is backend-specific and is not attributed to FFmpeg state.
- The largest packet observed while scanning the logo through either context
  was `474,552` bytes. The production audio path rejects packets above its
  explicit 4 MiB bound and decoded frames above its explicit sample bound.
- `attract_movie.bk2` has no audio stream and therefore does not open the
  second context. It remains on a movie-local monotonic wall clock.
- The audio context compares its format start and duration with the already
  opened video context. Normal completion requires demux EOF, decoder EOF,
  resampler drain, and exact host queue drain. Open, decoder, submission, and
  device failures are terminal and visible; temporary queue-empty underrun is
  a recoverable state. Host generation disposal cancels and joins the audio
  pump before releasing its native state.

The target assets, raw traces, logs, manifests, and game-derived data remain
outside Git.

## Authored experiment

The experiment is test-only in
`tests/SharpEmu.Libs.Tests/Media/MovieAudioPumpExperiment.cs` and
`MovieTimelineExperiment.cs`. It uses no retail content, FFmpeg-generated file,
sleep, or wall-clock assertion. The timeline tests advance `FakeMonotonicTime`
explicitly.

This is not a parallel media architecture. Once production behavior is
implemented and production-facing tests cover the distinct contracts, remove or
collapse test-only model code that no longer protects a separate contract.

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

The authored two-packet/eight-byte candidate remains valid as a synthetic
ownership and backpressure experiment, but it is falsified as the production
target model by this evidence gate. It is rejected because the required
backlog is duration-dependent and material on the 16 GiB host, not because
FFmpeg reference counting is inherently unreliable.

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

## Attended pilot evidence and stopping point

The clean self-contained Release preflight preserved `PPSA01341`, Europe,
`1.004.000`, the expected eboot SHA-256, the fixed 32 GiB page file, and the
runner limits of 9 GiB working set, 2 GiB minimum available physical memory,
and 4 GiB minimum commit headroom. The first pilot was authorized after that
preflight. Raw logs, JSONL diagnostics, screenshots, and manifests remain in
ignored local run directories.

The first pilot used the one-demux decode-and-discard implementation from
commit `ebb9e7254ba9f55d4efb941ba726c96f665e247a`. It reached the attract route
but not the character-creation nickname prompt before the 300-second wall
limit. Its scalar observations were:

- `ps_studios_logo.bk2` completed at frame 218 in 7.3086 seconds, versus the
  measured 8.5-second source and the PR #18 control completions at frame 254
  in 11.13, 13.90, and 14.12 seconds.
- The movie-owned SDL stream submitted and dequeued all 408,960 input frames
  with zero failed submissions. Its queue arithmetic nevertheless recorded 60
  underruns totaling approximately 2.496 seconds. This supports “submitted
  continuously with no submission failure,” not a claim about continuous
  physical or audible sound.
- The first movie clock used the movie-owned progress estimate. At start the
  selected local position was zero while the unrelated global AudioOut2 clock
  was already approximately 32.86 seconds ahead. The movie clock recorded
  `Running` and `TemporaryUnderrun` states and `MovieAudio` and
  `HeldDuringUnderrun` modes; no global clock was used by the production code
  in that pilot.
- No late-frame count was visible in the periodic movie events, but the
  completion at frame 218 proves the implementation had discarded or failed
  to make available later source frames. This is an incorrect video result,
  not a timing correction.
- `attract_movie.bk2` used local wall time, reached movie-local 128.71 seconds
  against its 117.3667-second source, and was still active at frame 3212 of a
  target frame index of 3861 when the runner stopped. No main-menu progression
  or expected checkpoint was observed.
- Peak working set was 8,593,494,016 bytes and peak private bytes were
  14,809,223,168 bytes. Minimum available physical memory was
  2,375,888,896 bytes. Cleanup reported no failures, but the private-memory
  headroom was too narrow to treat this as a safe timing confirmation.

The follow-up tested the smallest apparent repair: stop at the first future
decoded frame, retain one measured-size demux-boundary packet, and wake when
that frame's local PTS interval became late. It used executable SHA-256
`641419B207D507E3F37285B1479B29EA328667CAE858B6120D9B6347BA99211C`.
The runner stopped at the physical-headroom safety boundary after 55.028
seconds. The movie had only reached frame 0; its local clock was held at zero
in `TemporaryUnderrun`/`HeldDuringUnderrun`, with one retained next frame and
one 114,456-byte boundary packet. The movie audio stream had submitted 46,080
and dequeued 44,160 input frames, had 40 ms queued, and recorded two short
underruns. Minimum available physical memory was 2,089,025,536 bytes, below
the configured 2 GiB boundary. Cleanup again reported no failures.

These pilots falsify the selected one-demux/one-frame model for this target:
the first version drained future frames too aggressively; the boundary repair
could not keep audio supplied while a future frame and the next video packet
blocked the demux. No confirmation runs were justified after the first pilot,
and the follow-up independently confirmed that the small repair was unsafe and
ineffective. Grey, black, and flashing output were not investigated.

The first targeted listening run of the independent-context implementation was
not a confirmation run. It reached `attract_movie.bk2`, `logo_intro.bk2`, and
`main_menu.bk2`; the bridge attached and guest-closed each asset in order. The
first `ps_studios_logo.bk2` reached frame 254 in 9.11 seconds. The runner
stopped after 300.617 seconds at the unchanged physical-headroom boundary:
peak working set was 8.731 GiB, peak private memory was 17.529 GiB, minimum
available physical memory was 1.846 GiB against the 2 GiB floor, and minimum
commit headroom was 21.725 GiB. No confirmation run was justified after this
boundary.

The following are direct attended observations, not claims inferred from queue
metrics:

- The first PlayStation Studios logo audio was no longer audibly stretched or
  delayed, but contained a persistent unpleasant noisy/lagging artifact.
- The grey interval remained. Near the end of the first logo, its audible tail
  had not finished before a second similar sound began over the grey output;
  that second sound played in short bursts separated by silence. The target
  still showed the later `Sony Interactive Entertainment Presents` visual.
- Audible output was present during `attract_movie.bk2` but was more severely
  intermittent and noisy. The authored asset inventory says that movie has no
  embedded audio stream, so this sound must not be attributed to the
  independent movie-audio context without a future source trace.
- `logo_intro.bk2` produced audible output dominated by very loud noise, with
  the intended audio nearly inaudible. Menu music and button-selection audio
  were present for the first time in this experiment.
- The maintainer reached the main menu, selected Play, selected Continue
  Offline, and then the emulator ended. Character Creation was not observed.
  No visual improvement was observed: the grey interval and later Sony visual
  remained.

These observations support that the independent path changes the first logo's
temporal behavior and allows later movie/menu progression, but they do not
establish audible correctness. The noisy/intermittent output, the apparent
overlapping or replayed logo sound during the grey interval, and the difference
between embedded movie audio and other guest audio are now the next audio
frontier. They must be traced separately from the grey/black/flashing rendering
problem and from the general low-FPS condition.

## Evaluated alternatives

### A. Decode-and-discard late video output — falsified on target

The packet measurement falsified compressed-packet deferral as the production
model. Alternative A keeps one demux and one video decoder, sends every video
packet to FFmpeg in demux order, and keeps the existing five externally owned
RGBA destinations. When those destinations are full, the decoder continues
through the interleaved input far enough to submit the next movie-audio packet.
Decoded video is compared with the movie-local time using the frame PTS and is
discarded only when its presentation interval is already late. At most one
decoded next `AVFrame` reference is retained; there is no compressed-video
queue and no decoded RGBA queue beyond the existing five destinations.

The hypothetical finite limits would therefore be:

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
not copied into another queue; the audio submission boundary paces demux work,
and the consumer will receive the retained next frame before the decoder reads
the following video run. This preserves codec reference state while allowing
the measured audio packets behind a video run to be reached.

At EOF, the demux is marked exhausted, both decoders are drained, the retained
next frame is delivered or released, and only then can playback complete.
Cancellation, replacement, and disposal wake the pump, release the retained
frame exactly once, stop audio submission, and leave externally owned
destinations untouched. The target pilots falsified this one-demux contract:
the first implementation discarded required future frames, while the boundary
repair stalled audio at the first future frame. It is therefore not a
production selection despite its finite nominal ownership bound.

### B. Separate audio demux/decode context — selected production model,
target correction not yet accepted

The audio context owns its own `AVFormatContext`, selected audio codec,
packet, frame, resampler, conversion storage, and bounded host stream. Video
retains the current five externally owned destinations and remains the only
video decoder; there is no compressed-video deferral, second video decoder,
video packet skipping, or decode-and-discard path.

The lawful scalar probe established that the same asset can be opened through
two independent FFmpeg input contexts with matching format origin and
timestamp domain. Three fresh trials measured approximately 16.2–16.6 MiB
additional working set, 12.4–13.4 MiB additional private memory, and one
additional process handle for the second FFmpeg context. The separate dummy
host stream cost approximately 2.7–3.0 MiB and 30 handles in that probe; this
is backend-specific and is not attributed to FFmpeg state.

Production now uses a generation-local submission boundary. Supported SDL,
WinMM, CoreAudio, and ALSA streams expose strict, cancellation-aware bounded
submission and exact queue depth. A calibrated submission-paced capability is
explicit; an unavailable-progress capability never claims a host drain. Each
context owns at most one live input packet and one working frame, and fixed
conversion storage plus packet/sample limits provide the retained-state bound.

The first attended target run showed the intended temporal improvement and
later/menu progression, but direct listening found persistent noise, replayed
or intermittent sound over the grey interval, severe logo-intro noise, and
sound during the audio-less `attract_movie.bk2`. Scalar attribution has not
yet been run, so this model remains selected for investigation but is not an
accepted audio correction.

### C. Unbounded decoded-frame or packet queue

This would keep reading and put video frames or packets into a queue with no
finite bound. It could pump audio, but its memory cost is unbounded, its
ownership contract becomes harder to audit, and a slow consumer can turn a
temporary presentation delay into native memory growth. It is rejected.

### D. Wall clock as the timing correction

Wall clock explains why the current shared clock stretches `attract_movie.bk2`,
but it does not preserve the movie's own audio relationship and does not fix
the frame-buffer starvation. It remains a diagnostic comparison, not a
selected production contract.

## Movie-local timeline contract

The movie-local timeline is owned by the active host movie generation. It is
created at attach/start and is never a static global clock. The timeline source
state is explicit:

| State | Source | Behavior |
| --- | --- | --- |
| Movie audio running | This movie's host audio progress estimate | Advance monotonically, capped at the movie's local wall origin so future audio cannot select future video. |
| Temporary underrun | Last movie-local audio value | Hold video; do not read AudioOut or AudioOut2 progress. |
| Host progress unavailable | No synthetic clock or drain claim | Keep the explicit unsupported capability visible; supported backends must expose exact or calibrated progress before movie completion can be claimed. |
| Audio unavailable or permanently failed | Movie-local monotonic wall time | Switch once to a wall fallback anchored at the last value; never freeze on a dead audio source. |
| No audio stream | Movie-local monotonic wall time | Advance independently of every guest audio stream. |
| Paused | Last selected value | Hold until the owning playback resumes; resume rebases wall/fallback time. |
| Completed or skipped | Terminal value | Stop selecting frames and tear down the generation. |
| Replaced or disposed | Old identity terminated | New playback always receives a new identity, even for the same path. |

An unrelated AudioOut or AudioOut2 stream can never legitimately advance a host
movie under this contract. The contract is intentionally narrower than the
current `GuestAudioClock` and does not assert that the PS5 uses the same model.

## Lifecycle and synchronization invariants

The production implementation must preserve all of these invariants:

1. A decoded RGBA destination has one owner. It is not overwritten, reused, or
   returned to the free pool until that owner releases it.
2. The demux owns at most one live input `AVPacket`; every read is either sent,
   processed, or unreferenced before the next read.
3. Each context owns at most one working `AVFrame`; it is unreferenced exactly
   once on delivery, EOF drain, cancellation, replacement, or disposal.
4. No compressed-video queue exists. Video packets are never skipped before
   FFmpeg receives them, audio packets remain ordered, and no decoded video is
   retained outside the existing externally owned destination model.
5. EOF means demux exhaustion, not playback completion. Audio and video decoder
   output, the resampler, and the host stream must drain before completion.
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

## Selected model and bounded ownership

The independent audio-context model is selected because the lawful probe closed
the previous falsifiers without sharing mutable FFmpeg state. The production
implementation is generation-local and opens the second context only after the
video context identifies an audio stream. A no-audio movie does not open it.

The video context owns video packet order, video decoding, frame conversion, and
the five external RGBA destinations. The audio context independently owns its
format context, selected audio codec context, packet, frame, resampler, and host
stream. Each context has at most one live input packet and one working frame;
audio conversion uses fixed storage, strict host queue bounds on every supported
backend, and explicit packet/sample limits. No compressed-video queue, second
video decoder, packet deferral, video packet skipping, or decode-and-discard path
was added.

The two contexts use the same path-origin contract: the audio open checks the
already-open video format start and duration, and both begin demuxing from the
same source origin. Audio and video EOF are independent. Normal movie
completion waits for video drain plus audio demux EOF, decoder EOF, resampler
drain, and host queue drain. A temporary empty host queue holds the movie clock
and may recover; explicit open, decoder, submission, and device failure enters a
visible terminal state and releases the host stream. Normal audio completion or
terminal audio failure uses an anchored movie-local wall continuation while
video remains. No-audio movies use their own monotonic wall clock.

Pause, resume, cancellation, skip, replacement, and disposal are owned by the
movie generation. Backends that cannot pause expose that unsupported capability
explicitly; they do not silently claim device pause. Disposal cancels and joins
the audio pump before releasing its native resources; the existing presenter
generation invalidation boundary is unchanged. Diagnostics are opt-in and
bounded; the disabled path does not construct event payloads, format state,
lock the event stream, or perform per-event accounting.

The authored independent-context contract tests cover saturation, EOF order,
underrun recovery, normal completion, no-audio behavior, all failure classes,
pause/resume, lifecycle races, stale generations, native ownership, finite
retained state, diagnostics bounds, and repeated teardown. The earlier
two-packet/eight-byte queue remains synthetic coverage for falsified-boundary
history and is not production code.

## Remaining uncertainty

- The exact guest/render consumer holding the fifth buffer is still unknown.
- The lawful probe establishes packet order and scalar size/timestamp aggregates,
  not the host runtime's exact scheduling or which consumer owns a destination.
- SDL queue arithmetic remains an estimate, so the local movie-audio progress
  source must retain its calibrated non-audible terminology.
- The criterion for distinguishing temporary audio underrun from permanent
  device/decoder failure must be tied to explicit host error/state transitions,
  not an arbitrary elapsed-time guess.
- The probe's process deltas are scalar host measurements, not a decomposition
  of every FFmpeg allocator or device-driver allocation. The target pilot must
  measure the complete emulator process while the movie runs.
- The selected implementation has one attended retail listening run, but its
  audible result is not correct enough to accept: the first logo has noisy
  artifacts, the grey interval has intermittent/replayed sound, and later
  movies have noisy or intermittent output. The run reached the main menu and
  the offline path but not Character Creation; the unchanged physical-memory
  boundary also prevented a safe confirmation run.
- The earlier one-demux pilots did not reach main-menu progression and remain
  no evidence about the selected model. The selected model reached later host
  movies and menu audio once, but still lacks comparable confirmation and a
  source-level explanation for the later audible output.
- The title's intended proprietary clock ownership remains unknown. The
  movie-local contract is justified by the authored boundary and target clock
  observations, not by a claim about Sony internals.

## Falsifiers

The selected implementation remains unaccepted as a target correction if any
of these falsifiers appears:

- A one-demux model must not lose a source frame, stall at the first future frame,
  or cross the configured physical-memory safety boundary. Both failure modes
  were observed in the pilots and are now accepted evidence against Alternative
  A.
- The separate audio context must preserve duplicate file ownership, exact
  audio and video EOF/drain ordering, cancellation, disposal, host-stream
  failure, and bounded memory on the target.
- A video packet is skipped before being sent to FFmpeg, codec reference state
  becomes invalid, or PTS order is not preserved at the decoder input.
- A candidate pump overwrites or reuses an owned RGBA destination, retains more
  than its explicit bound, or reports EOF before all decoder output drains.
- Audio remains starved while the destination pool is full, or a permanent
  failure cannot transition to the anchored fallback without a jump.
- A controlled target run shows movie-local audio and video remain correctly
  synchronized while the global AudioOut2 clock is ahead/slow, or shows that a
  no-audio movie must follow a guest stream. That would falsify the movie-local
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
dotnet test tests\SharpEmu.Libs.Tests\SharpEmu.Libs.Tests.csproj -c Release --filter "FullyQualifiedName~SharpEmu.Libs.Tests.Media"
```

The requested repository verification remains:

```powershell
./scripts/verify.ps1 -Lane Fast
git diff --check
```

Shader verification is unnecessary because this change touches no shader or
GPU semantics. Retail target confirmations are still pending; the earlier
one-demux pilots are not evidence against this separately bounded model.

Verification completed before retail target launch:

- focused media suite: 68 passed;
- complete solution suite: 883 passed;
- Fast verification passed, including the target-memory, VMMap, runner
  supervision, Release build, and complete solution test gates;
- `git diff --check` passed;
- shader verification is unnecessary because this change touches no shader or
  GPU semantics.
