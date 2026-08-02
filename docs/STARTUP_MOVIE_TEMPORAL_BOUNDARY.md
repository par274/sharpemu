<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup movie temporal boundary

Status: diagnostic finding with the host-generation eligibility correction and
the final presenter submission-boundary hardening implemented. The target
evidence below validates the earlier stale-selection correction; the hardening
is covered by deterministic lifetime/resource tests. A separate grey
transition output remains unresolved.

This finding covers the startup movie sequence of Demon’s Souls v1.004.000
(`PPSA01341`, Europe) after the splash screen. It does not replace the current
compatibility frontier: the title has already been observed reaching the main
menu, the offline prompt, and name/class/starting-gift customization.

## Source sequence

The lawful local Bink assets were inspected with the repository’s existing
FFmpeg-compatible probe. Only metadata, private samples, and scalar diagnostic
results were retained locally; no game-derived artifacts are tracked.

| Asset | Source facts | Relevant material |
| --- | --- | --- |
| `ps_studios_logo.bk2` | 8.500 s, 30 fps, 255 frames, 3840×2160, one Bink audio track at 48 kHz stereo | Blue PlayStation Studios animation, symbols, logo, and a black final frame |
| `attract_movie.bk2` | 117.3667 s, 30 fps, 3,521 frames, 3840×2160, no audio stream | Starts with a black fade and the first title-card material, including “On the first day” in the opening section |
| `logo_intro.bk2` | 12.000 s, 30 fps, 360 frames, 3840×2160, no audio stream | Demon’s Souls title animation |
| `logo_intro_loop.bk2` | 8.000 s, 30 fps, 240 frames, 3840×2160, no audio stream | Looping Demon’s Souls title animation |
| `main_menu.bk2`, `main_menu_ngp.bk2` | 20.000 s, 30 fps, 600 header frames, 3840×2160, no audio stream | Main-menu background candidates |

Sampling did not locate the “Sony Interactive Entertainment presents” card in
the host-attached PlayStation Studios movie or in the title/menu candidate
movies sampled for this sequence. The card is therefore outside the host Bink
pixel stream observed here. Its exact guest resource/draw producer remains
unclassified.

The PlayStation Studios source order is monotonic: the opening blue imagery is
followed by the logo and then the black final frame. The repeated-looking
material is not a second section inside this source asset.

## Controlled evidence

The target identity used for the runs was:

- title ID `PPSA01341`;
- region Europe;
- version `1.004.000`;
- eboot SHA-256 `22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`.

The default control used native Bink behavior, the guest-audio-aware movie
clock, `SHARPEMU_LOG_MOVIE_SYNC=1`, and the unchanged controlled-runner safety
policy. The focused diagnostic used the same behavior plus the opt-in bounded
movie JSONL stream. A wall-clock comparison changed only
`SHARPEMU_MOVIE_CLOCK=wall`.

The direct visual observation from the no-recording control was:

- the Demon’s Souls splash appeared at approximately 6–10 s;
- after it disappeared, the window remained black for more than 20 s;
- the first “Sony Interactive Entertainment presents” card and blue
  PlayStation Studios animation completed by approximately 55 s;
- the window then remained solid black, with no observed flashing, until about
  1:50;
- the card appeared again around 1:50 and the next cinematic began around
  1:58 with “On the first day”;
- the user closed the window after reaching that next cinematic.

This observation is treated separately from earlier runs that showed flashing.
It proves the solid-black outcome for one run, not that every visual outcome has
the same immediate cause.

## Finding

### Temporal behavior

The default movie clock follows `GuestAudioClock` while `IsRunning` is true.
During the focused default run, the clock stayed running and progressed much
more slowly than wall time:

| Movie instance | Wall observation | Guest audio / selected playback | Result |
| --- | ---: | ---: | --- |
| `ps_studios_logo.bk2` | 12.169 s at the last clock sample; host completion at 12.680 s | 8.145 s | Completed once at source frame 254 |
| `attract_movie.bk2` | 170.174 s at the last sample | 95.721 s | Reached frame 2,871 of 3,521 before the 300 s runner limit |

The sampled current and target frame indices were monotonic for both movie
instances. There was no index restart, regression, or second host start.

The wall-clock control selected wall time while the guest audio estimate was
still slow. The PlayStation Studios movie completed at 9.87 s, and the attract
movie completed at 131.73 s at frame 3,520, close to the source duration but
with the expected diagnostic audio-clock desynchronization. This establishes
that the slow guest-audio progression explains the stretched host playback.
It does not establish that wall time is the correct guest-observable contract.

### Lifecycle behavior

The focused default run observed this host lifecycle, using anonymous instance
IDs and private basenames:

```text
43.477 s  attach/open  ps_studios_logo.bk2       instance 1
44.301 s  start       ps_studios_logo.bk2       instance 1
56.982 s  complete    ps_studios_logo.bk2       frame 254, 12.680 s playback
56.983 s  dispose     ps_studios_logo.bk2       reason complete
118.781 s guest close ps_studios_logo.bk2       no active host instance
130.254 s attach/open attract_movie.bk2          instance 2
130.369 s start       attract_movie.bk2          instance 2
```

There was one descriptor/open event for each observed host movie, no duplicate
active-path attach, no queue duplicate, no reattach of the same source, and no
second host start for `ps_studios_logo.bk2`. The late guest close was not a
restart: host playback had already completed and disposed instance 1, so the
close produced a non-active stop notification.

The guest path is still alive at the same time. `TryTakeOverGuestMovie` keeps
the real Bink header and guest draw alive; host pixels replace the sampled image
when the presenter identifies the Bink Y/UV bindings. Thus host decoding and
guest Bink/render work coexist. The evidence rules out a second host movie
instance, but it does not identify which ordinary guest draw produces the later
title card.

### Frame behavior

The decoder produces changing frames while the host instance is active. In the
focused default stream, instance 1 advanced through sampled frame indices
0–243 and completed at frame 254; instance 2 advanced through 0–2,871 in the
300-second sample. Frames were held between target-time changes and some late
frames were skipped, which is expected at the observed presentation rate.

The host frame serial and uploads advanced while each movie was active. After
the first movie completed, the presenter retained the last host frame and its
serial: the frame remained available while host playback was inactive, and the
same inactive instance was still selected by some Bink-shaped guest draws for
more than a minute. This is stale-frame eligibility, not a decoder restart.

### Presentation behavior

The presenter does not put a host movie directly on the final swapchain. It
uses host-decoded Y/UV resources as replacements for the guest Bink textures in
translated guest draws; the final swapchain presentation remains an ordinary
guest/translated presentation.

The focused stream therefore crosses the following boundary:

```text
host decoder advances/uploads
        → guest Bink-shaped draw may select host Y/UV resources
        → translated guest draw reaches ordinary swapchain presentation
```

#### Before the correction

After host completion, `VulkanVideoPresenter` deliberately kept
`_hostMovieFramePixels` and its serial while the next movie was not ready. The
diagnostic showed that completed host data remained eligible for selection even
though `HostMovieBridge.IsHostPlaybackActive` was false. The local source’s
final PlayStation Studios frame is black, and the direct run showed a
solid-black interval at this boundary. The narrowest proven black-output
boundary was the completed host frame remaining selectable during the
guest/host handoff.

#### Implemented host-generation correction

Each successfully attached host movie now receives a monotonically increasing
generation. Completion, guest close, replacement, and failed queued
continuation invalidate the bridge generation before the host instance is
disposed or cleared. Presenter shutdown clears its retained generation and
frame state. The presenter retains the generation with its frame and requires
an exact match among the retained frame, the active bridge generation, and the
host binding before selecting host Y/UV resources. A generation change clears
the retained CPU frame, converted planes, binding addresses, frame serials,
and upload serials, including when the path is unchanged. A stale binding
snapshot falls through to ordinary guest texture resolution.

Host texture resources retain their creation generation and instance identity.
Their preparation is provisional until the presenter reserves that exact
generation at the final CPU boundary before command recording. If completion,
guest close, or replacement wins first, the presenter rejects the late host
candidate, discards its unsubmitted staging state, rewrites the descriptor set
to the ordinary guest texture resources, and emits a bounded late-rejection
diagnostic. If the presenter reserves first, bridge invalidation waits only
until `QueueSubmit` succeeds. The reservation is then released; the submitted
command may complete normally and its storage remains owned by the existing
frame-fence/timeline retirement path. Logical invalidation never destroys
resources that submitted GPU work may still reference. The presenter does not
call back into the bridge while holding the reservation, avoiding an inverse
bridge-lock dependency. Multiple host draws in one shared guest command batch
share reference-counted ownership of that one generation reservation, which is
released only after the batch submission.

This is a synchronization guarantee, not a claim that the presenter and
bridge are globally serialized: work prepared before the reservation may be
rejected, while work whose reservation precedes invalidation may be submitted
and later retired. Target observation showed that the stale black host output
was replaced by a grey transition, leaving a separate output owner unresolved.

#### After correction: target observation

The attended pilot and comparable confirmations observed the corrected
boundary: generation 1 completed once, the presenter invalidated it, and later
guest draws did not select or upload generation 1. The direct visual result was
consistent across the runs: the former solid-black interval became grey, while
the slow animation audio continued. The later startup route remained usable
through the main menu. This validates stale host-generation selection as one
cause of the old black output, but it does not identify the producer of the
remaining grey transition or establish a timing correction.

The intermittent flashing reports are not collapsed into this finding. They
may be a different selection or transition race between the stale host input
and ordinary guest output. The present evidence proves the stale-selection
condition and the solid-black outcome, but does not prove that it explains every
flashing run.

### Audio and movie-clock attribution

This section records the 2026-08-03 attribution pass. It is an investigation
finding only: no compatibility correction was implemented.

#### Direct observations

The exact stream ownership is now established. On both diagnostic runs the
streams were:

| Stream | Owner/source | Input and queue | Device observation | Clock reports |
| ---: | --- | --- | --- | --- |
| 1 | `audio-out2-primary` / `guest-audio-out2-primary` | 48 kHz, 2-channel S16; 682.667 ms cap | SDL device 25, 48 kHz 2-channel F32, 480-frame buffer, running | Accepted reports; this stream advances the global clock |
| 2 | `movie` / `ps_studios_logo.bk2`, movie instance 1, generation 1 | 48 kHz, 2-channel S16; 170.667 ms cap | SDL device 29, 48 kHz 2-channel F32, 480-frame buffer, running | 0 accepted, 213 rejected in each run |
| 3 | `audio-out` / `port-1` | 48 kHz, 8-channel S16; 60 ms cap | SDL device 33, 48 kHz 2-channel F32, 480-frame buffer, running | Rejected because its local position lagged stream 1 |

The three SDL device IDs are distinct logical device associations with the same
reported physical device name. Each stream observed one initial running-state
transition, then remained running. No queue query failure, device-unavailable
state, pause, frequency-ratio change, or SDL submission failure was recorded.
The push streams reported no application callback: callback availability was
false and requested/supplied callback frames remained zero.

The movie path is:

```text
Bink packet demux/decode
  → FfmpegVideoDecoder.SubmitAudioFrame
  → swr_convert to 48 kHz stereo S16
  → SdlHostAudio.AudioStream.Submit
  → SDL_PutAudioStreamData (SDL input queue)
  → SDL device conversion to 48 kHz stereo F32
  → device consumption
```

The decoder-open event reported source `AV_SAMPLE_FMT_FLTP`, 48 kHz stereo,
output `AV_SAMPLE_FMT_S16`, 48 kHz stereo, and an FFmpeg declared audio
duration of 0 s. The independent source metadata is 8.500 s; the zero FFmpeg
duration did not prevent draining the measured 8.520 s of samples.

`SdlHostAudio.Submit` is also the only caller of `GuestAudioClock.Report`.
It reports accepted submitted samples minus the queue depth; the movie stream
reports its own local position, but the shared furthest-value clock rejects it
because the guest AudioOut2 stream is already farther ahead. At movie start the
global value was 26.506666 s in diagnostic run 1 and 28.286 s in run 2. The
movie stream ended at 8.47/8.48 local seconds while its reports remained
0 accepted/213 rejected. Stream 1 was the accepted clock source throughout the
movie interval.

The first starvation boundary is in the host movie decoder, before SDL
submission. In diagnostic run 1 the movie decoder entered `frame-buffer-wait`
at 45.278 s with 100 ms queued and resumed `video-decode` at 45.975 s with an
empty queue. In run 2 it entered the same wait at 44.503 s with 130 ms queued
and resumed at 45.018 s empty. `MediaFramePlayback.DecodeLoop` cannot call
`FfmpegVideoDecoder.TryDecodeNextFrame` while all five frame buffers are held;
the decoder therefore cannot read the next interleaved audio packets during
that wait. Later short waits repeat after the queue is empty. The measured
boundary is the frame-buffer wait; the component that delays releasing a frame
buffer is not yet isolated.

#### Calculated values

The final movie totals reconciled identically in both diagnostic runs:

| Quantity | Value | Calculation/meaning |
| --- | ---: | --- |
| Source audio frames decoded | 408,960 | FFmpeg audio frames, source 48 kHz |
| Converted output frames | 408,960 | `swr_convert` output; 1.0000 ratio |
| Submitted output frames | 408,960 | 1,635,840 bytes at 4 bytes/frame |
| Failed/unsubmitted frames | 0 | No SDL `PutAudioStreamData` failure and no converted output left unsubmitted |
| Consumed frames at final snapshot | 408,960 | Queue and converted-available bytes both zero at disposal |
| Missing output frames | 0 | Converted output equals accepted submission |
| Source audio time | 8.520000 s | `408,960 / 48,000` |
| Last source timestamp | 8.48 s | FFmpeg audio-frame PTS observed |

The source asset is 8.500 s at 30 fps; the audio packet stream contributes
8.520 s of 48 kHz samples. The movie completed once at frame 254 after
13.896 s and 14.124 s of movie wall playback in the two diagnostic runs. The
audio data was not stretched by a sample-count or resampling error: all source
samples were converted, submitted, and consumed, but delivery was separated
by host-time gaps. The final stream snapshots showed zero queued input and zero
converted-available bytes, so the end-of-stream reconciliation is exact.

The separate guest stream was the slow clock frontier. In run 2, the final
AudioOut2 primary snapshot had a 10.667 ms queue, 2,912,000 submitted frames,
2,911,488 consumed frames, 2,121 underruns, and 22.573 s accumulated empty
time. The movie stream had 11 underruns and 12.650 s accumulated empty time;
the classic AudioOut stream had a 58 ms queue, one underrun, and 0.19 s of
accumulated empty time. Queue caps were never exceeded and no stream recorded
an over-target enqueue.

#### Source-backed behavior

The interpretation uses the current official SDL3 and .NET contracts recorded
in [`docs/SOURCES.md`](SOURCES.md): SDL reports stream queued bytes and
converted availability separately, exposes stream/device formats and device
identity, and a null callback selects push-mode delivery; SDL's frequency ratio
of 1.0 is normal-rate conversion. `Stopwatch.GetTimestamp` and
`Stopwatch.GetElapsedTime` provide the host monotonic correlation used by the
events. These API contracts do not identify the title's intended guest/movie
clock owner.

#### Inferences

- The movie stream starves because Bink audio production is bursty and coupled
  to the video decoder's five-buffer availability. The first measured cause is
  the decoder's `frame-buffer-wait`, not slow sample conversion.
- The slow movie presentation is causally explained by two measured facts:
  movie frame selection follows the shared `GuestAudioClock`, and the accepted
  clock source is the underrunning AudioOut2 primary stream. The movie stream's
  own audio does not drive that clock.
- The current implementation does not establish that the movie's host audio
  and the guest AudioOut2 stream are intended to share one timeline. Therefore
  changing the global clock owner, making it per-movie, or moving audio packet
  pumping off the video decoder would be a semantic correction, not an
  instrumentation-only change.
- The historical 683 ms queue attribution to the movie stream was incorrect.
  That cap belongs to AudioOut2 primary; the movie cap is 170.667 ms.

#### No-default-device warnings

The two diagnostic runs had no no-default-device warning and still reproduced
the movie's empty queue and stretched completion. In the earlier warning-bearing
run `20260801T061920689Z-c129d0f-trial-01`, every warning was explicitly
`AudioOut2 primary backend unavailable: ... No default audio device available`.
The movie stream was not the warning owner. The present evidence therefore
rules out the warnings as the cause of this movie underrun; it does not rule
out a separate AudioOut2 fallback effect in warning-bearing runs.

#### Unresolved questions and falsifiers

The following remain open: which guest/render phase holds the fifth movie frame
buffer, whether the intended startup contract couples movie video to the movie
audio or to guest AudioOut2, and whether SDL's input-queue/converted-available
boundary needs a device-level consumption probe for sub-interval accounting.

The attribution would be falsified if a repeat run shows movie stream clock
reports accepted while AudioOut2 reports are rejected, if movie audio totals
contain failed/unsubmitted samples or a non-1.0 ratio, if the movie queue stays
non-empty across the measured frame-buffer waits, if device state transitions
precede the gaps, or if decoupling frame-buffer availability in a synthetic
authored decoder leaves the same starvation pattern. A correction proposal also
requires a proof of the intended guest/movie timeline and ownership.

#### Narrowest correction boundary

No implementation-ready compatibility correction exists from this pass. The
narrowest measured boundary is the host `MediaFramePlayback` frame-buffer wait
that prevents `FfmpegVideoDecoder` from pumping interleaved audio packets. The
smallest plausible future experiment is an authored synthetic decoder that
continues audio packet pumping while the video frame pool is exhausted; it must
preserve the observed frame ownership and prove the guest/movie clock contract
before any target behavior is changed. Wall-clock playback remains diagnostic
only.

#### Runs, hashes, safety, and instrumentation overhead

| Run | Mode/result | Movie checkpoint |
| --- | --- | --- |
| `20260802T220619684Z-a7ee8a4-trial-01` | Clean control, diagnostics disabled; physical-headroom stop at 204.420 s | `ps_studios_logo.bk2` attached and completed at 11.13 s/frame 254; `attract_movie.bk2` attached; no nickname checkpoint inferred |
| `20260802T221008090Z-a7ee8a4-trial-01` | Diagnostic; physical-headroom stop at 70.781 s; no cleanup failures | Logo attached at 44.454 s, started at 45.800 s, completed at 13.896 s/frame 254 |
| `20260802T221703483Z-a7ee8a4-trial-01` | Diagnostic repeat; physical-headroom stop at 93.151 s; no cleanup failures | Logo attached at 43.707 s, started at 44.936 s, completed at 14.124 s/frame 254 |

The Release executable SHA-256 was
`FAA5F39B1A1395873DE5577770671421FF0A955DB0CADD716A7EC4C7280DAF47`.
The target `eboot.bin` SHA-256 was
`22ED8843917CB16438B7B780998E408321F5CEBE79DD10F388AE59CFCA588306`.
The fixed page file remained `C:\pagefile.sys`, 32,768 MB initial and maximum;
the runner's physical-headroom, commit-headroom, process-tree cleanup, and
sampling policies were unchanged. All three manifests recorded empty cleanup
failures, and no SharpEmu process remained after each run.

With diagnostics disabled, the audio path performs no diagnostic payload
construction, formatting, diagnostic locking, or per-frame accounting. Enabled
runs emitted 411 and 408 bounded audio events respectively and produced 5.1 MB
and 6.5 MB JSONL artifacts, alongside the runner's other memory events. The
target completion shift relative to the clean control is a sensitivity signal,
not an isolated instrumentation-overhead measurement; the broad memory
diagnostic stream and physical-headroom stop prevent that claim.

Focused diagnostics tests passed 8/8. The Fast lane passed all six runner and
memory regressions and all 841 solution tests. `git diff --check` passed. The
shader lane was not run because this investigation changes no shader or GPU
semantics.

### Later progression and safety

The movie behavior is independent of the already-proven route through the main
menu, offline prompt, body-type screen, and name/class/starting-gift
customization. The user-controlled run reached the next attract cinematic and
was closed by the user; that is not a runner safety termination.

Other controlled runs terminated at the configured physical-headroom or
wall-time boundaries, or by normal process exit; cleanup succeeded in each
case. No visual checkpoint is inferred from any safety termination.

## Implemented correction and remaining frontier

The first semantic correction is now owned by the host movie/presenter lifetime
boundary: once a movie generation completes or is closed, its host frame is no
longer eligible for a guest Bink draw. The generation/active handoff keeps the
guest surface available for the ordinary guest path during the transition.

Do not switch the movie clock to wall time as the timing correction. This change
does not alter `GuestAudioClock`, `MediaFramePlayback`, or frame pacing.

The timing correction is a separate boundary. Establish the guest-observable
audio-clock contract with a synthetic audio/movie experiment before changing
`CurrentPlaybackSecondsLocked`. The expected result is source-duration timing
without losing the ordered guest audio relationship; a wall-clock improvement
alone is insufficient.

Expected visible improvement from the first change: the completed black host
frame cannot persist as a selectable movie input during the handoff. Whether the
screen becomes guest-owned, remains black for another reason, or still flashes
requires direct target observation. Expected timing change: none by itself;
timing should change only after the audio-clock contract is corrected.

Synthetic regression coverage should use authored decoders and fake guest
clock/presenter inputs to verify:

1. monotonic target/current frame selection with late-frame retirement;
2. audio-clock and wall-clock selection as separate policies;
3. completion, guest close, and replacement invalidating host selection for
   the completed generation, with shutdown clearing presenter selection;
4. next-generation attachment, including the same path, not exposing the
   previous generation’s frame or binding state;
5. a prepared host draw rejected after invalidation wins the final submission
   boundary, with descriptor/resource fallback to ordinary guest texture
   resolution;
6. a reservation acquired before invalidation releasing only after successful
   submission, while in-flight Vulkan storage remains fence-owned;
7. same-path replacement retaining distinct generation identity and bounded
   late-rejection diagnostics, including the disabled diagnostics path.

Target validation of the earlier correction used the default native-Bink run
under the same controlled safety policy, correlated generation-end,
presenter-invalidation, upload, and guest-draw-selection events, and included
direct visual observation. That evidence held the logical stale-selection
invariant, and the direct visual result was grey rather than black at the
handoff. The final submission-boundary race is validated synthetically because
an attended target run does not deterministically place invalidation between
resource preparation and command submission. Timing variance requires three
comparable trials for a timing claim; this correction did not alter timing.

The correction is incomplete if a completed generation remains selected by a
later guest draw, if a new generation inherits the previous frame or binding
identity, or if the ordinary guest texture path is not available after
invalidation. The earlier diagnosis remains separate if the stale generation
is excluded but the screen remains black or flashing.

Raw logs, manifests, source samples, movie fingerprints, and target paths remain
outside Git under the ignored local artifact root.
