<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Startup movie temporal boundary

Status: diagnostic finding. No compatibility correction is included here.

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

After host completion, `VulkanVideoPresenter` deliberately keeps
`_hostMovieFramePixels` and its serial while the next movie is not ready. The
diagnostic shows that completed host data remains eligible for selection even
though `HostMovieBridge.IsHostPlaybackActive` is false. The local source’s final
PlayStation Studios frame is black, and the direct run showed a solid-black
interval at this boundary. The narrowest proven black-output boundary is thus
the completed host frame remaining selectable during the guest/host handoff.

The intermittent flashing reports are not collapsed into this finding. They
may be a different selection or transition race between the stale host input
and ordinary guest output. The present evidence proves the stale-selection
condition and the solid-black outcome, but does not prove that it explains every
flashing run.

### Audio behavior

The global `GuestAudioClock` was running and its selected progression was
substantially slower than wall time during the host movie samples. A focused
queue-log pass observed repeated underruns on multiple streams, including the
identified movie stream. That movie stream (the stream with the 683 ms queue
cap) commonly reported 2–5 ms average queued depth, frequent zero-depth
observations, and zero submission drops.

`GuestAudioClock` stores the furthest reported progress across audio streams
without identifying which stream supplied that value. The exact stream or
combination of streams advancing the global clock therefore remains unresolved.
The proven boundary is narrower: `MediaFramePlayback` selects the slow global
clock, and the wall-clock A/B completed the movies near their source durations
while guest audio time lagged. That proves the selected slow global clock
causally stretches host video; it does not prove that the movie stream alone
owns the clock or that wall time is the correct guest-observable contract.

The queue evidence supports ordered audio segments separated by real silent
gaps, rather than proving repeated samples or skipped samples. No sample-level
content claim is made. The wall-clock comparison remains a diagnostic control,
not a correction.

### Later progression and safety

The movie behavior is independent of the already-proven route through the main
menu, offline prompt, body-type screen, and name/class/starting-gift
customization. The user-controlled run reached the next attract cinematic and
was closed by the user; that is not a runner safety termination.

Other controlled runs terminated at the configured physical-headroom or
wall-time boundaries, or by normal process exit; cleanup succeeded in each
case. No visual checkpoint is inferred from any safety termination.

## Implementation-ready next change

Do not switch the movie clock to wall time as the compatibility correction.
The first semantic change should be owned by the host movie/presenter lifetime
boundary: once a movie instance completes or is closed, its host frame must no
longer be eligible for a guest Bink draw unless that same instance is still the
guest-observable active surface. A generation/active handoff or equivalent
invalidation should make this invariant explicit. The guest surface must remain
available for the ordinary guest path during the transition.

The timing correction is a separate boundary. Establish the guest-observable
audio-clock contract with a synthetic audio/movie experiment before changing
`CurrentPlaybackSecondsLocked`. The expected result is source-duration timing
without losing the ordered guest audio relationship; a wall-clock improvement
alone is insufficient.

Expected visible improvement from the first change: the completed black host
frame cannot persist as a selectable movie input during the handoff. Expected
timing change: none by itself; timing should change only after the audio-clock
contract is corrected.

Synthetic regression coverage should use authored decoders and fake guest
clock/presenter inputs to verify:

1. monotonic target/current frame selection with late-frame retirement;
2. audio-clock and wall-clock selection as separate policies;
3. completion invalidating host selection for the completed instance;
4. next-instance attachment not exposing the previous instance’s frame.

Target validation should repeat the default native-Bink run under the same
controlled safety policy, correlate the host instance, active-generation,
upload, and guest-draw-selection events, and use direct visual observation.
Timing variance requires three comparable trials; no blind three-run matrix is
needed to re-prove the current boundary.

The diagnosis would be falsified if a completed host instance remains excluded
from all guest movie selection, if default playback reaches source duration
despite the measured audio-clock lag, or if a second active attachment/start of
the same source is observed.

Raw logs, manifests, source samples, movie fingerprints, and target paths remain
outside Git under the ignored local artifact root.
