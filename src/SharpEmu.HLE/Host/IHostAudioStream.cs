// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE.Host;

/// <summary>
/// One open host audio output stream. Submissions are interleaved stereo 16-bit PCM at
/// the sample rate the stream was opened with.
/// </summary>
public interface IHostAudioStream : IDisposable
{
    /// <summary>
    /// Submits one buffer. May block briefly while the device drains its queue (this is
    /// what paces the guest's audio loop); returns false when the stream cannot accept
    /// audio, in which case the caller paces the guest itself.
    /// </summary>
    bool Submit(ReadOnlySpan<byte> stereoPcm16);

    /// <summary>
    /// Audio already handed to the device and not yet played, in milliseconds —
    /// the cushion protecting playback from a late submission. Zero means the
    /// device has run dry and is emitting silence.
    ///
    /// Callers that pace the guest against an emulated hardware queue need this:
    /// pacing purely on wall clock releases exactly one buffer per buffer-period
    /// and so keeps the cushion at zero, which turns any scheduling jitter into
    /// an audible dropout. Returns -1 when the backend cannot report a depth, in
    /// which case callers must fall back to their own pacing.
    /// </summary>
    int QueuedMilliseconds => -1;

    /// <summary>
    /// Exact PCM bytes already handed to the device and not yet played, when
    /// the backend can report them. Zero means the device queue is drained.
    /// </summary>
    int QueuedPcmBytes => -1;

    /// <summary>
    /// Describes how a media owner may interpret progress from this stream.
    /// Backends with an exact queue depth inherit that capability; other
    /// backends must explicitly expose a calibrated submission-paced or
    /// unavailable state instead of making the movie fail after one buffer.
    /// </summary>
    HostAudioProgressSource ProgressSource => QueuedPcmBytes >= 0
        ? HostAudioProgressSource.ExactQueueDepth
        : HostAudioProgressSource.Unavailable;
}

public enum HostAudioProgressSource
{
    ExactQueueDepth,
    CalibratedSubmissionPaced,
    Unavailable,
}

/// <summary>
/// Optional controls used by host-owned media streams. Guest audio streams
/// continue to use <see cref="IHostAudioStream.Submit(ReadOnlySpan{byte})"/>
/// and do not need to implement this extension.
/// </summary>
public interface IHostAudioStreamControl
{
    bool Submit(ReadOnlySpan<byte> stereoPcm16, CancellationToken cancellationToken);

    /// <summary>
    /// Whether SetPaused changes the device state. A false value is an
    /// explicit unsupported capability, not an implicit pause promise.
    /// </summary>
    bool SupportsPause => false;

    HostAudioProgressSource ProgressSource => HostAudioProgressSource.Unavailable;

    void SetPaused(bool paused);

    void SetGuestClockReporting(bool enabled);

    /// <summary>
    /// Enables rejection instead of over-target admission when a bounded
    /// host-owned stream cannot accept the next submission.
    /// </summary>
    void SetStrictQueueBound(bool enabled);
}
