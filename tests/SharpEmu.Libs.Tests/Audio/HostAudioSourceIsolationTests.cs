// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE.Host;
using SharpEmu.Libs.Audio;
using SharpEmu.Libs.Media;
using Xunit;

namespace SharpEmu.Libs.Tests.Audio;

public sealed class HostAudioSourceIsolationTests
{
    [Fact]
    public void SelectionUsesOnlyStableOwnerIdentities()
    {
        var selection = HostAudioSourceIsolationSelection.Parse(
            "movie,audio-out2");

        Assert.True(selection.IsSelected(HostAudioSourceOwner.Movie));
        Assert.True(selection.IsSelected(HostAudioSourceOwner.AudioOut2));
        Assert.False(selection.IsSelected(HostAudioSourceOwner.AudioOut));

        var unchanged = new byte[] { 1, 2, 3, 4 };
        selection.SilenceIfSelected(
            HostAudioSourceOwner.AudioOut,
            unchanged);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, unchanged);
    }

    [Fact]
    public void SelectedMovieSilencePreservesSubmissionSizeAccountingAndQueue()
    {
        var selection = HostAudioSourceIsolationSelection.Parse("movie");
        using var stream = new RecordingHostAudioStream();
        using var boundary = new MovieAudioSubmissionBoundary(
            stream,
            outputBytesPerFrame: 4,
            outputSampleRate: 48_000,
            sourceIsolation: selection);
        var pcm = new byte[] { 0x01, 0x20, 0x7F, 0xFF, 0x40, 0x80, 0xAA, 0x55 };

        Assert.Equal(
            MovieAudioSubmissionResult.Accepted,
            boundary.Submit(
                pcm,
                outputFrames: 2,
                CancellationToken.None,
                out var progress));

        Assert.True(stream.LastSubmissionWasSilent);
        Assert.Equal(pcm.Length, stream.LastSubmissionLength);
        Assert.Equal(1, stream.SubmissionCount);
        Assert.Equal(pcm.Length, stream.QueuedPcmBytes);
        Assert.Equal(2, progress.SubmittedFrames);
        Assert.Equal(2, boundary.LastProgress.SubmittedFrames);
    }

    [Fact]
    public void SelectedOwnersSilenceOnlyTheirBuffersAndKeepAllLengths()
    {
        var selection = HostAudioSourceIsolationSelection.Parse(
            "movie,audio-out2,audio-out");
        foreach (var owner in Enum.GetValues<HostAudioSourceOwner>())
        {
            var pcm = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            var length = pcm.Length;

            selection.SilenceIfSelected(owner, pcm);

            Assert.Equal(length, pcm.Length);
            Assert.All(pcm, sample => Assert.Equal(0, sample));
        }
    }

    [Fact]
    public void EmptySelectionDoesNoSampleMutation()
    {
        var selection = HostAudioSourceIsolationSelection.Parse(null);
        var pcm = new byte[] { 1, 2, 3, 4 };

        selection.SilenceIfSelected(HostAudioSourceOwner.Movie, pcm);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, pcm);
    }

    [Fact]
    public void UnknownOwnerIsRejectedInsteadOfSilentlySelectingAStream()
    {
        var exception = Assert.Throws<ArgumentException>(
            () => HostAudioSourceIsolationSelection.Parse("stream-1"));

        Assert.Contains("movie", exception.Message, StringComparison.Ordinal);
        Assert.Contains("audio-out2", exception.Message, StringComparison.Ordinal);
        Assert.Contains("audio-out", exception.Message, StringComparison.Ordinal);
    }

    private sealed class RecordingHostAudioStream :
        IHostAudioStream,
        IHostAudioStreamControl
    {
        public int QueuedPcmBytes { get; private set; }

        public HostAudioProgressSource ProgressSource =>
            HostAudioProgressSource.ExactQueueDepth;

        public int LastSubmissionLength { get; private set; }

        public bool LastSubmissionWasSilent { get; private set; }

        public int SubmissionCount { get; private set; }

        public bool Submit(ReadOnlySpan<byte> stereoPcm16) =>
            Submit(stereoPcm16, CancellationToken.None);

        public bool Submit(
            ReadOnlySpan<byte> stereoPcm16,
            CancellationToken cancellationToken)
        {
            LastSubmissionLength = stereoPcm16.Length;
            LastSubmissionWasSilent = stereoPcm16.IsEmpty ||
                stereoPcm16.IndexOfAnyExcept((byte)0) < 0;
            QueuedPcmBytes = checked(QueuedPcmBytes + stereoPcm16.Length);
            SubmissionCount++;
            return true;
        }

        public void SetPaused(bool paused)
        {
        }

        public void SetGuestClockReporting(bool enabled)
        {
        }

        public void SetStrictQueueBound(bool enabled)
        {
        }

        public void Dispose()
        {
        }
    }
}
