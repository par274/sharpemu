// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE.Host;
using Xunit;

namespace SharpEmu.Libs.Tests.Audio;

public sealed class AudioDiagnosticsTests
{
    [Fact]
    public void Signed48KHzStereoDeliveryReconcilesExactly()
    {
        var accounting = new AudioSampleAccounting(bytesPerStreamFrame: 4);

        accounting.RecordDecodedAndConverted(sourceFrames: 480, outputFrames: 480);
        accounting.RecordSubmission(bytes: 480 * 4, accepted: true);
        accounting.RecordDecodedAndConverted(sourceFrames: 480, outputFrames: 480);
        accounting.RecordSubmission(bytes: 480 * 4, accepted: true);

        var snapshot = accounting.Snapshot(queuedInputBytes: 480 * 4);

        Assert.Equal(960, snapshot.DecodedSourceFrames);
        Assert.Equal(960, snapshot.ConvertedOutputFrames);
        Assert.Equal(960, snapshot.SubmittedInputFrames);
        Assert.Equal(480, snapshot.QueuedInputFrames);
        Assert.Equal(480, snapshot.DequeuedInputFrames);
        Assert.Equal(0, snapshot.FailedSubmissionFrames);
        Assert.Equal(0, snapshot.MissingOutputFrames);
        Assert.Equal(960, snapshot.ResamplerInputFrames);
        Assert.Equal(960, snapshot.ResamplerOutputFrames);
    }

    [Fact]
    public void Full48KHzStereoMovieTotalUsesExactInputFrameCount()
    {
        const long frames = 408_960;
        const int bytesPerInputFrame = 2 * sizeof(short);
        var accounting = new AudioSampleAccounting(bytesPerStreamFrame: bytesPerInputFrame);

        accounting.RecordDecodedAndConverted(sourceFrames: frames, outputFrames: frames);
        accounting.RecordSubmission(
            bytes: checked((int)(frames * bytesPerInputFrame)),
            accepted: true);

        var snapshot = accounting.Snapshot(queuedInputBytes: 0);

        Assert.Equal(frames, snapshot.DecodedSourceFrames);
        Assert.Equal(frames, snapshot.ConvertedOutputFrames);
        Assert.Equal(frames, snapshot.SubmittedInputFrames);
        Assert.Equal(frames, snapshot.DequeuedInputFrames);
        Assert.Equal(frames * bytesPerInputFrame, snapshot.SubmittedInputBytes);
        Assert.Equal(0, snapshot.MissingOutputFrames);
    }

    [Fact]
    public void PartialAndFailedDeliveryPreservesByteRemainders()
    {
        var accounting = new AudioSampleAccounting(bytesPerStreamFrame: 4);
        accounting.RecordDecodedAndConverted(sourceFrames: 3, outputFrames: 3);
        accounting.RecordSubmission(bytes: 6, accepted: true);
        accounting.RecordSubmission(bytes: 6, accepted: false);

        var snapshot = accounting.Snapshot(queuedInputBytes: 2);

        Assert.Equal(12, snapshot.ConvertedOutputBytes);
        Assert.Equal(6, snapshot.SubmittedInputBytes);
        Assert.Equal(6, snapshot.FailedSubmissionBytes);
        Assert.Equal(1, snapshot.SubmittedInputFrames);
        Assert.Equal(1, snapshot.FailedSubmissionFrames);
        Assert.Equal(2, snapshot.QueuedInputBytes);
        Assert.Equal(4, snapshot.DequeuedInputBytes);
        Assert.Equal(6, snapshot.MissingOutputBytes);
        Assert.Equal(1, snapshot.MissingOutputFrames);
    }

    [Fact]
    public void EmptyDeliveryDoesNotInventSamples()
    {
        var accounting = new AudioSampleAccounting(bytesPerStreamFrame: 4);

        accounting.RecordSubmission(bytes: 0, accepted: true);

        var snapshot = accounting.Snapshot(queuedInputBytes: 0);

        Assert.Equal(0, snapshot.SubmittedInputBytes);
        Assert.Equal(0, snapshot.DequeuedInputBytes);
        Assert.Equal(0, snapshot.MissingOutputBytes);
    }

    [Fact]
    public void ResamplingTotalsExposeTheMeasuredRatio()
    {
        var accounting = new AudioSampleAccounting(bytesPerStreamFrame: 4);
        accounting.RecordDecodedAndConverted(sourceFrames: 441, outputFrames: 480);

        var snapshot = accounting.Snapshot(queuedInputBytes: -1);

        Assert.Equal(441, snapshot.ResamplerInputFrames);
        Assert.Equal(480, snapshot.ResamplerOutputFrames);
        Assert.Equal(480d / 441d, (double)snapshot.ResamplerOutputFrames /
            snapshot.ResamplerInputFrames, precision: 12);
        Assert.Equal(-1, snapshot.DequeuedInputFrames);
    }

    [Fact]
    public void DeviceUnavailablePushModeHasNoApplicationCallbackFrames()
    {
        var snapshot = new HostAudioStreamDiagnosticSnapshot
        {
            DeviceState = "unavailable",
            CallbackAvailable = false,
            CallbackRequestedFrames = 0,
            CallbackSuppliedFrames = 0,
        };

        Assert.Equal("unavailable", snapshot.DeviceState);
        Assert.False(snapshot.CallbackAvailable);
        Assert.Equal(0, snapshot.CallbackRequestedFrames);
        Assert.Equal(0, snapshot.CallbackSuppliedFrames);
    }

    [Fact]
    public void CounterDeltasHandleResetAndModularRollover()
    {
        Assert.Equal(7, AudioSampleAccounting.CounterDelta(10, 17));
        Assert.Equal(3, AudioSampleAccounting.CounterDelta(10, 3));
        Assert.Equal(
            4UL,
            AudioSampleAccounting.CounterDelta(
                previous: 0xFFFF_FFFF_FFFF_FFFEuL,
                current: 2,
                counterMaximum: ulong.MaxValue));
    }

    [Fact]
    public void ResetAllowsARepeatedSessionToStartAtZero()
    {
        var accounting = new AudioSampleAccounting(bytesPerStreamFrame: 4);
        accounting.RecordDecodedAndConverted(48, 48);
        accounting.RecordSubmission(48 * 4, accepted: true);

        accounting.Reset();
        var secondSession = accounting.Snapshot(queuedInputBytes: 0);

        Assert.Equal(0, secondSession.DecodedSourceFrames);
        Assert.Equal(0, secondSession.SubmittedInputFrames);
        Assert.Equal(0, secondSession.DequeuedInputFrames);
    }

    [Fact]
    public void DiagnosticsDisabledPathDoesNotReserveAnEvent()
    {
        var budget = new AudioDiagnosticEventBudget(maximum: 1);

        Assert.True(budget.TryReserve());
        Assert.False(budget.TryReserve());
        Assert.False(budget.HasCapacity);
    }

    [Fact]
    public void TraceWindowDoesNotResetCumulativeEmptyQueueObservations()
    {
        var counters = new AudioQueueObservationCounters();

        counters.RecordDiagnosticObservation(queuedInputBytes: 0);
        counters.RecordTraceSubmission(queuedInputBytes: 0);
        counters.RecordDiagnosticObservation(queuedInputBytes: 0);
        counters.RecordDiagnosticObservation(queuedInputBytes: 128);

        Assert.Equal(2, counters.DiagnosticEmptyQueueObservations);
        Assert.Equal(1, counters.TakeTraceWindowEmptyQueueObservations());
        Assert.Equal(2, counters.DiagnosticEmptyQueueObservations);
        Assert.Equal(0, counters.TakeTraceWindowEmptyQueueObservations());

        counters.RecordDiagnosticObservation(queuedInputBytes: 0);

        Assert.Equal(3, counters.DiagnosticEmptyQueueObservations);
    }
}
