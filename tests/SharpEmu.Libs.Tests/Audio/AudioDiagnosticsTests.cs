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
        var accounting = new AudioSampleAccounting(bytesPerOutputFrame: 4);

        accounting.RecordDecodedAndConverted(sourceFrames: 480, outputFrames: 480);
        accounting.RecordSubmission(bytes: 480 * 4, accepted: true);
        accounting.RecordDecodedAndConverted(sourceFrames: 480, outputFrames: 480);
        accounting.RecordSubmission(bytes: 480 * 4, accepted: true);

        var snapshot = accounting.Snapshot(queuedOutputBytes: 480 * 4);

        Assert.Equal(960, snapshot.DecodedSourceFrames);
        Assert.Equal(960, snapshot.ConvertedOutputFrames);
        Assert.Equal(960, snapshot.SubmittedOutputFrames);
        Assert.Equal(480, snapshot.QueuedOutputFrames);
        Assert.Equal(480, snapshot.ConsumedOutputFrames);
        Assert.Equal(0, snapshot.FailedSubmissionFrames);
        Assert.Equal(0, snapshot.MissingOutputFrames);
        Assert.Equal(960, snapshot.ResamplerInputFrames);
        Assert.Equal(960, snapshot.ResamplerOutputFrames);
    }

    [Fact]
    public void PartialAndFailedDeliveryPreservesByteRemainders()
    {
        var accounting = new AudioSampleAccounting(bytesPerOutputFrame: 4);
        accounting.RecordDecodedAndConverted(sourceFrames: 3, outputFrames: 3);
        accounting.RecordSubmission(bytes: 6, accepted: true);
        accounting.RecordSubmission(bytes: 6, accepted: false);

        var snapshot = accounting.Snapshot(queuedOutputBytes: 2);

        Assert.Equal(12, snapshot.ConvertedOutputBytes);
        Assert.Equal(6, snapshot.SubmittedOutputBytes);
        Assert.Equal(6, snapshot.FailedSubmissionBytes);
        Assert.Equal(1, snapshot.SubmittedOutputFrames);
        Assert.Equal(1, snapshot.FailedSubmissionFrames);
        Assert.Equal(2, snapshot.QueuedOutputBytes);
        Assert.Equal(4, snapshot.ConsumedOutputBytes);
        Assert.Equal(6, snapshot.MissingOutputBytes);
        Assert.Equal(1, snapshot.MissingOutputFrames);
    }

    [Fact]
    public void EmptyDeliveryDoesNotInventSamples()
    {
        var accounting = new AudioSampleAccounting(bytesPerOutputFrame: 4);

        accounting.RecordSubmission(bytes: 0, accepted: true);

        var snapshot = accounting.Snapshot(queuedOutputBytes: 0);

        Assert.Equal(0, snapshot.SubmittedOutputBytes);
        Assert.Equal(0, snapshot.ConsumedOutputBytes);
        Assert.Equal(0, snapshot.MissingOutputBytes);
    }

    [Fact]
    public void ResamplingTotalsExposeTheMeasuredRatio()
    {
        var accounting = new AudioSampleAccounting(bytesPerOutputFrame: 4);
        accounting.RecordDecodedAndConverted(sourceFrames: 441, outputFrames: 480);

        var snapshot = accounting.Snapshot(queuedOutputBytes: -1);

        Assert.Equal(441, snapshot.ResamplerInputFrames);
        Assert.Equal(480, snapshot.ResamplerOutputFrames);
        Assert.Equal(480d / 441d, (double)snapshot.ResamplerOutputFrames /
            snapshot.ResamplerInputFrames, precision: 12);
        Assert.Equal(-1, snapshot.ConsumedOutputFrames);
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
        var accounting = new AudioSampleAccounting(bytesPerOutputFrame: 4);
        accounting.RecordDecodedAndConverted(48, 48);
        accounting.RecordSubmission(48 * 4, accepted: true);

        accounting.Reset();
        var secondSession = accounting.Snapshot(queuedOutputBytes: 0);

        Assert.Equal(0, secondSession.DecodedSourceFrames);
        Assert.Equal(0, secondSession.SubmittedOutputFrames);
        Assert.Equal(0, secondSession.ConsumedOutputFrames);
    }

    [Fact]
    public void DiagnosticsDisabledPathDoesNotReserveAnEvent()
    {
        var budget = new AudioDiagnosticEventBudget(maximum: 1);

        Assert.True(budget.TryReserve());
        Assert.False(budget.TryReserve());
        Assert.False(budget.HasCapacity);
    }
}
