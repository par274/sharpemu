// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Xunit;

namespace SharpEmu.Libs.Tests.Media;

/// <summary>
/// Small arithmetic guard for the rejected compressed-packet candidate. It is
/// evidence-gate coverage, not a production queue: the selected movie pump
/// retains zero compressed packets.
/// </summary>
public sealed class MoviePacketCapacityEvidenceTests
{
    [Fact]
    public void PacketAtByteCapIsRetainedAndCountsEveryByte()
    {
        var capacity = new PacketCapacity(count: 2, bytes: 8);

        Assert.True(capacity.TryRetain(8));
        Assert.Equal(1, capacity.Count);
        Assert.Equal(8, capacity.Bytes);
        Assert.False(capacity.TryRetain(1));
    }

    [Fact]
    public void PacketLargerThanByteCapIsRejectedWithoutHiddenStorage()
    {
        var capacity = new PacketCapacity(count: 2, bytes: 8);

        Assert.False(capacity.TryRetain(9));
        Assert.Equal(0, capacity.Count);
        Assert.Equal(0, capacity.Bytes);
    }

    [Fact]
    public void CountAndByteCapsAreIndependentHardBounds()
    {
        var countLimited = new PacketCapacity(count: 1, bytes: 100);
        Assert.True(countLimited.TryRetain(1));
        Assert.False(countLimited.TryRetain(1));

        var byteLimited = new PacketCapacity(count: 100, bytes: 2);
        Assert.True(byteLimited.TryRetain(1));
        Assert.False(byteLimited.TryRetain(2));
        Assert.Equal(1, byteLimited.Count);
        Assert.Equal(1, byteLimited.Bytes);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(10)]
    public void SlowConsumerBacklogTrendsTowardTheAsset(int consumerFramesPerSecond)
    {
        var packets = Enumerable.Range(0, 3_600)
            .Select(index => new TimedVideoPacket(index / 30.0, 200_000))
            .ToArray();
        var simulation = SimulateDeferral(packets, consumerFramesPerSecond);

        Assert.True(simulation.MaximumRetainedBytes > packets.Sum(packet => packet.Bytes) * 0.5);
        Assert.True(simulation.EndRetainedCount > packets.Length * 0.5);
    }

    [Fact]
    public void ThirtyFpsConsumerCanKeepUpWithThirtyFpsPackets()
    {
        var packets = Enumerable.Range(0, 900)
            .Select(index => new TimedVideoPacket(index / 30.0, 200_000))
            .ToArray();

        var simulation = SimulateDeferral(packets, consumerFramesPerSecond: 30);

        Assert.InRange(simulation.EndRetainedCount, 0, 2);
        Assert.InRange(simulation.EndRetainedBytes, 0, 400_000);
    }

    private static DeferralSimulation SimulateDeferral(
        IReadOnlyList<TimedVideoPacket> packets,
        int consumerFramesPerSecond)
    {
        var retainedCount = 0;
        var retainedBytes = 0L;
        var retained = new Queue<int>();
        var maximumBytes = 0L;
        var nextConsumerTime = 0d;
        var retainedAtEnd = 0;

        foreach (var packet in packets)
        {
            while (nextConsumerTime <= packet.TimestampSeconds)
            {
                if (retainedCount > 0)
                {
                    retainedCount--;
                    retainedBytes -= retained.Dequeue();
                }

                nextConsumerTime += 1.0 / consumerFramesPerSecond;
            }

            retainedCount++;
            retainedBytes += packet.Bytes;
            retained.Enqueue(packet.Bytes);
            maximumBytes = Math.Max(maximumBytes, retainedBytes);
            retainedAtEnd = retainedCount;
        }

        return new(retainedAtEnd, retainedBytes, maximumBytes);
    }

    private readonly record struct TimedVideoPacket(double TimestampSeconds, int Bytes);

    private readonly record struct DeferralSimulation(
        int EndRetainedCount,
        long EndRetainedBytes,
        long MaximumRetainedBytes);

    private sealed class PacketCapacity(int count, int bytes)
    {
        private readonly int _maximumCount = count > 0
            ? count
            : throw new ArgumentOutOfRangeException(nameof(count));
        private readonly int _maximumBytes = bytes > 0
            ? bytes
            : throw new ArgumentOutOfRangeException(nameof(bytes));

        internal int Count { get; private set; }

        internal int Bytes { get; private set; }

        internal bool TryRetain(int packetBytes)
        {
            if (packetBytes <= 0 ||
                packetBytes > _maximumBytes ||
                Count >= _maximumCount ||
                Bytes > _maximumBytes - packetBytes)
            {
                return false;
            }

            Count++;
            Bytes += packetBytes;
            return true;
        }
    }
}
