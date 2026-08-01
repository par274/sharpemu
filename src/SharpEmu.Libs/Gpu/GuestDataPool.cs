// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers;
using System.Numerics;
using SharpEmu.Logging;

namespace SharpEmu.Libs.Gpu;

/// <summary>
/// The pool backing AGC-to-presenter ownership transfers, shared by every backend
/// (the AGC layer rents, the presenter returns, so both sides must use one pool).
/// Guest draw snapshots churn through a small set of 128 KiB-16 MiB size classes
/// thousands of times per second; the process-wide shared pool trims and
/// repartitions those large arrays aggressively under GC load, causing hundreds of
/// MiB/s of replacement byte[] allocations, so this pool is bounded and non-shared.
/// </summary>
internal static class GuestDataPool
{
    public static ArrayPool<byte> Shared { get; } = new BoundedByteArrayPool(
        maxArrayLength: 16 * 1024 * 1024,
        maxCachedBytes: 256UL * 1024 * 1024,
        maxArraysPerBucket: 8);

    public static void Trim() => ((BoundedByteArrayPool)Shared).Trim();

    private sealed class BoundedByteArrayPool : ArrayPool<byte>
    {
        private readonly object _gate = new();
        private readonly int _maxArrayLength;
        private readonly ulong _maxCachedBytes;
        private readonly int _maxArraysPerBucket;
        private readonly Dictionary<int, Stack<byte[]>> _cachedByBucket = [];
        private readonly HashSet<byte[]> _leases =
            new(System.Collections.Generic.ReferenceEqualityComparer.Instance);
        private ulong _cachedBytes;

        public BoundedByteArrayPool(
            int maxArrayLength,
            ulong maxCachedBytes,
            int maxArraysPerBucket)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxArrayLength);
            ArgumentOutOfRangeException.ThrowIfZero(maxCachedBytes);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxArraysPerBucket);
            _maxArrayLength = maxArrayLength;
            _maxCachedBytes = maxCachedBytes;
            _maxArraysPerBucket = maxArraysPerBucket;
        }

        public override byte[] Rent(int minimumLength)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(minimumLength);
            var length = GetAllocationLength(minimumLength);
            byte[]? array = null;
            var allocated = false;
            lock (_gate)
            {
                if (length <= _maxArrayLength &&
                    _cachedByBucket.TryGetValue(length, out var bucket) &&
                    bucket.TryPop(out array))
                {
                    _cachedBytes -= (ulong)array.LongLength;
                }

                if (array is null)
                {
                    array = new byte[length];
                    allocated = true;
                }

                _leases.Add(array);
                if (allocated)
                {
                    var allocatedBytes = checked((long)array.LongLength);
                    MemoryDiagnostics.Adjust(
                        "managed.guest-data-pool-retained",
                        allocatedBytes,
                        countDelta: 1);
                    MemoryDiagnostics.Adjust(
                        "managed.guest-data-pool-allocated",
                        allocatedBytes,
                        countDelta: 1);
                }
            }

            return array;
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            ArgumentNullException.ThrowIfNull(array);
            var arrayBytes = checked((long)array.LongLength);
            lock (_gate)
            {
                if (!_leases.Remove(array))
                {
                    return;
                }
            }

            // The lease no longer belongs to the pool while Return evaluates
            // whether it can be cached. Keep the current-retained counter
            // aligned with that ownership boundary.
            MemoryDiagnostics.Adjust(
                "managed.guest-data-pool-retained",
                -arrayBytes,
                countDelta: -1);

            if (clearArray)
            {
                Array.Clear(array);
            }

            lock (_gate)
            {
                if (array.Length > _maxArrayLength ||
                    !IsBucketLength(array.Length) ||
                    (ulong)array.LongLength > _maxCachedBytes -
                        Math.Min(_cachedBytes, _maxCachedBytes))
                {
                    return;
                }

                if (!_cachedByBucket.TryGetValue(array.Length, out var bucket))
                {
                    bucket = new Stack<byte[]>();
                    _cachedByBucket.Add(array.Length, bucket);
                }

                if (bucket.Count >= _maxArraysPerBucket)
                {
                    return;
                }

                bucket.Push(array);
                _cachedBytes += (ulong)array.LongLength;
                MemoryDiagnostics.Adjust(
                    "managed.guest-data-pool-retained",
                    arrayBytes,
                    countDelta: 1);
            }
        }

        public void Trim()
        {
            lock (_gate)
            {
                var cachedBytes = checked((long)_cachedBytes);
                var cachedArrayCount = 0;
                foreach (var bucket in _cachedByBucket.Values)
                {
                    cachedArrayCount += bucket.Count;
                }

                _cachedByBucket.Clear();
                _cachedBytes = 0;
                MemoryDiagnostics.Adjust(
                    "managed.guest-data-pool-retained",
                    -cachedBytes,
                    countDelta: -cachedArrayCount);
            }
        }

        private int GetAllocationLength(int minimumLength)
        {
            if (minimumLength <= 16)
            {
                return 16;
            }

            if (minimumLength > _maxArrayLength)
            {
                return minimumLength;
            }

            return checked((int)BitOperations.RoundUpToPowerOf2((uint)minimumLength));
        }

        private static bool IsBucketLength(int length) =>
            length >= 16 && (length & (length - 1)) == 0;
    }
}
