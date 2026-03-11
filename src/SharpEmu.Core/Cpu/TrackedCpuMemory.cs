// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;

namespace SharpEmu.Core.Cpu;

public sealed class TrackedCpuMemory : ICpuMemory, ITrackedCpuMemory
{
    private readonly ICpuMemory _inner;

    public TrackedCpuMemory(ICpuMemory inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public CpuMemoryAccessFailure? LastFailure { get; private set; }

    public ICpuMemory Inner => _inner;

    public bool TryRead(ulong virtualAddress, Span<byte> destination)
    {
        var result = _inner.TryRead(virtualAddress, destination);
        if (!result)
        {
            LastFailure = new CpuMemoryAccessFailure(virtualAddress, destination.Length, isWrite: false);
        }

        return result;
    }

    public bool TryWrite(ulong virtualAddress, ReadOnlySpan<byte> source)
    {
        var result = _inner.TryWrite(virtualAddress, source);
        if (!result)
        {
            LastFailure = new CpuMemoryAccessFailure(virtualAddress, source.Length, isWrite: true);
        }

        return result;
    }
}
