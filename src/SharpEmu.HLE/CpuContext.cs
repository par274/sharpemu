// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;

namespace SharpEmu.HLE;

public sealed class CpuContext
{
    private readonly ulong[] _registers = new ulong[16];
    private readonly ulong[] _xmmRegisters = new ulong[32];
    private readonly ulong[] _ymmUpperRegisters = new ulong[32];
    private bool _raxWritten;

    public CpuContext(ICpuMemory memory, Generation generation)
    {
        Memory = memory ?? throw new ArgumentNullException(nameof(memory));
        TargetGeneration = generation;
    }

    public ICpuMemory Memory { get; }

    public Generation TargetGeneration { get; }

    public ulong Rip { get; set; }

    public ulong Rflags { get; set; }

    public ulong FsBase { get; set; }

    public ulong GsBase { get; set; }

    public ulong this[CpuRegister register]
    {
        get => _registers[(int)register];
        set
        {
            _registers[(int)register] = value;
            if (register == CpuRegister.Rax)
            {
                _raxWritten = true;
            }
        }
    }

    public void ClearRaxWriteFlag()
    {
        _raxWritten = false;
    }

    public bool WasRaxWritten => _raxWritten;

    public void GetXmmRegister(int registerIndex, out ulong low, out ulong high)
    {
        if ((uint)registerIndex >= 16)
        {
            throw new ArgumentOutOfRangeException(nameof(registerIndex));
        }

        var offset = registerIndex * 2;
        low = _xmmRegisters[offset];
        high = _xmmRegisters[offset + 1];
    }

    public void SetXmmRegister(int registerIndex, ulong low, ulong high)
    {
        if ((uint)registerIndex >= 16)
        {
            throw new ArgumentOutOfRangeException(nameof(registerIndex));
        }

        var offset = registerIndex * 2;
        _xmmRegisters[offset] = low;
        _xmmRegisters[offset + 1] = high;
    }

    public void GetYmmUpper(int registerIndex, out ulong low, out ulong high)
    {
        if ((uint)registerIndex >= 16)
        {
            throw new ArgumentOutOfRangeException(nameof(registerIndex));
        }

        var offset = registerIndex * 2;
        low = _ymmUpperRegisters[offset];
        high = _ymmUpperRegisters[offset + 1];
    }

    public void SetYmmUpper(int registerIndex, ulong low, ulong high)
    {
        if ((uint)registerIndex >= 16)
        {
            throw new ArgumentOutOfRangeException(nameof(registerIndex));
        }

        var offset = registerIndex * 2;
        _ymmUpperRegisters[offset] = low;
        _ymmUpperRegisters[offset + 1] = high;
    }

    public void ClearYmmUpper(int registerIndex)
    {
        SetYmmUpper(registerIndex, 0, 0);
    }

    public void ClearAllYmmUpper()
    {
        Array.Clear(_ymmUpperRegisters);
    }

    public void GetYmmRegister(
        int registerIndex,
        out ulong lowLow,
        out ulong lowHigh,
        out ulong highLow,
        out ulong highHigh)
    {
        GetXmmRegister(registerIndex, out lowLow, out lowHigh);
        GetYmmUpper(registerIndex, out highLow, out highHigh);
    }

    public void SetYmmRegister(
        int registerIndex,
        ulong lowLow,
        ulong lowHigh,
        ulong highLow,
        ulong highHigh)
    {
        SetXmmRegister(registerIndex, lowLow, lowHigh);
        SetYmmUpper(registerIndex, highLow, highHigh);
    }

    public bool TryReadUInt64(ulong address, out ulong value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];
        if (!Memory.TryRead(address, buffer))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt64LittleEndian(buffer);
        return true;
    }

    public bool TryWriteUInt64(ulong address, ulong value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        return Memory.TryWrite(address, buffer);
    }

    public bool PushUInt64(ulong value)
    {
        var rsp = this[CpuRegister.Rsp];
        rsp -= sizeof(ulong);
        this[CpuRegister.Rsp] = rsp;
        return TryWriteUInt64(rsp, value);
    }

    public bool PopUInt64(out ulong value)
    {
        var rsp = this[CpuRegister.Rsp];
        if (!TryReadUInt64(rsp, out value))
        {
            return false;
        }

        this[CpuRegister.Rsp] = rsp + sizeof(ulong);
        return true;
    }
}
