// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System;
using System.Runtime.InteropServices;

namespace SharpEmu.Core.Cpu.Native;

public sealed unsafe class CpuPatcher : IDisposable
{
    private readonly nint _tlsBaseAddress;

    public CpuPatcher(nint tlsBaseAddress)
    {
        _tlsBaseAddress = tlsBaseAddress;
    }

    public bool TryPatchInstruction(nint address)
    {
        return false;
    }

    public void Dispose()
    {
    }

    internal unsafe class UnsafeCodeReader : Iced.Intel.CodeReader
    {
        private byte* _start;
        private byte* _current;
        private int _length;

        public UnsafeCodeReader(byte* start, int length)
        {
            _start = start;
            _current = start;
            _length = length;
        }

        public override int ReadByte()
        {
            if (_current >= _start + _length)
                return -1;
            return *_current++;
        }
    }
}
