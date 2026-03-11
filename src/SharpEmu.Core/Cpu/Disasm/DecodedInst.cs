// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Iced.Intel;

namespace SharpEmu.Core.Cpu.Disasm;

public readonly struct DecodedInst
{
    public DecodedInst(
        ulong rip,
        int length,
        string text,
        string mnemonic,
        FlowControl flowControl,
        ulong? nearBranchTarget,
        ulong? memoryAddress,
        byte[] bytes)
    {
        Rip = rip;
        Length = length;
        Text = text;
        Mnemonic = mnemonic;
        FlowControl = flowControl;
        NearBranchTarget = nearBranchTarget;
        MemoryAddress = memoryAddress;
        Bytes = bytes;
    }

    public ulong Rip { get; }

    public int Length { get; }

    public string Text { get; }

    public string Mnemonic { get; }

    public FlowControl FlowControl { get; }

    public ulong? NearBranchTarget { get; }

    public ulong? MemoryAddress { get; }

    public byte[] Bytes { get; }
}
