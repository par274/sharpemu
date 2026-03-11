// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Core.Cpu;

public readonly struct CpuTrapInfo
{
    public CpuTrapInfo(ulong instructionPointer, byte opcode)
    {
        InstructionPointer = instructionPointer;
        Opcode = opcode;
    }

    public ulong InstructionPointer { get; }

    public byte Opcode { get; }
}
