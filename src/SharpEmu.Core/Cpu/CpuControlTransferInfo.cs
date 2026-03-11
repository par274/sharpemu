// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Core.Cpu;

public readonly struct CpuControlTransferInfo
{
    public CpuControlTransferInfo(
        ulong sourceInstructionPointer,
        byte opcode,
        ulong targetInstructionPointer,
        CpuControlTransferKind kind,
        bool isIndirect,
        ulong rax,
        ulong rbx,
        ulong rcx,
        ulong rdx,
        ulong rsi,
        ulong rdi,
        ulong rsp,
        ulong rbp)
    {
        SourceInstructionPointer = sourceInstructionPointer;
        Opcode = opcode;
        TargetInstructionPointer = targetInstructionPointer;
        Kind = kind;
        IsIndirect = isIndirect;
        Rax = rax;
        Rbx = rbx;
        Rcx = rcx;
        Rdx = rdx;
        Rsi = rsi;
        Rdi = rdi;
        Rsp = rsp;
        Rbp = rbp;
    }

    public ulong SourceInstructionPointer { get; }

    public byte Opcode { get; }

    public ulong TargetInstructionPointer { get; }

    public CpuControlTransferKind Kind { get; }

    public bool IsIndirect { get; }

    public ulong Rax { get; }

    public ulong Rbx { get; }

    public ulong Rcx { get; }

    public ulong Rdx { get; }

    public ulong Rsi { get; }

    public ulong Rdi { get; }

    public ulong Rsp { get; }

    public ulong Rbp { get; }
}
