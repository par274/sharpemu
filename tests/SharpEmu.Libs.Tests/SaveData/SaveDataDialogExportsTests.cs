// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.SaveData;
using System.Buffers.Binary;
using Xunit;

namespace SharpEmu.Libs.Tests.SaveData;

public sealed class SaveDataDialogExportsTests
{
    private const ulong MemoryBase = 0x1_0000_0000;
    private const ulong ParamAddress = MemoryBase;
    private const ulong ResultAddress = MemoryBase + 0x200;

    private const int StatusRunning = 2;
    private const int StatusFinished = 3;

    public SaveDataDialogExportsTests()
    {
        SaveDataDialogExports.ResetForTests();
    }

    private static CpuContext CreateContext(out FakeCpuMemory memory)
    {
        memory = new FakeCpuMemory(MemoryBase, 0x400);
        return new CpuContext(memory, Generation.Gen5);
    }

    // Regression: Initialize used to return ALREADY_INITIALIZED (0x80B80004) on every call
    // after the first. Titles re-initialize the service defensively and spin on the error -
    // Demon's Souls retried it forever after name entry, which looked like a freeze with
    // memory climbing. Repeat initialization must be a success, as it is for MsgDialog.
    [Fact]
    public void RepeatedInitializeAlwaysSucceeds()
    {
        var context = CreateContext(out _);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));
            Assert.Equal(0UL, context[CpuRegister.Rax]);
        }
    }

    // Re-initializing mid-flow must not reset a live dialog back to INITIALIZED, or the
    // status poll would hand the title a dialog that never finishes.
    [Fact]
    public void InitializeDoesNotClobberARunningDialog()
    {
        var context = CreateContext(out _);
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));

        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        // Still the running dialog, so polling drives it to FINISHED rather than
        // reporting a fresh INITIALIZED state.
        Assert.Equal(StatusRunning, SaveDataDialogExports.SaveDataDialogGetStatus(context));
        Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogGetStatus(context));
    }

    // Regression: the dialog used to finish on the very first poll, so RUNNING was never
    // returned to the title. Demon's Souls only accepts FINISHED after it has observed
    // RUNNING, and looped initialize -> open -> status forever without it.
    [Fact]
    public void FirstPollReportsRunningBeforeTheDialogFinishes()
    {
        var context = CreateContext(out _);
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));

        Assert.Equal(StatusRunning, SaveDataDialogExports.SaveDataDialogGetStatus(context));
        Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogGetStatus(context));
        Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogGetStatus(context));
    }

    // The same must hold for UpdateStatus, which titles use interchangeably.
    [Fact]
    public void UpdateStatusAlsoReportsRunningFirst()
    {
        var context = CreateContext(out _);
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));

        Assert.Equal(StatusRunning, SaveDataDialogExports.SaveDataDialogUpdateStatus(context));
        Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogUpdateStatus(context));
    }

    // Reopening must re-arm the RUNNING observation, or the second dialog finishes
    // instantly and the title loops again.
    [Fact]
    public void ReopeningReArmsTheRunningPoll()
    {
        var context = CreateContext(out _);
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        for (var cycle = 0; cycle < 3; cycle++)
        {
            context[CpuRegister.Rdi] = ParamAddress;
            Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));
            Assert.Equal(StatusRunning, SaveDataDialogExports.SaveDataDialogGetStatus(context));
            Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogGetStatus(context));
        }
    }

    [Fact]
    public void FullOpenPollResultCycleReportsTheAffirmativeButton()
    {
        var context = CreateContext(out var memory);
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));
        Assert.Equal(StatusRunning, SaveDataDialogExports.SaveDataDialogGetStatus(context));
        Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogGetStatus(context));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogGetResult(context));

        Span<byte> buttonId = stackalloc byte[sizeof(int)];
        Assert.True(memory.TryRead(ResultAddress + 0x08, buttonId));
        Assert.Equal(1, BinaryPrimitives.ReadInt32LittleEndian(buttonId));
    }

    [Fact]
    public void TerminateThenInitializeStartsACleanDialog()
    {
        var context = CreateContext(out _);
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogTerminate(context));

        // Terminating twice is still an error - that path is unchanged.
        Assert.NotEqual(0, SaveDataDialogExports.SaveDataDialogTerminate(context));

        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));
        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));
    }

    // A real OrbisSaveDataDialogParam captured from Demon's Souls. Offset 0 is the *base
    // param's* size (0x30), not the mode - reading the mode there returned a constant 48,
    // which GetResult echoed back, so the title rejected every result and reopened the
    // dialog forever. The real mode (3) is at +0x34.
    private static readonly byte[] CapturedParam = Convert.FromHexString(
        "30000000000000000000000000000000" +
        "00000000000000000000000000000000" +
        "00000000000000000000000069932BC9" +
        "98000000030000000100000000000000" +
        "60FE590806000000C0FD590806000000" +
        "000000000000000080FD590806000000");

    [Fact]
    public void ModeIsReadFromTheRealFieldNotTheBaseParamSize()
    {
        var context = CreateContext(out var memory);
        Assert.True(memory.TryWrite(ParamAddress, CapturedParam));
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));
        Assert.Equal(StatusRunning, SaveDataDialogExports.SaveDataDialogGetStatus(context));
        Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogGetStatus(context));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogGetResult(context));

        Span<byte> mode = stackalloc byte[sizeof(int)];
        Assert.True(memory.TryRead(ResultAddress, mode));
        Assert.Equal(3, BinaryPrimitives.ReadInt32LittleEndian(mode));
        Assert.NotEqual(48, BinaryPrimitives.ReadInt32LittleEndian(mode));
    }

    // userData's offset is unknown; the old fixed +0xC8 read landed outside the 0x98-byte
    // struct and handed the title whatever followed it as a pointer. Out-of-range must
    // yield a null, not garbage.
    [Fact]
    public void UserDataOutsideTheDeclaredStructSizeIsReportedAsNull()
    {
        var context = CreateContext(out var memory);
        Assert.True(memory.TryWrite(ParamAddress, CapturedParam));

        // Poison well past the declared 0x98-byte struct, where the old read pointed.
        var poison = new byte[0x40];
        Array.Fill(poison, (byte)0xEE);
        Assert.True(memory.TryWrite(ParamAddress + 0xC8, poison));

        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));
        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogOpen(context));
        Assert.Equal(StatusRunning, SaveDataDialogExports.SaveDataDialogGetStatus(context));
        Assert.Equal(StatusFinished, SaveDataDialogExports.SaveDataDialogGetStatus(context));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogGetResult(context));

        Span<byte> userData = stackalloc byte[sizeof(ulong)];
        Assert.True(memory.TryRead(ResultAddress + 0x20, userData));
        Assert.Equal(0UL, BinaryPrimitives.ReadUInt64LittleEndian(userData));
    }

    [Fact]
    public void GetResultBeforeTheDialogFinishesIsRejected()
    {
        var context = CreateContext(out _);
        Assert.Equal(0, SaveDataDialogExports.SaveDataDialogInitialize(context));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.NotEqual(0, SaveDataDialogExports.SaveDataDialogGetResult(context));
    }
}
