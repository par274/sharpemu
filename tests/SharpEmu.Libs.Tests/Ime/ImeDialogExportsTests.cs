// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.Ime;
using System.Buffers.Binary;
using System.Text;
using Xunit;

namespace SharpEmu.Libs.Tests.Ime;

public sealed class ImeDialogExportsTests
{
    private const ulong MemoryBase = 0x1_0000_0000;
    private const ulong ParamAddress = MemoryBase;
    private const ulong TextBufferAddress = MemoryBase + 0x100;
    private const ulong ResultAddress = MemoryBase + 0x300;

    private const int ParamSize = 0x60;
    private const int ParamMaxTextLengthOffset = 0x24;
    private const int ParamInputTextBufferOffset = 0x28;

    private const int StatusRunning = 1;
    private const int StatusFinished = 2;

    public ImeDialogExportsTests()
    {
        ImeDialogExports.ResetForTests();
        Environment.SetEnvironmentVariable("SHARPEMU_IME_TEXT", null);
    }

    private static (FakeCpuMemory Memory, CpuContext Context) CreateDialog(uint maxTextLength = 16)
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x400);
        var context = new CpuContext(memory, Generation.Gen5);

        Span<byte> param = stackalloc byte[ParamSize];
        param.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(param[ParamMaxTextLengthOffset..], maxTextLength);
        BinaryPrimitives.WriteUInt64LittleEndian(param[ParamInputTextBufferOffset..], TextBufferAddress);
        Assert.True(memory.TryWrite(ParamAddress, param));

        context[CpuRegister.Rdi] = ParamAddress;
        return (memory, context);
    }

    private static string ReadGuestText(FakeCpuMemory memory, int maxCharacters)
    {
        var bytes = new byte[(maxCharacters + 1) * sizeof(char)];
        Assert.True(memory.TryRead(TextBufferAddress, bytes));
        var text = Encoding.Unicode.GetString(bytes);
        var terminator = text.IndexOf('\0');
        return terminator < 0 ? text : text[..terminator];
    }

    // The whole point of the module: the title's buffer has to come back holding text,
    // because sceImeDialogGetResult reports only how the dialog ended, never the string.
    [Fact]
    public void InitWritesConfiguredTextIntoTheGuestBufferAsNullTerminatedUtf16()
    {
        Environment.SetEnvironmentVariable("SHARPEMU_IME_TEXT", "Boletaria");
        var (memory, context) = CreateDialog();

        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));
        Assert.Equal("Boletaria", ReadGuestText(memory, 16));
    }

    // The terminator is reserved inside maxTextLength, so four characters of capacity
    // hold three characters plus the null.
    [Fact]
    public void TextLongerThanMaxTextLengthIsTruncatedToTheGuestCapacity()
    {
        Environment.SetEnvironmentVariable("SHARPEMU_IME_TEXT", "AstraeaMaidenInBlack");
        var (memory, context) = CreateDialog(maxTextLength: 4);

        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));
        Assert.Equal("Ast", ReadGuestText(memory, 4));
    }

    // Regression: writing maxTextLength characters *plus* a terminator overruns the guest
    // buffer by two bytes, which smashes a stack canary when the field is a local. The
    // byte at buffer[maxTextLength] must never be touched.
    [Theory]
    [InlineData(1u)]
    [InlineData(2u)]
    [InlineData(8u)]
    [InlineData(16u)]
    public void InitNeverWritesPastMaxTextLengthWideCharacters(uint maxTextLength)
    {
        Environment.SetEnvironmentVariable("SHARPEMU_IME_TEXT", "AstraeaMaidenInBlack");
        var memory = new FakeCpuMemory(MemoryBase, 0x400);
        var context = new CpuContext(memory, Generation.Gen5);

        // Poison the buffer and one wide character past its documented end.
        var guard = new byte[(maxTextLength + 1) * sizeof(char)];
        Array.Fill(guard, (byte)0xEE);
        Assert.True(memory.TryWrite(TextBufferAddress, guard));

        Span<byte> param = stackalloc byte[ParamSize];
        param.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(param[ParamMaxTextLengthOffset..], maxTextLength);
        BinaryPrimitives.WriteUInt64LittleEndian(param[ParamInputTextBufferOffset..], TextBufferAddress);
        Assert.True(memory.TryWrite(ParamAddress, param));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));

        Span<byte> pastEnd = stackalloc byte[sizeof(char)];
        Assert.True(memory.TryRead(TextBufferAddress + (maxTextLength * sizeof(char)), pastEnd));
        Assert.Equal(0xEE, pastEnd[0]);
        Assert.Equal(0xEE, pastEnd[1]);
    }

    // A title that never sees FINISHED spins on GetStatus forever - this is the exact
    // hang the auto-commit avoids.
    [Fact]
    public void StatusAdvancesFromRunningToFinishedOnTheFirstPoll()
    {
        var (_, context) = CreateDialog();
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));

        Assert.Equal(StatusFinished, ImeDialogExports.ImeDialogGetStatus(context));
        Assert.Equal(StatusFinished, ImeDialogExports.ImeDialogGetStatus(context));
    }

    [Fact]
    public void GetResultReportsSuccessOnlyAfterTheDialogFinished()
    {
        var (memory, context) = CreateDialog();
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.NotEqual(0, ImeDialogExports.ImeDialogGetResult(context));

        Assert.Equal(StatusFinished, ImeDialogExports.ImeDialogGetStatus(context));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.Equal(0, ImeDialogExports.ImeDialogGetResult(context));

        Span<byte> endStatus = stackalloc byte[sizeof(int)];
        Assert.True(memory.TryRead(ResultAddress, endStatus));
        Assert.Equal(0, BinaryPrimitives.ReadInt32LittleEndian(endStatus));
    }

    // Regression: GetResult used to zero 0x34 bytes of assumed OrbisImeDialogResult. Titles
    // pass a stack local, so writing past endStatus smashed the frame's canary and tripped
    // __stack_chk_fail when the calling function returned. Only the first four bytes are ours.
    [Fact]
    public void GetResultWritesEndStatusOnlyAndNothingPastIt()
    {
        var (memory, context) = CreateDialog();
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));
        Assert.Equal(StatusFinished, ImeDialogExports.ImeDialogGetStatus(context));

        var poison = new byte[0x40];
        Array.Fill(poison, (byte)0xEE);
        Assert.True(memory.TryWrite(ResultAddress, poison));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.Equal(0, ImeDialogExports.ImeDialogGetResult(context));

        var readBack = new byte[0x40];
        Assert.True(memory.TryRead(ResultAddress, readBack));
        Assert.Equal(0, BinaryPrimitives.ReadInt32LittleEndian(readBack));
        Assert.All(readBack[sizeof(int)..], b => Assert.Equal(0xEE, b));
    }

    [Fact]
    public void InitRejectsASecondDialogWhileOneIsRunning()
    {
        var (_, context) = CreateDialog();
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.NotEqual(0, ImeDialogExports.ImeDialogInit(context));
    }

    [Fact]
    public void InitRejectsANullParamAndANullTextBuffer()
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x400);
        var context = new CpuContext(memory, Generation.Gen5);

        context[CpuRegister.Rdi] = 0;
        Assert.NotEqual(0, ImeDialogExports.ImeDialogInit(context));

        Span<byte> param = stackalloc byte[ParamSize];
        param.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(param[ParamMaxTextLengthOffset..], 16);
        Assert.True(memory.TryWrite(ParamAddress, param));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.NotEqual(0, ImeDialogExports.ImeDialogInit(context));
    }

    [Fact]
    public void TermAfterFinishSucceedsAndAllowsAFreshDialog()
    {
        var (_, context) = CreateDialog();
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));
        Assert.Equal(StatusFinished, ImeDialogExports.ImeDialogGetStatus(context));
        Assert.Equal(0, ImeDialogExports.ImeDialogTerm(context));

        // Terminating an already-terminated dialog is an error, not a silent success.
        Assert.NotEqual(0, ImeDialogExports.ImeDialogTerm(context));

        // The new dialog is genuinely RUNNING: a second Init is rejected as busy.
        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));
        context[CpuRegister.Rdi] = ParamAddress;
        Assert.NotEqual(0, ImeDialogExports.ImeDialogInit(context));
    }

    [Fact]
    public void AbortMarksTheDialogAbortedForGetResult()
    {
        var (memory, context) = CreateDialog();
        Assert.Equal(0, ImeDialogExports.ImeDialogInit(context));
        Assert.Equal(0, ImeDialogExports.ImeDialogAbort(context));

        context[CpuRegister.Rdi] = ResultAddress;
        Assert.Equal(0, ImeDialogExports.ImeDialogGetResult(context));

        Span<byte> endStatus = stackalloc byte[sizeof(int)];
        Assert.True(memory.TryRead(ResultAddress, endStatus));
        Assert.Equal(2, BinaryPrimitives.ReadInt32LittleEndian(endStatus));
    }

    [Fact]
    public void ParamInitZeroesTheParameterBlock()
    {
        var memory = new FakeCpuMemory(MemoryBase, 0x400);
        var context = new CpuContext(memory, Generation.Gen5);

        var dirty = new byte[ParamSize];
        Array.Fill(dirty, (byte)0xCD);
        Assert.True(memory.TryWrite(ParamAddress, dirty));

        context[CpuRegister.Rdi] = ParamAddress;
        Assert.Equal(0, ImeDialogExports.ImeDialogParamInit(context));

        var readBack = new byte[ParamSize];
        Assert.True(memory.TryRead(ParamAddress, readBack));
        Assert.All(readBack, b => Assert.Equal(0, b));
    }
}
