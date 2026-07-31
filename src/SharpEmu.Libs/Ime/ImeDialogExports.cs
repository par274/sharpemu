// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers.Binary;
using System.Text;
using System.Threading;

namespace SharpEmu.Libs.Ime;

/// <summary>
/// libSceImeDialog: the on-screen keyboard for free-text entry. There is no host overlay
/// to type into, so the dialog completes immediately with text from ResolveText.
/// </summary>
public static class ImeDialogExports
{
    private const int StatusNone = 0;
    private const int StatusRunning = 1;
    private const int StatusFinished = 2;

    private const int EndStatusOk = 0;
    private const int EndStatusUserCanceled = 1;
    private const int EndStatusAborted = 2;

    private const int ErrorOk = 0;
    private const int ErrorInvalidAddress = unchecked((int)0x80BC1001);
    private const int ErrorInvalidParam = unchecked((int)0x80BC1002);
    private const int ErrorNotOpened = unchecked((int)0x80BC1003);
    private const int ErrorNotFinished = unchecked((int)0x80BC1004);
    private const int ErrorBusy = unchecked((int)0x80BC1005);

    // OrbisImeDialogParam. Only the fields deciding where the text goes are read.
    private const int ParamSize = 0x60;
    private const int ParamMaxTextLengthOffset = 0x24;
    private const int ParamInputTextBufferOffset = 0x28;

    // Caps the stack buffer below against a garbage maxTextLength.
    private const int MaxSupportedTextLength = 1024;

    private const string DefaultText = "SharpEmu";

    private static int _status;
    private static int _endStatus;

    [SysAbiExport(
        Nid = "aAx4WY4uwLc",
        ExportName = "sceImeDialogParamInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogParamInit(CpuContext ctx)
    {
        var paramAddress = ctx[CpuRegister.Rdi];
        if (paramAddress == 0)
        {
            return ctx.SetReturn(ErrorInvalidAddress);
        }

        // Zeroes the whole struct, as the real entry point does. Safe only because the
        // caller must have reserved ParamSize to hand the same struct to Init.
        Span<byte> zeroed = stackalloc byte[ParamSize];
        zeroed.Clear();
        if (!ctx.Memory.TryWrite(paramAddress, zeroed))
        {
            Trace($"param_init param=0x{paramAddress:X12} FAILED (unwritable)");
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
        }

        Trace($"param_init param=0x{paramAddress:X12}");
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "NUeBrN7hzf0",
        ExportName = "sceImeDialogInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogInit(CpuContext ctx)
    {
        var paramAddress = ctx[CpuRegister.Rdi];
        if (paramAddress == 0)
        {
            Trace("init REJECTED: null param");
            return ctx.SetReturn(ErrorInvalidAddress);
        }

        if (Volatile.Read(ref _status) == StatusRunning)
        {
            Trace($"init REJECTED: busy, a dialog is already running (param=0x{paramAddress:X12})");
            return ctx.SetReturn(ErrorBusy);
        }

        Span<byte> param = stackalloc byte[ParamSize];
        if (!ctx.Memory.TryRead(paramAddress, param))
        {
            Trace($"init REJECTED: param=0x{paramAddress:X12} unreadable for {ParamSize} bytes");
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
        }

        Trace($"init param=0x{paramAddress:X12}");

        var maxTextLength = BinaryPrimitives.ReadUInt32LittleEndian(param[ParamMaxTextLengthOffset..]);
        var textBuffer = BinaryPrimitives.ReadUInt64LittleEndian(param[ParamInputTextBufferOffset..]);
        if (textBuffer == 0)
        {
            Trace($"init REJECTED: inputTextBuffer at +0x{ParamInputTextBufferOffset:X2} is null - offsets are probably wrong for this title");
            return ctx.SetReturn(ErrorInvalidParam);
        }

        // Titles read the committed text out of this buffer - GetResult reports only how
        // the dialog ended - so it has to land here before the first status poll can
        // report FINISHED. The terminator is reserved inside maxTextLength rather than
        // written past it: whether the field counts the null is unverifiable here, and
        // guessing wrong overruns a caller's local by one wide character.
        var limit = (int)Math.Min(maxTextLength, MaxSupportedTextLength);
        if (limit == 0)
        {
            Trace($"init REJECTED: maxTextLength at +0x{ParamMaxTextLengthOffset:X2} is zero - offsets are probably wrong for this title");
            return ctx.SetReturn(ErrorInvalidParam);
        }

        var capacity = limit - 1;
        var text = ResolveText();
        if (text.Length > capacity)
        {
            text = text[..capacity];
        }

        // Guest wchar_t is 16-bit; the field is UTF-16LE and null-terminated.
        Span<byte> encoded = stackalloc byte[(text.Length + 1) * sizeof(char)];
        Encoding.Unicode.GetBytes(text, encoded);
        encoded[^2..].Clear();

        if (!ctx.Memory.TryWrite(textBuffer, encoded))
        {
            Trace($"init REJECTED: inputTextBuffer=0x{textBuffer:X12} unwritable for {encoded.Length} bytes - offsets are probably wrong for this title");
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
        }

        Volatile.Write(ref _endStatus, EndStatusOk);
        Volatile.Write(ref _status, StatusRunning);
        Trace($"init text='{text}' buffer=0x{textBuffer:X16} max={maxTextLength}");
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "IADmD4tScBY",
        ExportName = "sceImeDialogGetStatus",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogGetStatus(CpuContext ctx)
    {
        // Nothing can dismiss the dialog from the host side, so the first poll after Init
        // observes it as already committed. Titles spin until it leaves RUNNING.
        var previous = Interlocked.CompareExchange(ref _status, StatusFinished, StatusRunning);
        var current = Volatile.Read(ref _status);
        if (previous != current)
        {
            Trace($"get_status {previous} -> {current}");
        }

        return ctx.SetReturn(current);
    }

    [SysAbiExport(
        Nid = "x01jxu+vxlc",
        ExportName = "sceImeDialogGetResult",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogGetResult(CpuContext ctx)
    {
        var resultAddress = ctx[CpuRegister.Rdi];
        if (resultAddress == 0)
        {
            return ctx.SetReturn(ErrorInvalidAddress);
        }

        if (Volatile.Read(ref _status) != StatusFinished)
        {
            Trace($"get_result REJECTED: not finished (status={Volatile.Read(ref _status)})");
            return ctx.SetReturn(ErrorNotFinished);
        }

        // Only endStatus is written. Callers read that and the text buffer, never the
        // reserved tail of OrbisImeDialogResult, and titles pass this a stack local -
        // zeroing a tail whose size we cannot verify smashed a frame once already.
        Span<byte> endStatus = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(endStatus, Volatile.Read(ref _endStatus));
        if (!ctx.Memory.TryWrite(resultAddress, endStatus))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
        }

        Trace($"get_result end_status={Volatile.Read(ref _endStatus)}");
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "oBmw4xrmfKs",
        ExportName = "sceImeDialogAbort",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogAbort(CpuContext ctx) => Close(ctx, EndStatusAborted);

    [SysAbiExport(
        Nid = "bX4H+sxPI-o",
        ExportName = "sceImeDialogForceClose",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogForceClose(CpuContext ctx) => Close(ctx, EndStatusUserCanceled);

    [SysAbiExport(
        Nid = "gyTyVn+bXMw",
        ExportName = "sceImeDialogTerm",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogTerm(CpuContext ctx)
    {
        if (Interlocked.Exchange(ref _status, StatusNone) == StatusNone)
        {
            return ctx.SetReturn(ErrorNotOpened);
        }

        Trace("term");
        return ctx.SetReturn(ErrorOk);
    }

    private static int Close(CpuContext ctx, int endStatus)
    {
        if (Interlocked.CompareExchange(ref _status, StatusFinished, StatusRunning) != StatusRunning)
        {
            return ctx.SetReturn(ErrorNotOpened);
        }

        Volatile.Write(ref _endStatus, endStatus);
        Trace($"close end_status={endStatus}");
        return ctx.SetReturn(ErrorOk);
    }

    /// <summary>The text every IME dialog commits. SHARPEMU_IME_TEXT overrides it.</summary>
    private static string ResolveText()
    {
        var configured = Environment.GetEnvironmentVariable("SHARPEMU_IME_TEXT");
        return string.IsNullOrEmpty(configured) ? DefaultText : configured;
    }

    internal static void ResetForTests()
    {
        Volatile.Write(ref _status, StatusNone);
        Volatile.Write(ref _endStatus, EndStatusOk);
    }

    /// <summary>
    /// Off unless SHARPEMU_LOG_IME_DIALOG=1. A title whose param layout differs reads
    /// back an empty name and reopens the dialog forever, which presents as a freeze
    /// rather than an error, so the lifecycle has to be inspectable.
    /// </summary>
    private static void Trace(string message)
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable("SHARPEMU_LOG_IME_DIALOG"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        Console.Error.WriteLine($"[LOADER][TRACE] ime_dialog.{message}");
    }
}
