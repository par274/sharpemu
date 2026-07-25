// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using System.Text;
using SharpEmu.HLE;
using SharpEmu.Libs.VideoOut;

namespace SharpEmu.Libs.Ime;

/// <summary>
/// libSceImeDialog — the on-screen text-entry overlay titles use for menu text
/// fields (character names, search boxes, etc.), distinct from libSceIme's
/// physical-keyboard session in <see cref="ImeExports"/>. Backed by a real
/// state machine and an actual rendered/typeable overlay
/// (<see cref="ImeDialogOverlay"/>) rather than a stub: the title/placeholder/
/// initial text are read from guest memory, keystrokes are captured from the
/// host keyboard while the dialog is open, and the typed UTF-16LE string is
/// written back into the guest's own input buffer on confirm, matching how
/// titles read the result (re-reading their own buffer after GetStatus
/// reports Finished, per the public PS4/PS5 SDK contract).
/// </summary>
public static class ImeDialogExports
{
    // Struct offsets below are OrbisImeDialogParam's natural x64 layout
    // (8-byte fields 8-byte aligned): verified against the public PS4/PS5 SDK
    // header shape, not guessed. Total size 96 bytes.
    private const int ParamSize = 96;
    private const int OffsetOption = 32;
    private const int OffsetMaxTextLength = 36;
    private const int OffsetInputTextBuffer = 40;
    private const int OffsetPlaceholder = 64;
    private const int OffsetTitle = 72;

    // OrbisImeOption.PASSWORD, per the public SDK header.
    private const uint OptionPasswordBit = 4;

    private const int ResultSize = 16;
    private const uint MaxTextLengthLimit = 2048; // ORBIS_IME_DIALOG_MAX_TEXT_LENGTH

    private enum ImeDialogError : uint
    {
        Ok = 0x0,
        Busy = 0x80bc0001,
        NotOpened = 0x80bc0002,
        InvalidMaxTextLength = 0x80bc0016,
        InvalidInputTextBuffer = 0x80bc0017,
        InvalidAddress = 0x80bc0031,
        DialogNotRunning = 0x80bc0105,
        DialogNotFinished = 0x80bc0106,
    }

    private enum OrbisImeDialogStatus : uint
    {
        None = 0,
        Running = 1,
        Finished = 2,
    }

    private enum OrbisImeDialogEndStatus : uint
    {
        Ok = 0,
        UserCanceled = 1,
        Aborted = 2,
    }

    private static readonly object _gate = new();
    private static ICpuMemory? _memory;
    private static OrbisImeDialogStatus _status = OrbisImeDialogStatus.None;
    private static OrbisImeDialogEndStatus _endStatus = OrbisImeDialogEndStatus.Ok;
    private static ulong _inputTextBufferAddress;
    private static uint _maxTextLength;

    private static readonly bool _trace =
        string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IME"), "1", StringComparison.Ordinal);

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
            return Return(ctx, ImeDialogError.InvalidAddress);
        }

        Span<byte> raw = stackalloc byte[ParamSize];
        if (!ctx.Memory.TryRead(paramAddress, raw))
        {
            return Return(ctx, ImeDialogError.InvalidAddress);
        }

        var option = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(OffsetOption, 4));
        var maxTextLength = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(OffsetMaxTextLength, 4));
        var inputTextBuffer = BinaryPrimitives.ReadUInt64LittleEndian(raw.Slice(OffsetInputTextBuffer, 8));
        var placeholderAddress = BinaryPrimitives.ReadUInt64LittleEndian(raw.Slice(OffsetPlaceholder, 8));
        var titleAddress = BinaryPrimitives.ReadUInt64LittleEndian(raw.Slice(OffsetTitle, 8));
        var isPassword = (option & OptionPasswordBit) != 0;

        if (maxTextLength == 0 || maxTextLength > MaxTextLengthLimit)
        {
            return Return(ctx, ImeDialogError.InvalidMaxTextLength);
        }

        if (inputTextBuffer == 0)
        {
            return Return(ctx, ImeDialogError.InvalidInputTextBuffer);
        }

        lock (_gate)
        {
            if (_status == OrbisImeDialogStatus.Running)
            {
                return Return(ctx, ImeDialogError.Busy);
            }
        }

        // Best-effort: initial text and title/placeholder are UTF-16LE guest
        // strings. A failed read (bad pointer, unmapped placeholder) degrades
        // to an empty string rather than failing Init outright — titles pass
        // null placeholders routinely, and losing the initial text is
        // recoverable (the user just retypes it) where losing the whole
        // dialog is not.
        var initialText = TryReadUtf16(ctx.Memory, inputTextBuffer, (int)maxTextLength, out var initial)
            ? initial
            : string.Empty;
        var title = titleAddress != 0 && TryReadUtf16(ctx.Memory, titleAddress, 256, out var titleText)
            ? titleText
            : string.Empty;
        _ = placeholderAddress; // no on-screen placeholder rendering yet; reserved for a fast-follow.

        lock (_gate)
        {
            _memory = ctx.Memory;
            _inputTextBufferAddress = inputTextBuffer;
            _maxTextLength = maxTextLength;
            _status = OrbisImeDialogStatus.Running;
            _endStatus = OrbisImeDialogEndStatus.Ok;
        }

        ImeDialogOverlay.Open(title, initialText, (int)maxTextLength, isPassword);
        Trace($"init title='{title}' initial='{initialText}' maxLen={maxTextLength} buffer=0x{inputTextBuffer:X16}");
        return Return(ctx, ImeDialogError.Ok);
    }

    [SysAbiExport(
        Nid = "IADmD4tScBY",
        ExportName = "sceImeDialogGetStatus",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogGetStatus(CpuContext ctx)
    {
        OrbisImeDialogStatus status;
        lock (_gate)
        {
            status = _status;
        }

        return ctx.SetReturn((int)status, typeof(long));
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
            return Return(ctx, ImeDialogError.InvalidAddress);
        }

        OrbisImeDialogStatus status;
        OrbisImeDialogEndStatus endStatus;
        lock (_gate)
        {
            status = _status;
            endStatus = _endStatus;
        }

        if (status != OrbisImeDialogStatus.Finished)
        {
            return Return(ctx, ImeDialogError.DialogNotFinished);
        }

        Span<byte> result = stackalloc byte[ResultSize];
        result.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(result[..4], (uint)endStatus);
        if (!ctx.Memory.TryWrite(resultAddress, result))
        {
            return Return(ctx, ImeDialogError.InvalidAddress);
        }

        return Return(ctx, ImeDialogError.Ok);
    }

    [SysAbiExport(
        Nid = "gyTyVn+bXMw",
        ExportName = "sceImeDialogTerm",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogTerm(CpuContext ctx)
    {
        lock (_gate)
        {
            _status = OrbisImeDialogStatus.None;
            _inputTextBufferAddress = 0;
            _maxTextLength = 0;
        }

        ImeDialogOverlay.Close();
        Trace("term");
        return Return(ctx, ImeDialogError.Ok);
    }

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
            return Return(ctx, ImeDialogError.InvalidAddress);
        }

        Span<byte> zero = stackalloc byte[ParamSize];
        zero.Clear();
        if (!ctx.Memory.TryWrite(paramAddress, zero))
        {
            return Return(ctx, ImeDialogError.InvalidAddress);
        }

        return Return(ctx, ImeDialogError.Ok);
    }

    [SysAbiExport(
        Nid = "oBmw4xrmfKs",
        ExportName = "sceImeDialogAbort",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogAbort(CpuContext ctx)
    {
        lock (_gate)
        {
            if (_status != OrbisImeDialogStatus.Running)
            {
                return Return(ctx, ImeDialogError.DialogNotRunning);
            }

            _status = OrbisImeDialogStatus.Finished;
            _endStatus = OrbisImeDialogEndStatus.Aborted;
        }

        ImeDialogOverlay.Close();
        return Return(ctx, ImeDialogError.Ok);
    }

    [SysAbiExport(
        Nid = "bX4H+sxPI-o",
        ExportName = "sceImeDialogForceClose",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceImeDialog")]
    public static int ImeDialogForceClose(CpuContext ctx)
    {
        lock (_gate)
        {
            _status = OrbisImeDialogStatus.None;
        }

        ImeDialogOverlay.Close();
        return Return(ctx, ImeDialogError.Ok);
    }

    /// <summary>
    /// Called by the presenter's per-frame host-input poll when the user
    /// presses Enter while the dialog is open: writes the typed text back
    /// into the guest's own input buffer (the documented result-retrieval
    /// path — titles re-read this buffer once GetStatus reports Finished)
    /// and transitions to Finished/Ok.
    /// </summary>
    internal static void ConfirmFromHostInput()
    {
        ICpuMemory? memory;
        ulong bufferAddress;
        uint maxLength;
        lock (_gate)
        {
            if (_status != OrbisImeDialogStatus.Running)
            {
                return;
            }

            memory = _memory;
            bufferAddress = _inputTextBufferAddress;
            maxLength = _maxTextLength;
        }

        var text = ImeDialogOverlay.CurrentText;
        if (memory is not null && bufferAddress != 0)
        {
            WriteUtf16(memory, bufferAddress, text, (int)maxLength);
        }

        lock (_gate)
        {
            _status = OrbisImeDialogStatus.Finished;
            _endStatus = OrbisImeDialogEndStatus.Ok;
        }

        ImeDialogOverlay.Close();
        Trace($"confirmed text='{text}'");
    }

    /// <summary>
    /// Called by the presenter's per-frame host-input poll when the user
    /// presses Escape: transitions to Finished/UserCanceled without touching
    /// the guest's input buffer, matching a real cancel (the title keeps
    /// whatever it had before Init).
    /// </summary>
    internal static void CancelFromHostInput()
    {
        lock (_gate)
        {
            if (_status != OrbisImeDialogStatus.Running)
            {
                return;
            }

            _status = OrbisImeDialogStatus.Finished;
            _endStatus = OrbisImeDialogEndStatus.UserCanceled;
        }

        ImeDialogOverlay.Close();
        Trace("canceled");
    }

    private static int Return(CpuContext ctx, ImeDialogError error) =>
        ctx.SetReturn(unchecked((int)(uint)error), typeof(long));

    private static bool TryReadUtf16(ICpuMemory memory, ulong address, int maxCodeUnits, out string value)
    {
        value = string.Empty;
        if (address == 0 || maxCodeUnits <= 0)
        {
            return false;
        }

        const int ChunkCodeUnits = 64;
        var capacity = Math.Min(maxCodeUnits, 2048);
        Span<byte> chunk = stackalloc byte[ChunkCodeUnits * 2];
        var units = new List<char>(Math.Min(capacity, 256));

        var offset = 0;
        while (offset < capacity)
        {
            var count = Math.Min(ChunkCodeUnits, capacity - offset);
            var span = chunk[..(count * 2)];
            if (!memory.TryRead(address + (ulong)(offset * 2), span))
            {
                return units.Count > 0;
            }

            for (var i = 0; i < count; i++)
            {
                var unit = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(i * 2, 2));
                if (unit == 0)
                {
                    value = new string(units.ToArray());
                    return true;
                }

                units.Add((char)unit);
            }

            offset += count;
        }

        value = new string(units.ToArray());
        return true;
    }

    private static void WriteUtf16(ICpuMemory memory, ulong address, string text, int maxCodeUnits)
    {
        if (maxCodeUnits <= 0)
        {
            return;
        }

        // Truncate to leave room for the null terminator, matching the guest
        // buffer's own contract (max_text_length includes the terminator).
        var truncated = text.Length >= maxCodeUnits ? text[..(maxCodeUnits - 1)] : text;
        var bytes = new byte[(truncated.Length + 1) * 2];
        Encoding.Unicode.GetBytes(truncated, 0, truncated.Length, bytes, 0);
        // Trailing two bytes are already zero (null terminator) from array init.
        memory.TryWrite(address, bytes);
    }

    private static void Trace(string message)
    {
        if (!_trace)
        {
            return;
        }

        Console.Error.WriteLine($"[LOADER][TRACE] ime.dialog.{message}");
    }
}
