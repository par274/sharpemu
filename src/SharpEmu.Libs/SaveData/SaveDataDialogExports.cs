// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers.Binary;

namespace SharpEmu.Libs.SaveData;

public static class SaveDataDialogExports
{
    private const int StatusNone = 0;
    private const int StatusInitialized = 1;
    private const int StatusRunning = 2;
    private const int StatusFinished = 3;

    private const int ErrorOk = 0;
    private const int ErrorNotInitialized = unchecked((int)0x80B80003);
    private const int ErrorAlreadyInitialized = unchecked((int)0x80B80004);
    private const int ErrorNotFinished = unchecked((int)0x80B80005);
    private const int ErrorNotRunning = unchecked((int)0x80B8000B);
    private const int ErrorArgNull = unchecked((int)0x80B8000D);

    private const int ResultSize = 0x48;
    private const int ButtonIdAffirmative = 1;

    // OrbisSaveDataDialogParam offsets (0x98-byte struct): mode and userData
    // were previously read from the wrong offsets (0x00 and 0xC8) — 0x00 is
    // actually the leading CommonDialog::BaseParam.size field, and 0xC8 is
    // past the end of the struct entirely.
    private const int ParamModeOffset = 0x34;
    private const int ParamUserDataOffset = 0x70;

    private static int _status;
    private static int _lastMode;
    private static ulong _lastUserData;

    [SysAbiExport(
        Nid = "s9e3+YpRnzw",
        ExportName = "sceSaveDataDialogInitialize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogInitialize(CpuContext ctx)
    {
        // Finished is a fully-resolved prior session (its result has already been
        // read via GetResult), not a live one — treating it the same as None here
        // matches the reuse-without-Terminate pattern Open/Close already apply to
        // Finished (see the comments there). Requiring strictly None made every
        // Initialize after the very first successful dialog cycle permanently
        // fail with AlreadyInitialized, since nothing in a single-shot
        // system-message flow ever calls Terminate: verified live on Demon's
        // Souls that with this fix, character creation completes and the title
        // proceeds into real gameplay, which it never did before.
        var current = Volatile.Read(ref _status);
        if (current is not (StatusNone or StatusFinished))
        {
            return ctx.SetReturn(ErrorAlreadyInitialized);
        }

        Volatile.Write(ref _status, StatusInitialized);
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "4tPhsP6FpDI",
        ExportName = "sceSaveDataDialogOpen",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogOpen(CpuContext ctx)
    {
        var paramAddress = ctx[CpuRegister.Rdi];
        if (paramAddress == 0)
        {
            return ctx.SetReturn(ErrorArgNull);
        }

        if (_status is not (StatusInitialized or StatusFinished))
        {
            return ctx.SetReturn(ErrorNotInitialized);
        }

        _lastMode = TryReadInt32(ctx, paramAddress + ParamModeOffset, out var mode) ? mode : 0;
        _lastUserData = ctx.TryReadUInt64(paramAddress + ParamUserDataOffset, out var userData) ? userData : 0;

        // There is no host save dialog yet. Enter RUNNING so the close path sees a live
        // dialog; the guest's next status poll auto-dismisses it (see PollStatus).
        Interlocked.Exchange(ref _status, StatusRunning);
        TraceSaveDataDialog($"open mode={_lastMode} userData=0x{_lastUserData:X16} -> running");
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "ERKzksauAJA",
        ExportName = "sceSaveDataDialogGetStatus",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogGetStatus(CpuContext ctx) => ctx.SetReturn(PollStatus());

    [SysAbiExport(
        Nid = "KK3Bdg1RWK0",
        ExportName = "sceSaveDataDialogUpdateStatus",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogUpdateStatus(CpuContext ctx) => ctx.SetReturn(PollStatus());

    // With no host UI the dialog cannot wait for user input: the first status poll after
    // Open observes the dialog as already dismissed. Advancing on both UpdateStatus and
    // GetStatus keeps every guest polling pattern free of infinite RUNNING loops, while
    // an Open -> Close sequence with no poll in between still exercises the close path.
    private static int PollStatus()
    {
        Interlocked.CompareExchange(ref _status, StatusFinished, StatusRunning);
        return Volatile.Read(ref _status);
    }

    [SysAbiExport(
        Nid = "en7gNVnh878",
        ExportName = "sceSaveDataDialogIsReadyToDisplay",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogIsReadyToDisplay(CpuContext ctx) => ctx.SetReturn(1);

    [SysAbiExport(
        Nid = "yEiJ-qqr6Cg",
        ExportName = "sceSaveDataDialogGetResult",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogGetResult(CpuContext ctx)
    {
        var resultAddress = ctx[CpuRegister.Rdi];
        if (resultAddress == 0)
        {
            return ctx.SetReturn(ErrorArgNull);
        }

        if (Volatile.Read(ref _status) != StatusFinished)
        {
            return ctx.SetReturn(ErrorNotFinished);
        }

        // Report the affirmative button so save prompts take the confirming branch;
        // buttonId 0 is the "invalid" sentinel and games may treat it as an error.
        Span<byte> result = stackalloc byte[ResultSize];
        result.Clear();
        BinaryPrimitives.WriteInt32LittleEndian(result[0x00..], _lastMode);
        BinaryPrimitives.WriteInt32LittleEndian(result[0x04..], 0);
        BinaryPrimitives.WriteInt32LittleEndian(result[0x08..], ButtonIdAffirmative);
        BinaryPrimitives.WriteUInt64LittleEndian(result[0x20..], _lastUserData);

        if (!ctx.Memory.TryWrite(resultAddress, result))
        {
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
        }

        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "fH46Lag88XY",
        ExportName = "sceSaveDataDialogClose",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogClose(CpuContext ctx)
    {
        // The auto-dismiss design above (PollStatus) means a title's status poll has
        // almost always already advanced Running -> Finished by the time it calls
        // Close — Finished is the same "session over, ready for the next Open" state
        // Open itself already accepts (see the StatusInitialized-or-StatusFinished
        // guard there). Requiring strictly Running here made every real Open -> poll
        // -> GetResult -> Close sequence fail with NotRunning, leaving _status stuck
        // at Finished forever: the title's next Initialize call then permanently saw
        // AlreadyInitialized instead of succeeding.
        var current = Volatile.Read(ref _status);
        if (current is not (StatusRunning or StatusFinished))
        {
            return ctx.SetReturn(ErrorNotRunning);
        }

        Interlocked.CompareExchange(ref _status, StatusFinished, StatusRunning);
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "YuH2FA7azqQ",
        ExportName = "sceSaveDataDialogTerminate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogTerminate(CpuContext ctx)
    {
        if (Interlocked.Exchange(ref _status, StatusNone) == StatusNone)
        {
            return ctx.SetReturn(ErrorNotInitialized);
        }

        _lastMode = 0;
        _lastUserData = 0;
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "V-uEeFKARJU",
        ExportName = "sceSaveDataDialogProgressBarInc",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogProgressBarInc(CpuContext ctx) => ctx.SetReturn(ErrorOk);

    [SysAbiExport(
        Nid = "hay1CfTmLyA",
        ExportName = "sceSaveDataDialogProgressBarSetValue",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogProgressBarSetValue(CpuContext ctx) => ctx.SetReturn(ErrorOk);

    private static bool TryReadInt32(CpuContext ctx, ulong address, out int value)
    {
        value = 0;
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        if (!ctx.Memory.TryRead(address, bytes))
        {
            return false;
        }

        value = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        return true;
    }

    private static void TraceSaveDataDialog(string message)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_SAVEDATA"), "1", StringComparison.Ordinal))
        {
            return;
        }

        Console.Error.WriteLine($"[LOADER][TRACE] save_data_dialog.{message}");
    }
}
