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
    private const int ErrorNotFinished = unchecked((int)0x80B80005);
    private const int ErrorNotRunning = unchecked((int)0x80B8000B);
    private const int ErrorArgNull = unchecked((int)0x80B8000D);

    private const int ResultSize = 0x48;
    private const int ButtonIdAffirmative = 1;

    // How many polls report RUNNING before the dialog auto-finishes.
    private const int RunningPollsBeforeFinish = 1;

    // OrbisSaveDataDialogParam, confirmed against a captured block (see Open).
    private const int ParamSizeOffset = 0x30;
    private const int ParamModeOffset = 0x34;
    private const int ParamDispTypeOffset = 0x38;
    private const int ParamUserDataOffset = 0xC8;

    private static int _status;
    private static int _runningPolls;
    private static int _lastMode;
    private static ulong _lastUserData;

    [SysAbiExport(
        Nid = "s9e3+YpRnzw",
        ExportName = "sceSaveDataDialogInitialize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogInitialize(CpuContext ctx)
    {
        // Repeated initialization succeeds, matching MsgDialogInitialize. Retail firmware
        // reports ALREADY_INITIALIZED, but titles re-initialize defensively and then spin
        // on the error forever. Only NONE is promoted, so re-initializing mid-flow cannot
        // clobber a running or finished dialog.
        var previous = Interlocked.CompareExchange(ref _status, StatusInitialized, StatusNone);
        TraceSaveDataDialog($"initialize (status was {previous}) -> ok");
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
            TraceSaveDataDialog($"open REJECTED: not initialized (status={_status})");
            return ctx.SetReturn(ErrorNotInitialized);
        }

        // Layout confirmed from a captured param block: +0x00 is
        // OrbisCommonDialogBaseParam.size (0x30), and the dialog's own fields start at
        // +0x30 (param.size = 0x98). Reading mode at +0x00 therefore returned a constant
        // 48, which GetResult echoed back; titles compare that against the mode they
        // asked for and reopen the dialog when it does not match.
        _lastMode = TryReadInt32(ctx, paramAddress + ParamModeOffset, out var mode) ? mode : 0;

        // +0xC8 is outside the 0x98 bytes the title declared, so only read it when the
        // declared size covers it - a null the title can handle beats trailing memory
        // handed back as a pointer.
        _lastUserData = TryReadInt32(ctx, paramAddress + ParamSizeOffset, out var declaredSize) &&
            declaredSize >= ParamUserDataOffset + sizeof(ulong) &&
            ctx.TryReadUInt64(paramAddress + ParamUserDataOffset, out var userData)
                ? userData
                : 0;

        // There is no host save dialog yet. Enter RUNNING so the close path sees a live
        // dialog; a later status poll auto-dismisses it (see PollStatus).
        Interlocked.Exchange(ref _runningPolls, 0);
        Interlocked.Exchange(ref _status, StatusRunning);
        var dispType = TryReadInt32(ctx, paramAddress + ParamDispTypeOffset, out var type) ? type : 0;
        TraceSaveDataDialog(
            $"open mode={_lastMode} dispType={dispType} userData=0x{_lastUserData:X16} -> running");
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

    // With no host UI the dialog cannot wait for user input, so it auto-dismisses - but it
    // must be observably running first. A title whose state machine only accepts FINISHED
    // after it has seen RUNNING restarts the dialog forever otherwise, and one spinning in
    // `while (GetStatus() == RUNNING)` just goes around once more.
    private static int PollStatus()
    {
        if (Volatile.Read(ref _status) != StatusRunning)
        {
            return Volatile.Read(ref _status);
        }

        if (Interlocked.Increment(ref _runningPolls) <= RunningPollsBeforeFinish)
        {
            return StatusRunning;
        }

        var previous = Interlocked.CompareExchange(ref _status, StatusFinished, StatusRunning);
        var current = Volatile.Read(ref _status);
        if (previous != current)
        {
            TraceSaveDataDialog($"status {previous} -> {current}");
        }

        return current;
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
            TraceSaveDataDialog($"get_result REJECTED: not finished (status={Volatile.Read(ref _status)})");
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
            TraceSaveDataDialog($"get_result FAILED: result=0x{resultAddress:X12} unwritable");
            return ctx.SetReturn((int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT);
        }

        TraceSaveDataDialog(
            $"get_result mode={_lastMode} buttonId={ButtonIdAffirmative} userData=0x{_lastUserData:X16}");
        return ctx.SetReturn(ErrorOk);
    }

    [SysAbiExport(
        Nid = "fH46Lag88XY",
        ExportName = "sceSaveDataDialogClose",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceSaveDataDialog")]
    public static int SaveDataDialogClose(CpuContext ctx)
    {
        if (Interlocked.CompareExchange(ref _status, StatusFinished, StatusRunning) != StatusRunning)
        {
            return ctx.SetReturn(ErrorNotRunning);
        }

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
            TraceSaveDataDialog("terminate REJECTED: not initialized");
            return ctx.SetReturn(ErrorNotInitialized);
        }

        _lastMode = 0;
        _lastUserData = 0;
        TraceSaveDataDialog("terminate");
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

    internal static void ResetForTests()
    {
        Volatile.Write(ref _status, StatusNone);
        Volatile.Write(ref _runningPolls, 0);
        _lastMode = 0;
        _lastUserData = 0;
    }

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
        if (!string.Equals(
                Environment.GetEnvironmentVariable("SHARPEMU_LOG_SAVEDATA"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        Console.Error.WriteLine($"[LOADER][TRACE] save_data_dialog.{message}");
    }
}
