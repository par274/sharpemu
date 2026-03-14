// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers.Binary;

namespace SharpEmu.Libs.Rtc;

public static class RtcExports
{
    [SysAbiExport(
        Nid = "ZPD1YOKI+Kw",
        ExportName = "sceRtcGetCurrentClockLocalTime",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceRtc")]
    public static int RtcGetCurrentClockLocalTime(CpuContext ctx)
    {
        var timeAddress = ctx[CpuRegister.Rdi];
        if (timeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var now = DateTimeOffset.Now;
        Span<byte> rtcDateTime = stackalloc byte[16];
        BinaryPrimitives.WriteUInt16LittleEndian(rtcDateTime[0..2], checked((ushort)now.Year));
        BinaryPrimitives.WriteUInt16LittleEndian(rtcDateTime[2..4], checked((ushort)now.Month));
        BinaryPrimitives.WriteUInt16LittleEndian(rtcDateTime[4..6], checked((ushort)now.Day));
        BinaryPrimitives.WriteUInt16LittleEndian(rtcDateTime[6..8], checked((ushort)now.Hour));
        BinaryPrimitives.WriteUInt16LittleEndian(rtcDateTime[8..10], checked((ushort)now.Minute));
        BinaryPrimitives.WriteUInt16LittleEndian(rtcDateTime[10..12], checked((ushort)now.Second));
        BinaryPrimitives.WriteUInt32LittleEndian(
            rtcDateTime[12..16],
            checked((uint)((now.Ticks % TimeSpan.TicksPerSecond) / 10)));

        if (!ctx.Memory.TryWrite(timeAddress, rtcDateTime))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "8w-H19ip48I",
        ExportName = "sceRtcGetTick",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libSceRtc")]
    public static int RtcGetTick(CpuContext ctx)
    {
        var dateTimeAddress = ctx[CpuRegister.Rdi];
        var tickAddress = ctx[CpuRegister.Rsi];
        if (dateTimeAddress == 0 || tickAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryReadRtcDateTime(ctx, dateTimeAddress, out var rtcDateTime))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ulong tickValue;
        try
        {
            var baseDateTime = new DateTime(
                rtcDateTime.Year,
                rtcDateTime.Month,
                rtcDateTime.Day,
                rtcDateTime.Hour,
                rtcDateTime.Minute,
                rtcDateTime.Second,
                DateTimeKind.Utc);
            tickValue = checked((ulong)((baseDateTime.Ticks / 10) + rtcDateTime.Microsecond));
        }
        catch (ArgumentOutOfRangeException)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!ctx.TryWriteUInt64(tickAddress, tickValue))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static bool TryReadRtcDateTime(CpuContext ctx, ulong address, out RtcDateTime rtcDateTime)
    {
        Span<byte> buffer = stackalloc byte[16];
        if (!ctx.Memory.TryRead(address, buffer))
        {
            rtcDateTime = default;
            return false;
        }

        rtcDateTime = new RtcDateTime(
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[0..2]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[2..4]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[4..6]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[6..8]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[8..10]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[10..12]),
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[12..16]));
        return true;
    }

    private readonly record struct RtcDateTime(
        ushort Year,
        ushort Month,
        ushort Day,
        ushort Hour,
        ushort Minute,
        ushort Second,
        uint Microsecond);
}
