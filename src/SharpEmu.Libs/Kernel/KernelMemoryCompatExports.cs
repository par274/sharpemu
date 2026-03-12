// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers.Binary;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SharpEmu.Libs.Kernel;

public static class KernelMemoryCompatExports
{
    private const int MaxGuestStringLength = 4096;
    private const int MemsetChunkSize = 16 * 1024;
    private const int TlsModuleBlockSize = 0x10000;
    private const int O_WRONLY = 0x1;
    private const int O_RDWR = 0x2;
    private const int O_APPEND = 0x8;
    private const int O_CREAT = 0x0200;
    private const int O_TRUNC = 0x0400;
    private const int O_DIRECTORY = 0x00020000;
    private const int SeekSet = 0;
    private const int SeekCur = 1;
    private const int SeekEnd = 2;
    private const ulong DirectMemorySizeBytes = 16384UL * 1024 * 1024;
    private const ulong FlexibleMemorySizeBytes = 448UL * 1024 * 1024;
    private const uint MemCommit = 0x1000;
    private const uint PageNoAccess = 0x01;
    private const uint PageReadOnly = 0x02;
    private const uint PageReadWrite = 0x04;
    private const uint PageWriteCopy = 0x08;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;
    private const uint PageGuard = 0x100;
    private const int Enomem = 12;
    private const int Einval = 22;
    private const nuint DefaultLibcHeapAlignment = 16;

    private static readonly object _fdGate = new();
    private static readonly Dictionary<int, FileStream> _openFiles = new();
    private static readonly Dictionary<int, OpenDirectory> _openDirectories = new();
    private static readonly object _libcAllocGate = new();
    private static readonly object _memoryGate = new();
    private static readonly object _tlsGate = new();
    private static readonly Dictionary<ulong, DirectAllocation> _directAllocations = new();
    private static readonly Dictionary<ulong, LibcHeapAllocation> _libcAllocations = new();
    private static readonly Dictionary<ulong, MappedRegion> _mappedRegions = new();
    private static readonly Dictionary<ulong, ulong> _tlsModuleBlocks = new();
    private static long _nextFileDescriptor = 2;
    private static ulong _nextPhysicalAddress;
    private static ulong _nextVirtualAddress;
    private static ulong _allocatedFlexibleBytes;
    private static ulong _threadAtexitCountCallback;
    private static ulong _threadAtexitReportCallback;
    private static ulong _threadDtorsCallback;
    private static int _nullMemsetRecoveryCount;
    private static int _nonCanonicalMemsetRecoveryCount;
    private static int _inaccessibleMemsetRecoveryCount;
    private static int _hostMemoryWriteFallbackCount;
    private static int _hostMemoryReadFallbackCount;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nuint VirtualQuery(nint lpAddress, out MemoryBasicInformation lpBuffer, nuint dwLength);

    private sealed class OpenDirectory
    {
        public required string Path { get; init; }
        public required string[] Entries { get; init; }
        public int NextIndex { get; set; }
    }

    private readonly record struct DirectAllocation(ulong Start, ulong Length, int MemoryType);
    private readonly record struct LibcHeapAllocation(nint BaseAddress, nuint Size, nuint Alignment);
    private readonly record struct MappedRegion(ulong Address, ulong Length, int Protection, bool IsFlexible, ulong DirectStart);

    [SysAbiExport(
        Nid = "8zTFvBIAIN8",
        ExportName = "memset",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Memset(CpuContext ctx)
    {
        var destination = ctx[CpuRegister.Rdi];
        var value = (byte)(ctx[CpuRegister.Rsi] & 0xFF);
        var length = ctx[CpuRegister.Rdx];
        if (length == 0)
        {
            ctx[CpuRegister.Rax] = destination;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (destination == 0)
        {
            if (length <= 0x20)
            {
                var recoveryIndex = Interlocked.Increment(ref _nullMemsetRecoveryCount);
                if (recoveryIndex <= 8)
                {
                    Console.Error.WriteLine(
                        $"[LOADER][WARNING] memset null-dst recovery#{recoveryIndex}: rip=0x{ctx.Rip:X16} len=0x{length:X} val=0x{value:X2}");
                }

                ctx[CpuRegister.Rax] = 0;
                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }

            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        const ulong CanonicalUserUpper = 0x0000800000000000UL;
        if (destination >= CanonicalUserUpper && length <= 0x40)
        {
            var recoveryIndex = Interlocked.Increment(ref _nonCanonicalMemsetRecoveryCount);
            if (recoveryIndex <= 8)
            {
                Console.Error.WriteLine(
                    $"[LOADER][WARNING] memset non-canonical-dst recovery#{recoveryIndex}: rip=0x{ctx.Rip:X16} dst=0x{destination:X16} len=0x{length:X} val=0x{value:X2}");
            }

            ctx[CpuRegister.Rax] = destination;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        const ulong MaxSane = 512UL * 1024 * 1024;
        if (destination < 0x1000 || destination >= CanonicalUserUpper || length > MaxSane)
        {
            Console.WriteLine("!!! CRITICAL: Bad Memset Call !!!");
            Console.WriteLine($"Called from RIP: 0x{ctx.Rip:X}");
            Console.WriteLine($"dst=0x{destination:X} val=0x{value:X2} len=0x{length:X}");
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var chunk = new byte[MemsetChunkSize];
        Array.Fill(chunk, value);
        var remaining = length;
        var cursor = destination;
        while (remaining > 0)
        {
            var take = (int)Math.Min((ulong)chunk.Length, remaining);
            if (!TryWriteCompat(ctx, cursor, chunk.AsSpan(0, take)))
            {
                if (length <= 0x40)
                {
                    var recoveryIndex = Interlocked.Increment(ref _inaccessibleMemsetRecoveryCount);
                    if (recoveryIndex <= 8)
                    {
                        Console.Error.WriteLine(
                            $"[LOADER][WARNING] memset inaccessible-dst recovery#{recoveryIndex}: rip=0x{ctx.Rip:X16} dst=0x{destination:X16} len=0x{length:X} val=0x{value:X2}");
                    }

                    ctx[CpuRegister.Rax] = destination;
                    return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                }

                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
            }

            cursor += (ulong)take;
            remaining -= (ulong)take;
        }

        ctx[CpuRegister.Rax] = destination;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "j4ViWNHEgww",
        ExportName = "strlen",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Strlen(CpuContext ctx)
    {
        if (!TryReadCString(ctx, ctx[CpuRegister.Rdi], 1_048_576, out var bytes))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((ulong)bytes.Length);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "5jNubw4vlAA",
        ExportName = "strnlen",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Strnlen(CpuContext ctx)
    {
        var maxLength = ctx[CpuRegister.Rsi];
        if (!TryReadCString(ctx, ctx[CpuRegister.Rdi], maxLength, out var bytes))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((ulong)bytes.Length);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Ovb2dSJOAuE",
        ExportName = "strcmp",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Strcmp(CpuContext ctx)
    {
        var left = ctx[CpuRegister.Rdi];
        var right = ctx[CpuRegister.Rsi];
        if (!TryCompareStrings(ctx, left, right, limit: ulong.MaxValue, out var compare))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((ulong)compare);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "aesyjrHVWy4",
        ExportName = "strncmp",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Strncmp(CpuContext ctx)
    {
        var left = ctx[CpuRegister.Rdi];
        var right = ctx[CpuRegister.Rsi];
        var limit = ctx[CpuRegister.Rdx];
        if (!TryCompareStrings(ctx, left, right, limit, out var compare))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((ulong)compare);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "eLdDw6l0-bU",
        ExportName = "snprintf",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Snprintf(CpuContext ctx)
    {
        return SnprintfCore(ctx);
    }

    [SysAbiExport(
        Nid = "Q2V+iqvjgC0",
        ExportName = "vsnprintf",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Vsnprintf(CpuContext ctx)
    {
        return VsnprintfCore(ctx);
    }

    [SysAbiExport(
        Nid = "GMpvxPFW924",
        ExportName = "vprintf",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Vprintf(CpuContext ctx)
    {
        var formatAddress = ctx[CpuRegister.Rdi];
        var vaListAddress = ctx[CpuRegister.Rsi];
        if (!TryReadCString(ctx, formatAddress, 1_048_576, out var formatBytes))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var format = Encoding.UTF8.GetString(formatBytes);
        string rendered;
        if (!TryCreateVaListCursor(ctx, vaListAddress, out var vaCursor))
        {
            rendered = format;
        }
        else
        {
            ulong NextGpArg() => vaCursor.NextGpArg();
            double NextFloatArg() => vaCursor.NextFloatArg();
            rendered = FormatString(ctx, format, NextGpArg, NextFloatArg);
            vaCursor.Commit();
        }

        Console.Write(rendered);
        ctx[CpuRegister.Rax] = unchecked((ulong)Encoding.UTF8.GetByteCount(rendered));
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "kiZSXIWd9vg",
        ExportName = "strcpy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Strcpy(CpuContext ctx)
    {
        var destination = ctx[CpuRegister.Rdi];
        var source = ctx[CpuRegister.Rsi];
        if (!TryReadCString(ctx, source, 1_048_576, out var bytes))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var payload = new byte[bytes.Length + 1];
        bytes.CopyTo(payload.AsSpan());
        if (!TryWriteCompat(ctx, destination, payload))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = destination;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "6sJWiWSRuqk",
        ExportName = "strncpy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Strncpy(CpuContext ctx)
    {
        var destination = ctx[CpuRegister.Rdi];
        var source = ctx[CpuRegister.Rsi];
        var count = (int)Math.Min(ctx[CpuRegister.Rdx], int.MaxValue);
        if (count < 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var payload = new byte[count];
        Span<byte> one = stackalloc byte[1];
        var copied = 0;
        while (copied < count)
        {
            if (!TryReadCompat(ctx, source + (ulong)copied, one))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
            }

            payload[copied] = one[0];
            copied++;
            if (one[0] == 0)
            {
                break;
            }
        }

        if (!TryWriteCompat(ctx, destination, payload))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = destination;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Q3VBxCXhUHs",
        ExportName = "memcpy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Memcpy(CpuContext ctx)
    {
        var destination = ctx[CpuRegister.Rdi];
        var source = ctx[CpuRegister.Rsi];
        var count = (int)Math.Min(ctx[CpuRegister.Rdx], int.MaxValue);
        if (count < 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var payload = GC.AllocateUninitializedArray<byte>(count);
        if (count > 0 && (!TryReadCompat(ctx, source, payload) || !TryWriteCompat(ctx, destination, payload)))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = destination;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "+P6FRGH4LfA",
        ExportName = "memmove",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Memmove(CpuContext ctx)
    {
        return Memcpy(ctx);
    }

    [SysAbiExport(
        Nid = "gQX+4GDQjpM",
        ExportName = "malloc",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Malloc(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] =
            TryAllocateLibcHeap(ctx[CpuRegister.Rdi], DefaultLibcHeapAlignment, zeroFill: false, out var address)
                ? address
                : 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "tIhsqj0qsFE",
        ExportName = "free",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Free(CpuContext ctx)
    {
        FreeLibcHeap(ctx[CpuRegister.Rdi]);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "2X5agFjKxMc",
        ExportName = "calloc",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Calloc(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] =
            TryMultiplyAllocationSize(ctx[CpuRegister.Rdi], ctx[CpuRegister.Rsi], out var totalSize) &&
            TryAllocateLibcHeapCore(totalSize, DefaultLibcHeapAlignment, zeroFill: true, out var address)
                ? address
                : 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Y7aJ1uydPMo",
        ExportName = "realloc",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Realloc(CpuContext ctx)
    {
        var existingAddress = ctx[CpuRegister.Rdi];
        var requestedSize = ctx[CpuRegister.Rsi];

        if (existingAddress == 0)
        {
            ctx[CpuRegister.Rax] =
                TryAllocateLibcHeap(requestedSize, DefaultLibcHeapAlignment, zeroFill: false, out var freshAddress)
                    ? freshAddress
                    : 0;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (requestedSize == 0)
        {
            FreeLibcHeap(existingAddress);
            ctx[CpuRegister.Rax] = 0;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        ctx[CpuRegister.Rax] =
            TryReallocateLibcHeap(existingAddress, requestedSize, out var resizedAddress)
                ? resizedAddress
                : 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Ujf3KzMvRmI",
        ExportName = "memalign",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Memalign(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] =
            TryAllocateAlignedLibcHeap(
                alignmentValue: ctx[CpuRegister.Rdi],
                requestedSize: ctx[CpuRegister.Rsi],
                requireSizeMultiple: false,
                out var address)
                ? address
                : 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "2Btkg8k24Zg",
        ExportName = "aligned_alloc",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int AlignedAlloc(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] =
            TryAllocateAlignedLibcHeap(
                alignmentValue: ctx[CpuRegister.Rdi],
                requestedSize: ctx[CpuRegister.Rsi],
                requireSizeMultiple: true,
                out var address)
                ? address
                : 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "cVSk9y8URbc",
        ExportName = "posix_memalign",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int PosixMemalign(CpuContext ctx)
    {
        var outPointerAddress = ctx[CpuRegister.Rdi];
        if (outPointerAddress == 0)
        {
            ctx[CpuRegister.Rax] = Einval;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (!TryValidateAlignedAllocation(
                ctx[CpuRegister.Rsi],
                ctx[CpuRegister.Rdx],
                requireSizeMultiple: false,
                requirePointerSizedAlignment: true,
                out var alignment,
                out var requestedSize))
        {
            _ = TryWriteUInt64Compat(ctx, outPointerAddress, 0);
            ctx[CpuRegister.Rax] = Einval;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (!TryAllocateLibcHeapCore(requestedSize, alignment, zeroFill: false, out var address))
        {
            _ = TryWriteUInt64Compat(ctx, outPointerAddress, 0);
            ctx[CpuRegister.Rax] = Enomem;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (!TryWriteUInt64Compat(ctx, outPointerAddress, address))
        {
            FreeLibcHeap(address);
            ctx[CpuRegister.Rax] = Einval;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "DfivPArhucg",
        ExportName = "memcmp",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Memcmp(CpuContext ctx)
    {
        var left = ctx[CpuRegister.Rdi];
        var right = ctx[CpuRegister.Rsi];
        var count = (int)Math.Min(ctx[CpuRegister.Rdx], int.MaxValue);
        if (count < 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        Span<byte> leftByte = stackalloc byte[1];
        Span<byte> rightByte = stackalloc byte[1];
        for (var i = 0; i < count; i++)
        {
            if (!TryReadCompat(ctx, left + (ulong)i, leftByte) ||
                !TryReadCompat(ctx, right + (ulong)i, rightByte))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
            }

            var diff = leftByte[0] - rightByte[0];
            if (diff != 0)
            {
                ctx[CpuRegister.Rax] = unchecked((ulong)diff);
                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "QrZZdJ8XsX0",
        ExportName = "fputs",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Fputs(CpuContext ctx)
    {
        var textAddress = ctx[CpuRegister.Rdi];
        var stream = ctx[CpuRegister.Rsi];
        if (textAddress == 0)
        {
            ctx[CpuRegister.Rax] = unchecked((ulong)(-1L));
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryReadNullTerminatedUtf8(ctx, textAddress, MaxGuestStringLength, out var text))
        {
            ctx[CpuRegister.Rax] = unchecked((ulong)(-1L));
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        if (stream == 0)
        {
            Console.Error.Write(text);
            Console.Error.Flush();
        }
        else
        {
            Console.Out.Write(text);
            Console.Out.Flush();
        }

        ctx[CpuRegister.Rax] = unchecked((ulong)text.Length);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "6c3rCVE-fTU",
        ExportName = "_open",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelOpenUnderscore(CpuContext ctx)
    {
        var pathAddress = ctx[CpuRegister.Rdi];
        var flags = unchecked((int)ctx[CpuRegister.Rsi]);
        if (!TryReadNullTerminatedUtf8(ctx, pathAddress, MaxGuestStringLength, out var guestPath))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var hostPath = ResolveGuestPath(guestPath);
        var access = ResolveOpenAccess(flags);
        var mode = ResolveOpenMode(flags, access);
        try
        {
            var stream = new FileStream(hostPath, mode, access, FileShare.ReadWrite);
            if ((flags & O_APPEND) != 0)
            {
                stream.Seek(0, SeekOrigin.End);
            }

            var fd = (int)Interlocked.Increment(ref _nextFileDescriptor);
            lock (_fdGate)
            {
                _openFiles[fd] = stream;
            }

            ctx[CpuRegister.Rax] = unchecked((ulong)fd);
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }
        catch (IOException)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }
        catch (UnauthorizedAccessException)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }
    }

    [SysAbiExport(
        Nid = "NNtFaKJbPt0",
        ExportName = "_close",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelCloseUnderscore(CpuContext ctx)
    {
        var fd = unchecked((int)ctx[CpuRegister.Rdi]);
        if (fd is 0 or 1 or 2)
        {
            ctx[CpuRegister.Rax] = 0;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        FileStream? stream;
        lock (_fdGate)
        {
            if (!_openFiles.Remove(fd, out stream))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }
        }

        stream.Dispose();
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "DRuBt2pvICk",
        ExportName = "_read",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelReadUnderscore(CpuContext ctx)
    {
        var fd = unchecked((int)ctx[CpuRegister.Rdi]);
        var bufferAddress = ctx[CpuRegister.Rsi];
        var requested = (int)Math.Min(ctx[CpuRegister.Rdx], int.MaxValue);
        if (requested < 0 || (requested > 0 && bufferAddress == 0))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (requested == 0 || fd == 0)
        {
            ctx[CpuRegister.Rax] = 0;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        FileStream? stream;
        lock (_fdGate)
        {
            _openFiles.TryGetValue(fd, out stream);
        }

        if (stream is null)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var buffer = GC.AllocateUninitializedArray<byte>(requested);
        var read = stream.Read(buffer, 0, requested);
        if (read > 0 && !ctx.Memory.TryWrite(bufferAddress, buffer.AsSpan(0, read)))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((ulong)read);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "FxVZqBAA7ks",
        ExportName = "_write",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelWriteUnderscore(CpuContext ctx)
    {
        var fd = unchecked((int)ctx[CpuRegister.Rdi]);
        var bufferAddress = ctx[CpuRegister.Rsi];
        var requested = (int)Math.Min(ctx[CpuRegister.Rdx], int.MaxValue);
        if (requested < 0 || (requested > 0 && bufferAddress == 0))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var payload = requested == 0
            ? Array.Empty<byte>()
            : GC.AllocateUninitializedArray<byte>(requested);
        if (requested > 0 && !ctx.Memory.TryRead(bufferAddress, payload))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        if (fd == 1 || fd == 2)
        {
            var text = Encoding.UTF8.GetString(payload);
            if (fd == 1)
            {
                Console.Out.Write(text);
                Console.Out.Flush();
            }
            else
            {
                Console.Error.Write(text);
                Console.Error.Flush();
            }

            ctx[CpuRegister.Rax] = unchecked((ulong)requested);
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        FileStream? stream;
        lock (_fdGate)
        {
            _openFiles.TryGetValue(fd, out stream);
        }

        if (stream is null)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        stream.Write(payload, 0, requested);
        stream.Flush();
        ctx[CpuRegister.Rax] = unchecked((ulong)requested);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "lLMT9vJAck0",
        ExportName = "clock_gettime",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int ClockGettime(CpuContext ctx)
    {
        var timespecAddress = ctx[CpuRegister.Rsi];
        if (timespecAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var now = DateTimeOffset.UtcNow;
        var seconds = now.ToUnixTimeSeconds();
        var nanoseconds = (now.Ticks % TimeSpan.TicksPerSecond) * 100;
        if (!ctx.TryWriteUInt64(timespecAddress, unchecked((ulong)seconds)) ||
            !ctx.TryWriteUInt64(timespecAddress + sizeof(long), unchecked((ulong)nanoseconds)))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "vNe1w4diLCs",
        ExportName = "__tls_get_addr",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int TlsGetAddr(CpuContext ctx)
    {
        var tlsInfoAddress = ctx[CpuRegister.Rdi];
        if (tlsInfoAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!ctx.TryReadUInt64(tlsInfoAddress, out var moduleId) ||
            !ctx.TryReadUInt64(tlsInfoAddress + sizeof(ulong), out var offset))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = ResolveTlsAddress(ctx, moduleId, offset);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static ulong ResolveTlsAddress(CpuContext ctx, ulong moduleId, ulong offset)
    {
        if (ctx.FsBase == 0)
        {
            return 0;
        }

        if (moduleId <= 1)
        {
            return unchecked(ctx.FsBase + offset);
        }

        var key = (ctx.FsBase << 16) ^ (moduleId & 0xFFFFUL);
        ulong moduleBase;
        lock (_tlsGate)
        {
            if (!_tlsModuleBlocks.TryGetValue(key, out moduleBase))
            {
                var block = Marshal.AllocHGlobal(TlsModuleBlockSize);
                Marshal.Copy(new byte[TlsModuleBlockSize], 0, block, TlsModuleBlockSize);

                moduleBase = unchecked((ulong)block);
                _tlsModuleBlocks[key] = moduleBase;
            }
        }

        return unchecked(moduleBase + offset);
    }

    [SysAbiExport(
        Nid = "pB-yGZ2nQ9o",
        ExportName = "_sceKernelSetThreadAtexitCount",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelSetThreadAtexitCount(CpuContext ctx)
    {
        _threadAtexitCountCallback = ctx[CpuRegister.Rdi];
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "WhCc1w3EhSI",
        ExportName = "_sceKernelSetThreadAtexitReport",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelSetThreadAtexitReport(CpuContext ctx)
    {
        _threadAtexitReportCallback = ctx[CpuRegister.Rdi];
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "rNhWz+lvOMU",
        ExportName = "_sceKernelSetThreadDtors",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelSetThreadDtors(CpuContext ctx)
    {
        _threadDtorsCallback = ctx[CpuRegister.Rdi];
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Tz4RNUCBbGI",
        ExportName = "_sceKernelRtldThreadAtexitIncrement",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelRtldThreadAtexitIncrement(CpuContext ctx)
    {
        return KernelRtldThreadAtexitAdjust(ctx, delta: +1);
    }

    [SysAbiExport(
        Nid = "8OnWXlgQlvo",
        ExportName = "_sceKernelRtldThreadAtexitDecrement",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelRtldThreadAtexitDecrement(CpuContext ctx)
    {
        return KernelRtldThreadAtexitAdjust(ctx, delta: -1);
    }

    [SysAbiExport(
        Nid = "pO96TwzOm5E",
        ExportName = "sceKernelGetDirectMemorySize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelGetDirectMemorySize(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] = DirectMemorySizeBytes;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "C0f7TJcbfac",
        ExportName = "sceKernelAvailableDirectMemorySize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAvailableDirectMemorySize(CpuContext ctx)
    {
        var arg0 = ctx[CpuRegister.Rdi];
        var arg1 = ctx[CpuRegister.Rsi];
        var arg2 = ctx[CpuRegister.Rdx];
        var arg3 = ctx[CpuRegister.Rcx];
        var arg4 = ctx[CpuRegister.R8];

        ulong used = 0;
        lock (_memoryGate)
        {
            foreach (var allocation in _directAllocations.Values)
            {
                used = Math.Min(DirectMemorySizeBytes, used + allocation.Length);
            }
        }

        var totalAvailable = used >= DirectMemorySizeBytes
            ? 0UL
            : DirectMemorySizeBytes - used;

        if (arg1 != 0 || arg2 != 0 || arg3 != 0 || arg4 != 0)
        {
            var searchStartRaw = unchecked((long)arg0);
            var searchEndRaw = unchecked((long)arg1);
            var alignment = arg2 == 0 ? 0x1000UL : arg2;
            var outAddress = arg3;
            var outSize = arg4;
            if (outAddress == 0 || outSize == 0)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
            }

            var searchStart = searchStartRaw < 0 ? 0UL : (ulong)searchStartRaw;
            var searchEnd = searchEndRaw <= 0
                ? DirectMemorySizeBytes
                : Math.Min((ulong)searchEndRaw, DirectMemorySizeBytes);
            if (searchStart >= searchEnd)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
            }

            var candidate = AlignUp(Math.Max(searchStart, _nextPhysicalAddress), alignment);
            if (candidate >= searchEnd)
            {
                candidate = AlignUp(searchStart, alignment);
                if (candidate >= searchEnd)
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
                }
            }

            var rangeAvailable = searchEnd - candidate;
            if (!ctx.TryWriteUInt64(outAddress, candidate) || !ctx.TryWriteUInt64(outSize, rangeAvailable))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
            }

            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        var outSizeAddress = arg0;
        if (outSizeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!ctx.TryWriteUInt64(outSizeAddress, totalAvailable))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "aNz11fnnzi4",
        ExportName = "sceKernelAvailableFlexibleMemorySize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAvailableFlexibleMemorySize(CpuContext ctx)
    {
        var outSizeAddress = ctx[CpuRegister.Rdi];
        if (outSizeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        ulong available;
        lock (_memoryGate)
        {
            available = _allocatedFlexibleBytes >= FlexibleMemorySizeBytes
                ? 0
                : FlexibleMemorySizeBytes - _allocatedFlexibleBytes;
        }

        if (!ctx.TryWriteUInt64(outSizeAddress, available))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "rTXw65xmLIA",
        ExportName = "sceKernelAllocateDirectMemory",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAllocateDirectMemory(CpuContext ctx)
    {
        var searchStartRaw = unchecked((long)ctx[CpuRegister.Rdi]);
        var searchEndRaw = unchecked((long)ctx[CpuRegister.Rsi]);
        var length = ctx[CpuRegister.Rdx];
        var alignment = ctx[CpuRegister.Rcx];
        var memoryType = unchecked((int)ctx[CpuRegister.R8]);
        var outAddress = ctx[CpuRegister.R9];

        if (length == 0 || outAddress == 0)
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;

        var limit = DirectMemorySizeBytes;
        ulong searchStart;
        ulong searchEnd;

        if (searchEndRaw <= 0)
        {
            searchEnd = limit;
        }
        else
        {
            searchEnd = (ulong)searchEndRaw;
            if (searchEnd > limit)
            {
                searchEnd = limit;
            }
        }

        if (searchStartRaw < 0)
        {
            searchStart = 0;
        }
        else
        {
            searchStart = (ulong)searchStartRaw;
        }

        if (searchStart >= searchEnd)
        {
            searchStart = 0;
        }

        var align = alignment == 0 ? 0x1000UL : alignment;
        var alignedStart = AlignUp(searchStart, align);

        ulong selectedAddress;
        lock (_memoryGate)
        {
            selectedAddress = AlignUp(Math.Max(alignedStart, _nextPhysicalAddress), align);

            if (!TryAdd(selectedAddress, length, out var endAddr) ||
                endAddr > searchEnd ||
                endAddr > limit)
            {
                selectedAddress = alignedStart;

                if (!TryAdd(selectedAddress, length, out endAddr) ||
                    endAddr > searchEnd ||
                    endAddr > limit)
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
                }
            }

            _directAllocations[selectedAddress] = new DirectAllocation(selectedAddress, length, memoryType);
            _nextPhysicalAddress = selectedAddress + length;
        }

        if (!ctx.TryWriteUInt64(outAddress, selectedAddress))
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;

        static bool TryAdd(ulong a, ulong b, out ulong sum)
        {
            sum = a + b;
            return sum >= a;
        }
    }

    [SysAbiExport(
        Nid = "B+vc2AO2Zrc",
        ExportName = "sceKernelAllocateMainDirectMemory",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAllocateMainDirectMemory(CpuContext ctx)
    {
        var length = ctx[CpuRegister.Rdi];
        var alignment = ctx[CpuRegister.Rsi];
        var memoryType = unchecked((int)ctx[CpuRegister.Rdx]);
        var outAddress = ctx[CpuRegister.Rcx];
        if (outAddress == 0 || length == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var aligned = AlignUp(_nextPhysicalAddress, alignment == 0 ? 0x1000UL : alignment);
        lock (_memoryGate)
        {
            if (aligned + length > DirectMemorySizeBytes)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }

            _directAllocations[aligned] = new DirectAllocation(aligned, length, memoryType);
            _nextPhysicalAddress = aligned + length;
        }

        if (!ctx.TryWriteUInt64(outAddress, aligned))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "MBuItvba6z8",
        ExportName = "sceKernelReleaseDirectMemory",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelReleaseDirectMemory(CpuContext ctx)
    {
        var start = ctx[CpuRegister.Rdi];
        var length = ctx[CpuRegister.Rsi];
        if (length == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_memoryGate)
        {
            if (!_directAllocations.TryGetValue(start, out var allocation) || allocation.Length != length)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }

            _directAllocations.Remove(start);
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "L-Q3LEjIbgA",
        ExportName = "sceKernelMapDirectMemory",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelMapDirectMemory(CpuContext ctx)
    {
        var inOutAddressPointer = ctx[CpuRegister.Rdi];
        var length = ctx[CpuRegister.Rsi];
        var protection = unchecked((int)ctx[CpuRegister.Rdx]);
        var flags = ctx[CpuRegister.Rcx];
        var directMemoryStart = ctx[CpuRegister.R8];
        var alignment = ctx[CpuRegister.R9];
        Console.Error.WriteLine(
            $"[LOADER][TRACE] map_direct: inout=0x{inOutAddressPointer:X16} len=0x{length:X16} prot=0x{protection:X8} flags=0x{flags:X16} direct=0x{directMemoryStart:X16} align=0x{alignment:X16}");
        if (inOutAddressPointer == 0 || length == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!ctx.TryReadUInt64(inOutAddressPointer, out var requestedAddress))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ulong mappedAddress;
        lock (_memoryGate)
        {
            var effectiveAlignment = alignment == 0 ? 0x1000UL : alignment;
            var fixedMapping = (flags & 0x10UL) != 0;
            var desiredAddress = requestedAddress != 0
                ? requestedAddress
                : directMemoryStart != 0
                    ? AlignUp(directMemoryStart, effectiveAlignment)
                    : AlignUp(_nextVirtualAddress == 0 ? 0x1_0000_0000UL : _nextVirtualAddress, effectiveAlignment);

            var reserved = false;
            if (fixedMapping && requestedAddress != 0)
            {
                mappedAddress = requestedAddress;
            }
            else
            {
                reserved = TryReserveGuestVirtualRange(ctx, desiredAddress, length, protection, out mappedAddress);
            }
            Console.Error.WriteLine(
                $"[LOADER][TRACE] map_direct reserve: requested=0x{requestedAddress:X16} desired=0x{desiredAddress:X16} reserved={reserved} mapped=0x{mappedAddress:X16}");
            if (!reserved)
            {
                if (mappedAddress == 0)
                {
                    mappedAddress = requestedAddress != 0
                        ? requestedAddress
                        : AllocateMappedGuestAddress(ctx, length, effectiveAlignment);
                    Console.Error.WriteLine($"[LOADER][TRACE] map_direct fallback mapped=0x{mappedAddress:X16}");
                }
            }

            if (mappedAddress == 0)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }

            _nextVirtualAddress = Math.Max(_nextVirtualAddress, mappedAddress + length);
            _mappedRegions[mappedAddress] = new MappedRegion(mappedAddress, length, protection, IsFlexible: false, DirectStart: directMemoryStart);
        }

        if (!ctx.TryWriteUInt64(inOutAddressPointer, mappedAddress))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "NcaWUxfMNIQ",
        ExportName = "sceKernelMapNamedDirectMemory",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelMapNamedDirectMemory(CpuContext ctx)
    {
        return KernelMapDirectMemory(ctx);
    }

    [SysAbiExport(
        Nid = "mL8NDH86iQI",
        ExportName = "sceKernelMapNamedFlexibleMemory",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelMapNamedFlexibleMemory(CpuContext ctx)
    {
        var inOutAddressPointer = ctx[CpuRegister.Rdi];
        var length = ctx[CpuRegister.Rsi];
        var protection = unchecked((int)ctx[CpuRegister.Rdx]);
        var flags = ctx[CpuRegister.Rcx];
        Console.Error.WriteLine(
            $"[LOADER][TRACE] map_flexible: inout=0x{inOutAddressPointer:X16} len=0x{length:X16} prot=0x{protection:X8} flags=0x{flags:X16}");
        if (inOutAddressPointer == 0 || length == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!ctx.TryReadUInt64(inOutAddressPointer, out var requestedAddress))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ulong mappedAddress;
        lock (_memoryGate)
        {
            var fixedMapping = (flags & 0x10UL) != 0;
            var desiredAddress = requestedAddress != 0
                ? requestedAddress
                : AlignUp(_nextVirtualAddress == 0 ? 0x1_0000_0000UL : _nextVirtualAddress, 0x1000UL);

            if (fixedMapping && requestedAddress != 0)
            {
                mappedAddress = requestedAddress;
            }
            else if (!TryReserveGuestVirtualRange(ctx, desiredAddress, length, protection, out mappedAddress))
            {
                mappedAddress = requestedAddress != 0 && fixedMapping
                    ? requestedAddress
                    : AllocateMappedGuestAddress(ctx, length, 0x1000UL);
            }

            Console.Error.WriteLine(
                $"[LOADER][TRACE] map_flexible reserve: requested=0x{requestedAddress:X16} desired=0x{desiredAddress:X16} mapped=0x{mappedAddress:X16}");

            if (mappedAddress == 0)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }

            _nextVirtualAddress = Math.Max(_nextVirtualAddress, mappedAddress + length);
            _allocatedFlexibleBytes = Math.Min(FlexibleMemorySizeBytes, _allocatedFlexibleBytes + length);
            _mappedRegions[mappedAddress] = new MappedRegion(mappedAddress, length, protection, IsFlexible: true, DirectStart: 0);
        }

        if (!ctx.TryWriteUInt64(inOutAddressPointer, mappedAddress))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "IWIBBdTHit4",
        ExportName = "sceKernelMapFlexibleMemory",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelMapFlexibleMemory(CpuContext ctx)
    {
        return KernelMapNamedFlexibleMemory(ctx);
    }

    [SysAbiExport(
        Nid = "cQke9UuBQOk",
        ExportName = "sceKernelMunmap",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelMunmap(CpuContext ctx)
    {
        var address = ctx[CpuRegister.Rdi];
        var length = ctx[CpuRegister.Rsi];
        if (address == 0 || length == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_memoryGate)
        {
            if (!_mappedRegions.TryGetValue(address, out var mappedRegion) || mappedRegion.Length != length)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }

            _mappedRegions.Remove(address);
            if (mappedRegion.IsFlexible)
            {
                _allocatedFlexibleBytes = mappedRegion.Length >= _allocatedFlexibleBytes
                    ? 0
                    : _allocatedFlexibleBytes - mappedRegion.Length;
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "WFcfL2lzido",
        ExportName = "sceKernelQueryMemoryProtection",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelQueryMemoryProtection(CpuContext ctx)
    {
        var queryAddress = ctx[CpuRegister.Rdi];
        var startOut = ctx[CpuRegister.Rsi];
        var endOut = ctx[CpuRegister.Rdx];
        var protectionOut = ctx[CpuRegister.Rcx];

        lock (_memoryGate)
        {
            foreach (var region in _mappedRegions.Values)
            {
                if (queryAddress < region.Address || queryAddress >= region.Address + region.Length)
                {
                    continue;
                }

                if (startOut != 0 && !ctx.TryWriteUInt64(startOut, region.Address))
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
                }

                if (endOut != 0 && !ctx.TryWriteUInt64(endOut, region.Address + region.Length - 1))
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
                }

                if (protectionOut != 0 && !TryWriteInt32(ctx, protectionOut, region.Protection))
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
                }

                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "BHouLQzh0X0",
        ExportName = "sceKernelDirectMemoryQuery",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelDirectMemoryQuery(CpuContext ctx)
    {
        var offset = ctx[CpuRegister.Rdi];
        _ = ctx[CpuRegister.Rsi]; // flags
        var infoAddress = ctx[CpuRegister.Rdx];
        var infoSize = ctx[CpuRegister.Rcx];
        if (infoAddress == 0 || infoSize < 24)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_memoryGate)
        {
            foreach (var block in _directAllocations.Values)
            {
                if (offset < block.Start || offset >= block.Start + block.Length)
                {
                    continue;
                }

                if (!ctx.TryWriteUInt64(infoAddress, block.Start) ||
                    !ctx.TryWriteUInt64(infoAddress + sizeof(ulong), block.Start + block.Length) ||
                    !TryWriteInt32(ctx, infoAddress + (sizeof(ulong) * 2), block.MemoryType))
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
                }

                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "vSMAm3cxYTY",
        ExportName = "sceKernelMprotect",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelMprotect(CpuContext ctx)
    {
        var address = ctx[CpuRegister.Rdi];
        var length = ctx[CpuRegister.Rsi];
        var protection = unchecked((int)ctx[CpuRegister.Rdx]);
        if (address == 0 || length == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_memoryGate)
        {
            if (!_mappedRegions.TryGetValue(address, out var region) || region.Length != length)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
            }

            _mappedRegions[address] = region with { Protection = protection };
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int KernelRtldThreadAtexitAdjust(CpuContext ctx, int delta)
    {
        var counterAddress = ctx[CpuRegister.Rdi];
        if (counterAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!ctx.TryReadUInt64(counterAddress, out var value))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var adjusted = delta >= 0
            ? unchecked(value + (ulong)delta)
            : value >= (ulong)(-delta)
                ? unchecked(value - (ulong)(-delta))
                : 0UL;
        if (!ctx.TryWriteUInt64(counterAddress, adjusted))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = adjusted;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static int SnprintfCore(CpuContext ctx)
    {
        var destination = ctx[CpuRegister.Rdi];
        var bufferSize = ctx[CpuRegister.Rsi];
        var formatAddress = ctx[CpuRegister.Rdx];

        if (!TryReadCString(ctx, formatAddress, 1_048_576, out var formatBytes))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var format = Encoding.UTF8.GetString(formatBytes);
        var result = FormatString(ctx, format);
        var outputBytes = Encoding.UTF8.GetBytes(result);

        return WriteSnprintfOutput(ctx, destination, bufferSize, outputBytes);
    }

    private static int VsnprintfCore(CpuContext ctx)
    {
        var destination = ctx[CpuRegister.Rdi];
        var bufferSize = ctx[CpuRegister.Rsi];
        var formatAddress = ctx[CpuRegister.Rdx];
        var vaListAddress = ctx[CpuRegister.Rcx];

        if (!TryReadCString(ctx, formatAddress, 1_048_576, out var formatBytes))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var format = Encoding.UTF8.GetString(formatBytes);
        if (!TryCreateVaListCursor(ctx, vaListAddress, out var vaCursor))
        {
            return WriteSnprintfOutput(ctx, destination, bufferSize, formatBytes);
        }

        ulong NextGpArg() => vaCursor.NextGpArg();
        double NextFloatArg() => vaCursor.NextFloatArg();
        var rendered = FormatString(ctx, format, NextGpArg, NextFloatArg);
        vaCursor.Commit();

        var outputBytes = Encoding.UTF8.GetBytes(rendered);
        return WriteSnprintfOutput(ctx, destination, bufferSize, outputBytes);
    }

    private static bool TryCreateVaListCursor(CpuContext ctx, ulong vaListAddress, out SysVAmd64VaListCursor cursor)
    {
        cursor = default;
        if (vaListAddress == 0)
        {
            return false;
        }

        if (!TryReadUInt32Compat(ctx, vaListAddress + 0, out var gpOffset) ||
            !TryReadUInt32Compat(ctx, vaListAddress + 4, out var fpOffset) ||
            !TryReadUInt64Compat(ctx, vaListAddress + 8, out var overflowArgArea) ||
            !TryReadUInt64Compat(ctx, vaListAddress + 16, out var regSaveArea))
        {
            return false;
        }

        cursor = new SysVAmd64VaListCursor(
            ctx,
            vaListAddress,
            gpOffset,
            fpOffset,
            overflowArgArea,
            regSaveArea);
        return true;
    }

    private static int WriteSnprintfOutput(
        CpuContext ctx,
        ulong destination,
        ulong bufferSize,
        ReadOnlySpan<byte> outputBytes)
    {
        if (bufferSize != 0 && destination != 0)
        {
            var maxWritable = (int)Math.Min((ulong)int.MaxValue, bufferSize - 1);
            var copyLength = Math.Min(maxWritable, outputBytes.Length);
            if (copyLength > 0 && !ctx.Memory.TryWrite(destination, outputBytes[..copyLength]))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
            }

            Span<byte> nullTerminator = stackalloc byte[1];
            if (!ctx.Memory.TryWrite(destination + (ulong)copyLength, nullTerminator))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
            }
        }

        ctx[CpuRegister.Rax] = unchecked((ulong)outputBytes.Length);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static string FormatString(CpuContext ctx, string format)
    {
        var gpIndex = 3; // RDI, RSI, RDX used by snprintf itself, args start at RCX (index 3)

        ulong GetGpArg(int index)
        {
            return index switch
            {
                0 => ctx[CpuRegister.Rdi],
                1 => ctx[CpuRegister.Rsi],
                2 => ctx[CpuRegister.Rdx],
                3 => ctx[CpuRegister.Rcx],
                4 => ctx[CpuRegister.R8],
                5 => ctx[CpuRegister.R9],
                _ => ReadStackArg(ctx, (ulong)(index - 6) * 8)
            };
        }

        ulong NextGpArg() => GetGpArg(gpIndex++);
        double NextFloatArg()
        {
            var rawBits = NextGpArg();
            return BitConverter.Int64BitsToDouble(unchecked((long)rawBits));
        }

        return FormatString(ctx, format, NextGpArg, NextFloatArg);
    }

    private static string FormatString(
        CpuContext ctx,
        string format,
        Func<ulong> nextGpArg,
        Func<double> nextFloatArg)
    {
        var sb = new StringBuilder();

        for (var i = 0; i < format.Length; i++)
        {
            if (format[i] != '%')
            {
                sb.Append(format[i]);
                continue;
            }

            i++;
            if (i >= format.Length)
            {
                sb.Append('%');
                break;
            }

            var leftAlign = false;
            var showSign = false;
            var spaceForSign = false;
            var padWithZero = false;
            var alternateForm = false;

            while (i < format.Length)
            {
                switch (format[i])
                {
                    case '-': leftAlign = true; i++; continue;
                    case '+': showSign = true; i++; continue;
                    case ' ': spaceForSign = true; i++; continue;
                    case '0': padWithZero = true; i++; continue;
                    case '#': alternateForm = true; i++; continue;
                }
                break;
            }

            var width = 0;
            if (i < format.Length && format[i] == '*')
            {
                width = unchecked((int)nextGpArg());
                i++;
                if (width < 0)
                {
                    leftAlign = true;
                    width = -width;
                }
            }
            else if (i < format.Length && char.IsDigit(format[i]))
            {
                while (i < format.Length && char.IsDigit(format[i]))
                {
                    width = width * 10 + (format[i] - '0');
                    i++;
                }
            }

            var precision = -1;
            if (i < format.Length && format[i] == '.')
            {
                i++;
                if (i < format.Length && format[i] == '*')
                {
                    precision = unchecked((int)nextGpArg());
                    i++;
                }
                else if (i < format.Length && char.IsDigit(format[i]))
                {
                    precision = 0;
                    while (i < format.Length && char.IsDigit(format[i]))
                    {
                        precision = precision * 10 + (format[i] - '0');
                        i++;
                    }
                }
                else
                {
                    precision = 0;
                }
            }

            var lengthMod = "";
            if (i < format.Length)
            {
                if (i + 1 < format.Length &&
                    ((format[i] == 'h' && format[i + 1] == 'h') ||
                     (format[i] == 'l' && format[i + 1] == 'l')))
                {
                    lengthMod = format.Substring(i, 2);
                    i += 2;
                }
                else if (format[i] is 'h' or 'l' or 'j' or 'z' or 't' or 'L')
                {
                    lengthMod = format[i].ToString();
                    i++;
                }
            }

            if (i >= format.Length)
            {
                sb.Append('%');
                break;
            }

            var specifier = format[i];

            switch (specifier)
            {
                case '%':
                    sb.Append('%');
                    break;

                case 'd':
                case 'i':
                    {
                        long value = lengthMod switch
                        {
                            "hh" => unchecked((sbyte)nextGpArg()),
                            "h" => unchecked((short)nextGpArg()),
                            "l" => unchecked((long)nextGpArg()),
                            "ll" => unchecked((long)nextGpArg()),
                            "j" => unchecked((long)nextGpArg()),
                            "z" => unchecked((long)nextGpArg()),
                            "t" => unchecked((long)nextGpArg()),
                            _ => unchecked((int)nextGpArg())
                        };

                        var formatted = value.ToString();
                        if (showSign && value >= 0)
                            formatted = "+" + formatted;
                        else if (spaceForSign && value >= 0)
                            formatted = " " + formatted;

                        sb.Append(PadString(formatted, width, leftAlign, padWithZero && !leftAlign));
                    }
                    break;

                case 'u':
                    {
                        ulong value = lengthMod switch
                        {
                            "hh" => (byte)nextGpArg(),
                            "h" => (ushort)nextGpArg(),
                            "l" => nextGpArg(),
                            "ll" => nextGpArg(),
                            "j" => nextGpArg(),
                            "z" => nextGpArg(),
                            "t" => nextGpArg(),
                            _ => (uint)nextGpArg()
                        };

                        var formatted = value.ToString();
                        sb.Append(PadString(formatted, width, leftAlign, padWithZero && !leftAlign));
                    }
                    break;

                case 'x':
                case 'X':
                    {
                        ulong value = lengthMod switch
                        {
                            "hh" => (byte)nextGpArg(),
                            "h" => (ushort)nextGpArg(),
                            "l" => nextGpArg(),
                            "ll" => nextGpArg(),
                            "j" => nextGpArg(),
                            "z" => nextGpArg(),
                            "t" => nextGpArg(),
                            _ => (uint)nextGpArg()
                        };

                        var formatted = specifier == 'x'
                            ? value.ToString("x")
                            : value.ToString("X");

                        if (alternateForm && value != 0)
                            formatted = specifier == 'x' ? "0x" + formatted : "0X" + formatted;

                        sb.Append(PadString(formatted, width, leftAlign, padWithZero && !leftAlign));
                    }
                    break;

                case 'o':
                    {
                        ulong value = lengthMod switch
                        {
                            "hh" => (byte)nextGpArg(),
                            "h" => (ushort)nextGpArg(),
                            "l" => nextGpArg(),
                            "ll" => nextGpArg(),
                            "j" => nextGpArg(),
                            "z" => nextGpArg(),
                            "t" => nextGpArg(),
                            _ => (uint)nextGpArg()
                        };

                        var formatted = Convert.ToString((long)value, 8);
                        if (alternateForm && value != 0)
                            formatted = "0" + formatted;

                        sb.Append(PadString(formatted, width, leftAlign, padWithZero && !leftAlign));
                    }
                    break;

                case 'p':
                    {
                        var value = nextGpArg();
                        var formatted = value == 0
                            ? "(nil)"
                            : $"0x{value:X}";
                        sb.Append(formatted);
                    }
                    break;

                case 's':
                    {
                        var strAddr = nextGpArg();
                        if (strAddr == 0)
                        {
                            sb.Append("(null)");
                        }
                        else if (TryReadCString(ctx, strAddr, 1_048_576, out var strBytes))
                        {
                            var str = Encoding.UTF8.GetString(strBytes);
                            if (precision >= 0 && str.Length > precision)
                                str = str.Substring(0, precision);
                            sb.Append(PadString(str, width, leftAlign, false));
                        }
                        else
                        {
                            sb.Append("(null)");
                        }
                    }
                    break;

                case 'c':
                    {
                        var ch = (char)(byte)nextGpArg();
                        sb.Append(PadString(ch.ToString(), width, leftAlign, false));
                    }
                    break;

                case 'f':
                case 'F':
                case 'e':
                case 'E':
                case 'g':
                case 'G':
                    {
                        var value = nextFloatArg();

                        var formatStr = precision >= 0
                            ? $"{{0:{specifier}{precision}}}"
                            : $"{{0:{specifier}}}";
                        var formatted = string.Format(formatStr, value);

                        if (showSign && value >= 0)
                            formatted = "+" + formatted;
                        else if (spaceForSign && value >= 0)
                            formatted = " " + formatted;

                        sb.Append(PadString(formatted, width, leftAlign, padWithZero && !leftAlign));
                    }
                    break;

                case 'n':
                    {
                        var addr = nextGpArg();
                        if (addr != 0)
                        {
                            _ = TryWriteInt32(ctx, addr, sb.Length);
                        }
                    }
                    break;

                default:
                    sb.Append('%');
                    sb.Append(specifier);
                    break;
            }
        }

        return sb.ToString();
    }

    private static ulong ReadStackArg(CpuContext ctx, ulong offset)
    {
        var rsp = ctx[CpuRegister.Rsp];
        if (!ctx.TryReadUInt64(rsp + offset + 8, out var value)) // +8 to skip return address
        {
            return 0;
        }
        return value;
    }

    private static string PadString(string str, int width, bool leftAlign, bool padWithZero)
    {
        if (width <= str.Length)
            return str;

        var padChar = padWithZero ? '0' : ' ';
        var padLength = width - str.Length;
        var padding = new string(padChar, padLength);

        return leftAlign ? str + padding : padding + str;
    }

    private struct SysVAmd64VaListCursor
    {
        private const uint GpSaveAreaLimit = 48;
        private const uint FpSaveAreaLimit = 176;

        private readonly CpuContext _ctx;
        private readonly ulong _vaListAddress;
        private uint _gpOffset;
        private uint _fpOffset;
        private ulong _overflowArgArea;
        private readonly ulong _regSaveArea;

        public SysVAmd64VaListCursor(
            CpuContext ctx,
            ulong vaListAddress,
            uint gpOffset,
            uint fpOffset,
            ulong overflowArgArea,
            ulong regSaveArea)
        {
            _ctx = ctx;
            _vaListAddress = vaListAddress;
            _gpOffset = gpOffset;
            _fpOffset = fpOffset;
            _overflowArgArea = overflowArgArea;
            _regSaveArea = regSaveArea;
        }

        public ulong NextGpArg()
        {
            ulong readAddress;
            if (_regSaveArea != 0 && _gpOffset <= GpSaveAreaLimit - 8)
            {
                readAddress = _regSaveArea + _gpOffset;
                _gpOffset += 8;
            }
            else
            {
                readAddress = _overflowArgArea;
                _overflowArgArea += 8;
            }

            return TryReadUInt64Compat(_ctx, readAddress, out var value) ? value : 0;
        }

        public double NextFloatArg()
        {
            ulong readAddress;
            if (_regSaveArea != 0 && _fpOffset <= FpSaveAreaLimit - 16)
            {
                readAddress = _regSaveArea + _fpOffset;
                _fpOffset += 16;
            }
            else
            {
                readAddress = _overflowArgArea;
                _overflowArgArea += 8;
            }

            return TryReadUInt64Compat(_ctx, readAddress, out var rawBits)
                ? BitConverter.Int64BitsToDouble(unchecked((long)rawBits))
                : 0.0;
        }

        public void Commit()
        {
            _ = TryWriteUInt32Compat(_ctx, _vaListAddress + 0, _gpOffset);
            _ = TryWriteUInt32Compat(_ctx, _vaListAddress + 4, _fpOffset);
            _ = TryWriteUInt64Compat(_ctx, _vaListAddress + 8, _overflowArgArea);
        }
    }

    private static ulong AllocateMappedGuestAddress(CpuContext ctx, ulong length, ulong alignment)
    {
        if (length == 0)
        {
            return 0;
        }

        var effectiveAlignment = alignment == 0 ? 0x1000UL : alignment;
        if (_nextVirtualAddress == 0)
        {
            _nextVirtualAddress = 0x0100_0000UL;
        }

        var probeCandidates = new[]
        {
            8UL * 1024 * 1024,
            2UL * 1024 * 1024,
            512UL * 1024,
            128UL * 1024,
            0x1000UL,
        };

        foreach (var probeCandidate in probeCandidates)
        {
            var cursor = AlignUp(_nextVirtualAddress, effectiveAlignment);
            for (var i = 0; i < 0x4000; i++)
            {
                if (IsMappedGuestRangeAvailable(ctx, cursor, length, probeCandidate))
                {
                    _nextVirtualAddress = cursor + length;
                    return cursor;
                }

                cursor = AlignUp(cursor + 0x1000UL, effectiveAlignment);
            }
        }

        return 0;
    }

    private static bool TryReserveGuestVirtualRange(
        CpuContext ctx,
        ulong desiredAddress,
        ulong length,
        int protection,
        out ulong mappedAddress)
    {
        mappedAddress = 0;
        if (length == 0)
        {
            return false;
        }

        try
        {
            object memoryObject = ctx.Memory;
            MethodInfo? allocateAt = null;
            var allocateAtHasAllowAlternativeArg = false;
            for (var depth = 0; depth < 4; depth++)
            {
                foreach (var candidate in memoryObject.GetType().GetMethods(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (!string.Equals(candidate.Name, "AllocateAt", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var parameters = candidate.GetParameters();
                    if (parameters.Length == 3 &&
                        parameters[0].ParameterType == typeof(ulong) &&
                        parameters[1].ParameterType == typeof(ulong) &&
                        parameters[2].ParameterType == typeof(bool))
                    {
                        allocateAt = candidate;
                        allocateAtHasAllowAlternativeArg = false;
                        break;
                    }

                    if (parameters.Length == 4 &&
                        parameters[0].ParameterType == typeof(ulong) &&
                        parameters[1].ParameterType == typeof(ulong) &&
                        parameters[2].ParameterType == typeof(bool) &&
                        parameters[3].ParameterType == typeof(bool))
                    {
                        allocateAt = candidate;
                        allocateAtHasAllowAlternativeArg = true;
                        break;
                    }
                }

                if (allocateAt is not null)
                {
                    break;
                }

                var innerProperty = memoryObject.GetType().GetProperty("Inner", BindingFlags.Public | BindingFlags.Instance);
                if (innerProperty is null)
                {
                    break;
                }

                var innerValue = innerProperty.GetValue(memoryObject);
                if (innerValue is null || ReferenceEquals(innerValue, memoryObject))
                {
                    break;
                }

                memoryObject = innerValue;
            }

            if (allocateAt is null)
            {
                Console.Error.WriteLine($"[LOADER][TRACE] reserve range: AllocateAt missing on {ctx.Memory.GetType().FullName}");
                return false;
            }

            var executable = (protection & 0x04) != 0;
            var invokeArgs = allocateAtHasAllowAlternativeArg
                ? new object[] { desiredAddress, length, executable, true }
                : new object[] { desiredAddress, length, executable };
            var result = allocateAt.Invoke(memoryObject, invokeArgs);
            if (result is not ulong allocated || allocated == 0)
            {
                var resultType = result?.GetType().FullName ?? "null";
                Console.Error.WriteLine($"[LOADER][TRACE] reserve range: AllocateAt returned {resultType} value={result ?? "null"}");
                return false;
            }

            mappedAddress = allocated;
            return true;
        }
        catch
        {
            Console.Error.WriteLine("[LOADER][TRACE] reserve range threw while invoking AllocateAt");
            return false;
        }
    }

    private static bool IsMappedGuestRangeAvailable(
        CpuContext ctx,
        ulong address,
        ulong length,
        ulong minimumReadableSpan)
    {
        if (length == 0)
        {
            return false;
        }

        if (ulong.MaxValue - address < length - 1)
        {
            return false;
        }

        var end = address + length - 1;
        foreach (var region in _mappedRegions.Values)
        {
            var regionEnd = region.Address + region.Length - 1;
            if (address <= regionEnd && end >= region.Address)
            {
                return false;
            }
        }

        var probeLength = Math.Min(length, Math.Max(0x1000UL, minimumReadableSpan));
        var probeEnd = address + probeLength - 1;
        Span<byte> probe = stackalloc byte[1];
        return ctx.Memory.TryRead(address, probe) &&
               ctx.Memory.TryRead(probeEnd, probe);
    }

    private static FileAccess ResolveOpenAccess(int flags)
    {
        if ((flags & O_RDWR) == O_RDWR)
        {
            return FileAccess.ReadWrite;
        }

        if ((flags & O_WRONLY) == O_WRONLY)
        {
            return FileAccess.Write;
        }

        return FileAccess.Read;
    }

    private static FileMode ResolveOpenMode(int flags, FileAccess access)
    {
        var create = (flags & O_CREAT) != 0;
        var truncate = (flags & O_TRUNC) != 0;
        if (create && truncate)
        {
            return FileMode.Create;
        }

        if (create)
        {
            return FileMode.OpenOrCreate;
        }

        if (truncate)
        {
            return access == FileAccess.Read ? FileMode.Open : FileMode.Truncate;
        }

        return FileMode.Open;
    }

    private static string ResolveGuestPath(string guestPath)
    {
        if (string.IsNullOrWhiteSpace(guestPath))
        {
            return guestPath;
        }

        var app0Root = Environment.GetEnvironmentVariable("SHARPEMU_APP0_DIR");
        if (!string.IsNullOrWhiteSpace(app0Root))
        {
            if (guestPath.StartsWith("/app0/", StringComparison.OrdinalIgnoreCase))
            {
                var relative = guestPath["/app0/".Length..].Replace('/', Path.DirectorySeparatorChar);
                return Path.Combine(app0Root, relative);
            }

            if (guestPath.StartsWith("app0/", StringComparison.OrdinalIgnoreCase))
            {
                var relative = guestPath["app0/".Length..].Replace('/', Path.DirectorySeparatorChar);
                return Path.Combine(app0Root, relative);
            }
        }

        return guestPath;
    }

    private static bool TryReadCString(CpuContext ctx, ulong address, ulong maxLength, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (address == 0)
        {
            return false;
        }

        var limit = (int)Math.Min(maxLength, 1_048_576UL);
        var buffer = new List<byte>(Math.Min(limit, 256));
        Span<byte> one = stackalloc byte[1];
        for (var i = 0; i < limit; i++)
        {
            if (!TryReadCompat(ctx, address + (ulong)i, one))
            {
                return false;
            }

            if (one[0] == 0)
            {
                bytes = buffer.ToArray();
                return true;
            }

            buffer.Add(one[0]);
        }

        bytes = buffer.ToArray();
        return true;
    }

    private static bool TryCompareStrings(CpuContext ctx, ulong left, ulong right, ulong limit, out int compare)
    {
        compare = 0;
        if (left == 0 || right == 0)
        {
            return false;
        }

        var max = limit == ulong.MaxValue ? 1_048_576UL : Math.Min(limit, 1_048_576UL);
        Span<byte> leftByte = stackalloc byte[1];
        Span<byte> rightByte = stackalloc byte[1];
        for (ulong i = 0; i < max; i++)
        {
            if (!TryReadCompat(ctx, left + i, leftByte) ||
                !TryReadCompat(ctx, right + i, rightByte))
            {
                return false;
            }

            compare = leftByte[0] - rightByte[0];
            if (compare != 0 || leftByte[0] == 0 || rightByte[0] == 0)
            {
                return true;
            }
        }

        compare = 0;
        return true;
    }

    private static bool TryReadNullTerminatedUtf8(CpuContext ctx, ulong address, int maxLength, out string value)
    {
        value = string.Empty;
        if (address == 0 || maxLength <= 0)
        {
            return false;
        }

        var buffer = new List<byte>(Math.Min(maxLength, 256));
        Span<byte> one = stackalloc byte[1];
        for (var i = 0; i < maxLength; i++)
        {
            if (!TryReadCompat(ctx, address + (ulong)i, one))
            {
                return false;
            }

            if (one[0] == 0)
            {
                value = Encoding.UTF8.GetString(buffer.ToArray());
                return true;
            }

            buffer.Add(one[0]);
        }

        value = Encoding.UTF8.GetString(buffer.ToArray());
        return true;
    }

    private static bool TryReadCompat(CpuContext ctx, ulong address, Span<byte> destination)
    {
        if (destination.IsEmpty)
        {
            return true;
        }

        if (ctx.Memory.TryRead(address, destination))
        {
            return true;
        }

        if (!TryReadHostMemory(address, destination))
        {
            return false;
        }

        var recoveryIndex = Interlocked.Increment(ref _hostMemoryReadFallbackCount);
        if (recoveryIndex <= 8)
        {
            Console.Error.WriteLine(
                $"[LOADER][WARNING] host-read fallback#{recoveryIndex}: addr=0x{address:X16} len=0x{destination.Length:X}");
        }

        return true;
    }

    private static bool TryReadUInt32Compat(CpuContext ctx, ulong address, out uint value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        if (!TryReadCompat(ctx, address, bytes))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        return true;
    }

    private static bool TryReadUInt64Compat(CpuContext ctx, ulong address, out ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        if (!TryReadCompat(ctx, address, bytes))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        return true;
    }

    private static bool TryWriteCompat(CpuContext ctx, ulong address, ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return true;
        }

        if (ctx.Memory.TryWrite(address, source))
        {
            return true;
        }

        if (!TryWriteHostMemory(address, source))
        {
            return false;
        }

        var recoveryIndex = Interlocked.Increment(ref _hostMemoryWriteFallbackCount);
        if (recoveryIndex <= 8)
        {
            Console.Error.WriteLine(
                $"[LOADER][WARNING] host-write fallback#{recoveryIndex}: addr=0x{address:X16} len=0x{source.Length:X}");
        }

        return true;
    }

    private static bool TryWriteUInt32Compat(CpuContext ctx, ulong address, uint value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        return TryWriteCompat(ctx, address, bytes);
    }

    private static bool TryWriteUInt64Compat(CpuContext ctx, ulong address, ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        return TryWriteCompat(ctx, address, bytes);
    }

    private static bool TryReadHostMemory(ulong address, Span<byte> destination)
    {
        if (destination.IsEmpty || !IsHostRangeAccessible(address, (ulong)destination.Length, writeAccess: false))
        {
            return false;
        }

        try
        {
            var temporary = new byte[destination.Length];
            Marshal.Copy((nint)address, temporary, 0, temporary.Length);
            temporary.AsSpan().CopyTo(destination);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryAllocateLibcHeap(ulong requestedSize, nuint alignment, bool zeroFill, out ulong address)
    {
        address = 0;
        return TryConvertAllocationSize(requestedSize, out var size) &&
               TryAllocateLibcHeapCore(size, alignment, zeroFill, out address);
    }

    private static unsafe bool TryAllocateLibcHeapCore(nuint requestedSize, nuint alignment, bool zeroFill, out ulong address)
    {
        address = 0;
        alignment = NormalizeLibcAlignment(alignment);
        var actualSize = requestedSize == 0 ? 1u : requestedSize;

        nuint totalSize;
        try
        {
            checked
            {
                totalSize = actualSize + alignment - 1 + (nuint)IntPtr.Size;
            }
        }
        catch (OverflowException)
        {
            return false;
        }

        nint baseAddress;
        try
        {
            baseAddress = Marshal.AllocHGlobal(checked((nint)totalSize));
        }
        catch (OutOfMemoryException)
        {
            return false;
        }
        catch (OverflowException)
        {
            return false;
        }

        if (baseAddress == 0)
        {
            return false;
        }

        var alignedAddress = AlignUp(unchecked((ulong)baseAddress) + (ulong)IntPtr.Size, (ulong)alignment);
        lock (_libcAllocGate)
        {
            _libcAllocations[alignedAddress] = new LibcHeapAllocation(baseAddress, actualSize, alignment);
        }

        try
        {
            if (zeroFill)
            {
                NativeMemory.Clear((void*)alignedAddress, actualSize);
            }
        }
        catch
        {
            FreeLibcHeap(alignedAddress);
            return false;
        }

        address = alignedAddress;
        return true;
    }

    private static unsafe bool TryReallocateLibcHeap(ulong existingAddress, ulong requestedSize, out ulong resizedAddress)
    {
        resizedAddress = 0;
        if (existingAddress == 0)
        {
            return TryAllocateLibcHeap(requestedSize, DefaultLibcHeapAlignment, zeroFill: false, out resizedAddress);
        }

        if (requestedSize == 0)
        {
            FreeLibcHeap(existingAddress);
            return true;
        }

        LibcHeapAllocation allocation;
        lock (_libcAllocGate)
        {
            if (!_libcAllocations.TryGetValue(existingAddress, out allocation))
            {
                return false;
            }
        }

        if (!TryAllocateLibcHeap(requestedSize, allocation.Alignment, zeroFill: false, out resizedAddress))
        {
            return false;
        }

        var bytesToCopy = Math.Min(allocation.Size, (nuint)requestedSize);
        Buffer.MemoryCopy(
            source: (void*)existingAddress,
            destination: (void*)resizedAddress,
            destinationSizeInBytes: checked((long)Math.Max(bytesToCopy, 1u)),
            sourceBytesToCopy: checked((long)bytesToCopy));
        FreeLibcHeap(existingAddress);
        return true;
    }

    private static bool TryAllocateAlignedLibcHeap(ulong alignmentValue, ulong requestedSize, bool requireSizeMultiple, out ulong address)
    {
        address = 0;
        return TryValidateAlignedAllocation(
                   alignmentValue,
                   requestedSize,
                   requireSizeMultiple,
                   requirePointerSizedAlignment: false,
                   out var alignment,
                   out var size) &&
               TryAllocateLibcHeapCore(size, alignment, zeroFill: false, out address);
    }

    private static bool TryValidateAlignedAllocation(
        ulong alignmentValue,
        ulong requestedSize,
        bool requireSizeMultiple,
        bool requirePointerSizedAlignment,
        out nuint alignment,
        out nuint size)
    {
        alignment = 0;
        size = 0;
        if (!TryConvertAllocationSize(requestedSize, out size) ||
            alignmentValue == 0 ||
            alignmentValue > (ulong)nint.MaxValue)
        {
            return false;
        }

        alignment = (nuint)alignmentValue;
        if (!IsPowerOfTwo(alignment))
        {
            return false;
        }

        if (requirePointerSizedAlignment && alignment % (nuint)IntPtr.Size != 0)
        {
            return false;
        }

        if (alignment < (nuint)IntPtr.Size)
        {
            alignment = (nuint)IntPtr.Size;
        }

        if (requireSizeMultiple && size % alignment != 0)
        {
            return false;
        }

        return true;
    }

    private static void FreeLibcHeap(ulong address)
    {
        if (address == 0)
        {
            return;
        }

        LibcHeapAllocation allocation;
        lock (_libcAllocGate)
        {
            if (!_libcAllocations.Remove(address, out allocation))
            {
                return;
            }
        }

        Marshal.FreeHGlobal(allocation.BaseAddress);
    }

    private static bool TryMultiplyAllocationSize(ulong left, ulong right, out nuint size)
    {
        size = 0;
        if (!TryConvertAllocationSize(left, out var leftSize) ||
            !TryConvertAllocationSize(right, out var rightSize))
        {
            return false;
        }

        try
        {
            checked
            {
                size = leftSize * rightSize;
            }
        }
        catch (OverflowException)
        {
            return false;
        }

        return true;
    }

    private static bool TryConvertAllocationSize(ulong requestedSize, out nuint size)
    {
        size = 0;
        if (requestedSize > (ulong)nint.MaxValue)
        {
            return false;
        }

        size = (nuint)requestedSize;
        return true;
    }

    private static nuint NormalizeLibcAlignment(nuint alignment)
    {
        if (alignment < DefaultLibcHeapAlignment)
        {
            return DefaultLibcHeapAlignment;
        }

        return alignment;
    }

    private static bool IsPowerOfTwo(nuint value)
    {
        return value != 0 && (value & (value - 1)) == 0;
    }

    private static bool TryWriteHostMemory(ulong address, ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty || !IsHostRangeAccessible(address, (ulong)source.Length, writeAccess: true))
        {
            return false;
        }

        try
        {
            var temporary = source.ToArray();
            Marshal.Copy(temporary, 0, (nint)address, temporary.Length);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsHostRangeAccessible(ulong address, ulong length, bool writeAccess)
    {
        if (address == 0 || length == 0)
        {
            return false;
        }

        const ulong canonicalUpper = 0x0000800000000000UL;
        if (address >= canonicalUpper)
        {
            return false;
        }

        if (ulong.MaxValue - address < length - 1)
        {
            return false;
        }

        if (!TryQueryHostPage(address, out var startInfo) || !HasRequiredProtection(startInfo.Protect, writeAccess))
        {
            return false;
        }

        var endAddress = address + length - 1;
        if (endAddress == address)
        {
            return true;
        }

        if (!TryQueryHostPage(endAddress, out var endInfo) || !HasRequiredProtection(endInfo.Protect, writeAccess))
        {
            return false;
        }

        return true;
    }

    private static bool TryQueryHostPage(ulong address, out MemoryBasicInformation info)
    {
        info = default;
        var size = (nuint)Marshal.SizeOf<MemoryBasicInformation>();
        if (VirtualQuery((nint)address, out info, size) == 0)
        {
            return false;
        }

        return info.State == MemCommit;
    }

    private static bool HasRequiredProtection(uint protect, bool writeAccess)
    {
        if ((protect & (PageNoAccess | PageGuard)) != 0)
        {
            return false;
        }

        const uint readableMask = PageReadOnly | PageReadWrite | PageWriteCopy | PageExecuteRead | PageExecuteReadWrite | PageExecuteWriteCopy;
        const uint writableMask = PageReadWrite | PageWriteCopy | PageExecuteReadWrite | PageExecuteWriteCopy;
        var expected = writeAccess ? writableMask : readableMask;
        return (protect & expected) != 0;
    }

    private static bool TryWriteInt32(CpuContext ctx, ulong address, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BitConverter.TryWriteBytes(bytes, value);
        return ctx.Memory.TryWrite(address, bytes);
    }

    private static ulong AlignUp(ulong value, ulong alignment)
    {
        if (alignment <= 1)
        {
            return value;
        }

        var mask = alignment - 1;
        return (value + mask) & ~mask;
    }
}
