// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Threading;

namespace SharpEmu.Libs.Kernel;

public static class KernelExports
{
    private static int _nextFileDescriptor = 2;
    private static readonly object _cxaGate = new();
    private static readonly List<CxaDestructorEntry> _cxaDestructors = new();

    private readonly record struct CxaDestructorEntry(
        ulong Function,
        ulong Argument,
        ulong ModuleHandle);

    [SysAbiExport(
        Nid = "WB66evu8bsU",
        ExportName = "sceKernelGetCompiledSdkVersion",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelGetCompiledSdkVersion(CpuContext ctx)
    {
        _ = ctx;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "uMei1W9uyNo",
        ExportName = "exit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int Exit(CpuContext ctx)
    {
        _ = ctx;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "XKRegsFpEpk",
        ExportName = "catchReturnFromMain",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int CatchReturnFromMain(CpuContext ctx)
    {
        var status = unchecked((int)ctx[CpuRegister.Rdi]);
        Console.Error.WriteLine($"[LOADER][INFO] catchReturnFromMain(status={status})");
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "bzQExy189ZI",
        ExportName = "_init_env",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int InitEnv(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "8G2LB+A3rzg",
        ExportName = "atexit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Atexit(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "tsvEmnenz48",
        ExportName = "__cxa_atexit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int CxaAtexit(CpuContext ctx)
    {
        var destructorFunction = ctx[CpuRegister.Rdi];
        var destructorArgument = ctx[CpuRegister.Rsi];
        var moduleHandle = ctx[CpuRegister.Rdx];
        if (destructorFunction == 0)
        {
            ctx[CpuRegister.Rax] = 0;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        lock (_cxaGate)
        {
            _cxaDestructors.Add(new CxaDestructorEntry(
                destructorFunction,
                destructorArgument,
                moduleHandle));
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "H2e8t5ScQGc",
        ExportName = "__cxa_finalize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int CxaFinalize(CpuContext ctx)
    {
        var moduleHandle = ctx[CpuRegister.Rdi];

        lock (_cxaGate)
        {
            if (moduleHandle == 0)
            {
                _cxaDestructors.Clear();
            }
            else
            {
                for (var i = _cxaDestructors.Count - 1; i >= 0; i--)
                {
                    if (_cxaDestructors[i].ModuleHandle == moduleHandle)
                    {
                        _cxaDestructors.RemoveAt(i);
                    }
                }
            }
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "kbw4UHHSYy0",
        ExportName = "__pthread_cxa_finalize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCxaFinalize(CpuContext ctx)
    {
        _ = ctx;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "6Z83sYWFlA8",
        ExportName = "_exit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int UnderscoreExit(CpuContext ctx)
    {
        _ = ctx;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Ac86z8q7T8A",
        ExportName = "sceKernelExitSblock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelExitSblock(CpuContext ctx)
    {
        _ = ctx;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "6UgtwV+0zb4",
        ExportName = "scePthreadCreate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadCreate(CpuContext ctx)
    {
        var threadIdAddress = ctx[CpuRegister.Rdi];
        var attrAddress = ctx[CpuRegister.Rsi];
        var entryAddress = ctx[CpuRegister.Rdx];
        var argument = ctx[CpuRegister.Rcx];
        var nameAddress = ctx[CpuRegister.R8];
        var name = nameAddress == 0 ? string.Empty : ReadCString(ctx, nameAddress, 256);
        var threadHandle = KernelPthreadState.CreateThreadHandle(name);
        if (threadIdAddress != 0 && !ctx.TryWriteUInt64(threadIdAddress, threadHandle))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        if (ShouldTracePthread())
        {
            Console.Error.WriteLine(
                $"[LOADER][TRACE] pthread_create: out=0x{threadIdAddress:X16} attr=0x{attrAddress:X16} entry=0x{entryAddress:X16} arg=0x{argument:X16} name_ptr=0x{nameAddress:X16} name='{name}' -> thread=0x{threadHandle:X16}");
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "OxhIB8LB-PQ",
        ExportName = "pthread_create",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadCreate(CpuContext ctx)
    {
        return PthreadCreate(ctx);
    }

    [SysAbiExport(
        Nid = "onNY9Byn-W8",
        ExportName = "scePthreadJoin",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadJoin(CpuContext ctx)
    {
        var threadId = ctx[CpuRegister.Rdi];
        var returnValueAddress = ctx[CpuRegister.Rsi];
        if (returnValueAddress != 0 && !ctx.TryWriteUInt64(returnValueAddress, 0))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        if (ShouldTracePthread())
        {
            Console.Error.WriteLine(
                $"[LOADER][TRACE] pthread_join: thread=0x{threadId:X16} retval_out=0x{returnValueAddress:X16}");
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "h9CcP3J0oVM",
        ExportName = "pthread_join",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadJoin(CpuContext ctx)
    {
        return PthreadJoin(ctx);
    }

    [SysAbiExport(
        Nid = "wuCroIGjt2g",
        ExportName = "open",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int Open(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] = unchecked((ulong)Interlocked.Increment(ref _nextFileDescriptor));
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "1G3lF1Gg1k8",
        ExportName = "sceKernelOpen",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelOpen(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] = unchecked((ulong)Interlocked.Increment(ref _nextFileDescriptor));
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "hcuQgD53UxM",
        ExportName = "printf",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Printf(CpuContext ctx)
    {
        ulong fmtPtr = ctx[CpuRegister.Rdi];
        string fmt = ReadCString(ctx, fmtPtr, 4096);

        ulong[] args =
        {
        ctx[CpuRegister.Rsi],
        ctx[CpuRegister.Rdx],
        ctx[CpuRegister.Rcx],
        ctx[CpuRegister.R8],
        ctx[CpuRegister.R9],
    };

        int argIndex = 0;
        var sb = new System.Text.StringBuilder(fmt.Length + 64);

        for (int i = 0; i < fmt.Length; i++)
        {
            char ch = fmt[i];
            if (ch != '%')
            {
                sb.Append(ch);
                continue;
            }

            if (i + 1 < fmt.Length && fmt[i + 1] == '%')
            {
                sb.Append('%');
                i++;
                continue;
            }

            int j = i + 1;
            while (j < fmt.Length && "-+ #0".IndexOf(fmt[j]) >= 0) j++;
            while (j < fmt.Length && char.IsDigit(fmt[j])) j++;

            if (j < fmt.Length && fmt[j] == '.')
            {
                j++;
                while (j < fmt.Length && char.IsDigit(fmt[j])) j++;
            }

            if (j >= fmt.Length) break;
            char spec = fmt[j];
            i = j;

            ulong a = argIndex < args.Length ? args[argIndex++] : 0;

            switch (spec)
            {
                case 's':
                    sb.Append(a == 0 ? "(null)" : ReadCString(ctx, a, 4096));
                    break;

                case 'd':
                case 'i':
                    sb.Append(unchecked((int)a));
                    break;

                case 'u':
                    sb.Append(unchecked((uint)a));
                    break;

                case 'x':
                    sb.Append(unchecked((uint)a).ToString("x"));
                    break;

                case 'p':
                    sb.Append("0x").Append(a.ToString("x16"));
                    break;

                default:
                    sb.Append('%').Append(spec);
                    break;
            }
        }

        string outStr = sb.ToString();
        Console.WriteLine($"[DEBUG][PRINF] {outStr}");

        ctx[CpuRegister.Rax] = (ulong)outStr.Length;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "EMutwaQ34Jo",
        ExportName = "perror",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libc")]
    public static int Perror(CpuContext ctx)
    {
        ulong sPtr = ctx[CpuRegister.Rdi];

        string msg;
        if (sPtr == 0)
        {
            msg = "perror(NULL)";
        }
        else
        {
            msg = ReadCString(ctx, sPtr, 2048);
            msg = $"perror(\"{msg}\")";
        }

        Console.WriteLine(msg);

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static string ReadCString(CpuContext ctx, ulong address, int maxLen)
    {
        Span<byte> buf = stackalloc byte[maxLen];
        if (!ctx.Memory.TryRead(address, buf))
            return $"<unreadable 0x{address:X16}>";

        int len = 0;
        while (len < buf.Length && buf[len] != 0) len++;

        try { return System.Text.Encoding.UTF8.GetString(buf.Slice(0, len)); }
        catch { return System.Text.Encoding.ASCII.GetString(buf.Slice(0, len)); }
    }

    private static bool ShouldTracePthread()
    {
        return string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_PTHREADS"), "1", StringComparison.Ordinal);
    }
}
