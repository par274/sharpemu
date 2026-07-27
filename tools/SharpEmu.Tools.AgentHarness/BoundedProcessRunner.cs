// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record BoundedProcessResult(
    int? ExitCode,
    bool TimedOut,
    bool Canceled,
    bool Crash,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    double ElapsedSeconds,
    double CpuSeconds,
    long PeakWorkingSetBytes,
    string ResourceMeasurementScope,
    bool JobObjectOwned,
    bool ProcessTreeCleaned,
    uint? ActiveProcessCountAfterCleanup,
    IReadOnlyList<string> Warnings);

internal static class BoundedProcessRunner
{
    public static async Task<BoundedProcessResult> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string?> environment,
        TimeSpan timeout,
        string stdoutPath,
        string stderrPath,
        Func<Process, TimeSpan, Task>? sample = null,
        CancellationToken cancellationToken = default)
    {
        var warnings = new List<string>();
        var start = DateTimeOffset.UtcNow;
        using var stdout = new StreamWriter(stdoutPath, append: false) { AutoFlush = true };
        using var stderr = new StreamWriter(stderrPath, append: false) { AutoFlush = true };
        Process? process = null;
        WindowsSuspendedProcess? suspended = null;
        WindowsJob? job = null;
        Task stdoutReader = Task.CompletedTask;
        Task stderrReader = Task.CompletedTask;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                job = WindowsJob.TryCreate(out var jobWarning)
                    ?? throw new InvalidOperationException(jobWarning ?? "Windows Job Object creation failed before launch.");
                suspended = WindowsSuspendedProcess.Start(executable, arguments, workingDirectory, environment);
                process = suspended.Process;
                if (!job.TryAssign(process, out jobWarning))
                {
                    suspended.Terminate();
                    throw new InvalidOperationException(jobWarning ?? "Windows Job Object assignment failed before resume.");
                }
                stdoutReader = CopyLinesAsync(suspended.StandardOutput, stdout);
                stderrReader = CopyLinesAsync(suspended.StandardError, stderr);
                suspended.Resume();
            }
            else
            {
                process = new Process
                {
                    StartInfo = new ProcessStartInfo(executable)
                    {
                        WorkingDirectory = workingDirectory,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = false,
                    },
                    EnableRaisingEvents = true,
                };
                foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
                foreach (var pair in environment) process.StartInfo.Environment[pair.Key] = pair.Value;
                process.Start();
                stdoutReader = CopyLinesAsync(process.StandardOutput, stdout);
                stderrReader = CopyLinesAsync(process.StandardError, stderr);
            }
        }
        catch
        {
            suspended?.Dispose();
            process?.Dispose();
            job?.Dispose();
            throw;
        }

        var jobOwned = job is not null;
        try
        {
            var stopwatch = Stopwatch.StartNew();
            var peakWorkingSet = 0L;
            var lastCpu = TimeSpan.Zero;
            using var sampleCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var sampler = Task.Run(async () =>
            {
                while (!sampleCancellation.IsCancellationRequested && !process.HasExited)
                {
                    try
                    {
                        process.Refresh();
                        peakWorkingSet = Math.Max(peakWorkingSet, process.WorkingSet64);
                        lastCpu = process.TotalProcessorTime;
                        if (sample is not null) await sample(process, stopwatch.Elapsed);
                    }
                    catch (InvalidOperationException)
                    {
                        break;
                    }
                    await Task.Delay(250, sampleCancellation.Token).ConfigureAwait(false);
                }
            }, sampleCancellation.Token);

            var timedOut = false;
            var canceled = false;
            try
            {
                var exitTask = process.WaitForExitAsync(CancellationToken.None);
                var timeoutTask = Task.Delay(timeout, CancellationToken.None);
                var cancellationTask = cancellationToken.CanBeCanceled
                    ? Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                    : Task.Delay(Timeout.InfiniteTimeSpan, CancellationToken.None);
                var completed = await Task.WhenAny(exitTask, timeoutTask, cancellationTask);
                if (completed != exitTask)
                {
                    canceled = completed == cancellationTask;
                    timedOut = !canceled;
                    if (process.CloseMainWindow())
                    {
                        await Task.WhenAny(process.WaitForExitAsync(CancellationToken.None), Task.Delay(TimeSpan.FromSeconds(2), CancellationToken.None));
                    }
                    if (!process.HasExited)
                    {
                        if (job is not null) job.Terminate();
                        else process.Kill(entireProcessTree: true);
                        await process.WaitForExitAsync(CancellationToken.None);
                    }
                }
                else
                {
                    await exitTask;
                }
            }
            finally
            {
                await sampleCancellation.CancelAsync();
                try { await sampler; } catch (OperationCanceledException) { }
                if (!process.HasExited) process.WaitForExit();
            }

            stopwatch.Stop();
            if (job is not null && job.TryGetActiveProcessCount(out var remaining, out var cleanupWarning) && remaining != 0)
            {
                job.Terminate();
                for (var attempt = 0; attempt < 40 && remaining != 0; attempt++)
                {
                    await Task.Delay(25, CancellationToken.None);
                    if (!job.TryGetActiveProcessCount(out remaining, out cleanupWarning)) break;
                }
            }
            var end = DateTimeOffset.UtcNow;
            int? exitCode = null;
            if (process.HasExited) exitCode = process.ExitCode;
            uint? activeAfterCleanup = null;
            var cleaned = job is null && process.HasExited;
            var resourceScope = "root-process";
            string? accountingWarning = null;
            if (job is not null && job.TryReadAccounting(out var jobCpu, out var peakJobMemory, out var activeProcesses, out accountingWarning))
            {
                lastCpu = jobCpu;
                peakWorkingSet = Math.Max(peakWorkingSet, peakJobMemory);
                resourceScope = "windows-job-object-process-tree";
                activeAfterCleanup = activeProcesses;
                cleaned = activeProcesses == 0;
            }
            else if (accountingWarning is not null)
            {
                warnings.Add(accountingWarning);
                cleaned = false;
            }
            await Task.WhenAll(stdoutReader, stderrReader);
            var result = new BoundedProcessResult(
                exitCode,
                timedOut,
                canceled,
                !timedOut && !canceled && exitCode is not (null or 0 or 4),
                start,
                end,
                stopwatch.Elapsed.TotalSeconds,
                lastCpu.TotalSeconds,
                peakWorkingSet,
                resourceScope,
                jobOwned,
                cleaned,
                activeAfterCleanup,
                warnings);
            return result;
        }
        finally
        {
            job?.Dispose();
            suspended?.Dispose();
            process.Dispose();
        }
    }

    private static async Task CopyLinesAsync(StreamReader reader, StreamWriter writer)
    {
        while (await reader.ReadLineAsync(CancellationToken.None) is { } line)
        {
            lock (writer) writer.WriteLine(line);
        }
    }
}

internal sealed class WindowsSuspendedProcess : IDisposable
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private nint _threadHandle;
    private readonly AnonymousPipeServerStream _stdoutPipe;
    private readonly AnonymousPipeServerStream _stderrPipe;

    private WindowsSuspendedProcess(Process process, nint threadHandle, AnonymousPipeServerStream stdoutPipe, AnonymousPipeServerStream stderrPipe)
    {
        Process = process;
        _threadHandle = threadHandle;
        _stdoutPipe = stdoutPipe;
        _stderrPipe = stderrPipe;
        StandardOutput = new StreamReader(stdoutPipe, Encoding.UTF8, true, 4096, leaveOpen: true);
        StandardError = new StreamReader(stderrPipe, Encoding.UTF8, true, 4096, leaveOpen: true);
    }

    public Process Process { get; }

    public StreamReader StandardOutput { get; }

    public StreamReader StandardError { get; }

    public static WindowsSuspendedProcess Start(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string?> environment)
    {
        executable = ResolveExecutable(executable, workingDirectory);
        var stdoutPipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        var stderrPipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), InheritHandle = true };
        var nullInput = CreateFileW("NUL", GenericRead, FileShareRead | FileShareWrite, ref security, OpenExisting, 0, 0);
        if (nullInput == -1)
        {
            stdoutPipe.Dispose();
            stderrPipe.Dispose();
            throw new InvalidOperationException($"Opening NUL for suspended process input failed ({Marshal.GetLastWin32Error()}).");
        }

        var startup = new StartupInfo
        {
            Size = Marshal.SizeOf<StartupInfo>(),
            Flags = StartfUseStdHandles,
            StandardInput = nullInput,
            StandardOutput = stdoutPipe.ClientSafePipeHandle.DangerousGetHandle(),
            StandardError = stderrPipe.ClientSafePipeHandle.DangerousGetHandle(),
        };
        var commandLine = new StringBuilder(string.Join(' ', new[] { executable }.Concat(arguments).Select(QuoteArgument)));
        var environmentBlock = CreateEnvironmentBlock(environment);
        try
        {
            if (!CreateProcessW(
                    executable,
                    commandLine,
                    0,
                    0,
                    true,
                    CreateSuspended | CreateUnicodeEnvironment,
                    environmentBlock,
                    workingDirectory,
                    ref startup,
                    out var processInformation))
            {
                throw new InvalidOperationException($"Suspended process creation failed ({Marshal.GetLastWin32Error()}).");
            }

            stdoutPipe.DisposeLocalCopyOfClientHandle();
            stderrPipe.DisposeLocalCopyOfClientHandle();
            var process = Process.GetProcessById(checked((int)processInformation.ProcessId));
            process.EnableRaisingEvents = true;
            CloseHandle(processInformation.ProcessHandle);
            return new WindowsSuspendedProcess(process, processInformation.ThreadHandle, stdoutPipe, stderrPipe);
        }
        catch
        {
            stdoutPipe.Dispose();
            stderrPipe.Dispose();
            throw;
        }
        finally
        {
            if (environmentBlock != 0) Marshal.FreeHGlobal(environmentBlock);
            CloseHandle(nullInput);
        }
    }

    public void Resume()
    {
        if (_threadHandle == 0 || ResumeThread(_threadHandle) == uint.MaxValue)
        {
            Terminate();
            throw new InvalidOperationException($"Resuming the contained process failed ({Marshal.GetLastWin32Error()}).");
        }
        CloseHandle(_threadHandle);
        _threadHandle = 0;
    }

    public void Terminate()
    {
        try { if (!Process.HasExited) Process.Kill(entireProcessTree: false); } catch (InvalidOperationException) { }
    }

    public void Dispose()
    {
        if (_threadHandle != 0) CloseHandle(_threadHandle);
        _threadHandle = 0;
        StandardOutput.Dispose();
        StandardError.Dispose();
        _stdoutPipe.Dispose();
        _stderrPipe.Dispose();
    }

    internal static string QuoteArgument(string value)
    {
        if (value.Length > 0 && value.All(character => !char.IsWhiteSpace(character) && character != '"')) return value;
        var result = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                result.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
                continue;
            }
            result.Append('\\', backslashes).Append(character);
            backslashes = 0;
        }
        result.Append('\\', backslashes * 2).Append('"');
        return result.ToString();
    }

    private static nint CreateEnvironmentBlock(IReadOnlyDictionary<string, string?> overrides)
    {
        var values = Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key, entry => (string?)entry.Value, StringComparer.OrdinalIgnoreCase);
        foreach (var pair in overrides)
        {
            if (pair.Value is null) values.Remove(pair.Key); else values[pair.Key] = pair.Value;
        }
        var block = string.Join('\0', values.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => $"{pair.Key}={pair.Value}")) + "\0\0";
        return Marshal.StringToHGlobalUni(block);
    }

    private static string ResolveExecutable(string executable, string workingDirectory)
    {
        if (Path.IsPathFullyQualified(executable)) return Path.GetFullPath(executable);
        var names = Path.HasExtension(executable) ? new[] { executable } : new[] { executable, executable + ".exe" };
        foreach (var directory in new[] { workingDirectory }.Concat((Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)))
        {
            foreach (var name in names)
            {
                var candidate = Path.GetFullPath(name, directory.Trim('"'));
                if (File.Exists(candidate)) return candidate;
            }
        }
        throw new FileNotFoundException($"Executable '{executable}' was not found on PATH.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public nint SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public ushort ShowWindow, Reserved2Size;
        public nint Reserved2, StandardInput, StandardOutput, StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint ProcessHandle;
        public nint ThreadHandle;
        public uint ProcessId;
        public uint ThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, nint processAttributes, nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, nint environment, string currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint CreateFileW(string fileName, uint desiredAccess, uint shareMode, ref SecurityAttributes securityAttributes, uint creationDisposition, uint flags, nint template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(nint thread);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}

internal sealed class WindowsJob : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int ExtendedLimitInformationClass = 9;
    private const int BasicAccountingInformationClass = 1;
    private nint _handle;

    private WindowsJob(nint handle) => _handle = handle;

    public static WindowsJob? TryCreate(out string? warning)
    {
        warning = null;
        if (!OperatingSystem.IsWindows()) return null;
        var handle = CreateJobObjectW(0, null);
        if (handle == 0)
        {
            warning = $"Windows Job Object creation failed ({Marshal.GetLastWin32Error()}); launch was refused.";
            return null;
        }
        var job = new WindowsJob(handle);
        var info = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation { LimitFlags = JobObjectLimitKillOnJobClose },
        };
        var size = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        var memory = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, memory, false);
            if (!SetInformationJobObject(handle, ExtendedLimitInformationClass, memory, (uint)size))
            {
                warning = $"Windows Job Object configuration failed ({Marshal.GetLastWin32Error()}); launch was refused.";
                job.Dispose();
                return null;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(memory);
        }
        return job;
    }

    public bool TryAssign(Process process, out string? warning)
    {
        warning = null;
        if (_handle != 0 && AssignProcessToJobObject(_handle, process.Handle)) return true;
        warning = $"Windows Job Object assignment failed ({Marshal.GetLastWin32Error()}); the suspended process was terminated before guest execution.";
        return false;
    }

    public void Terminate()
    {
        if (_handle != 0) _ = TerminateJobObject(_handle, 1460);
    }

    public bool TryReadAccounting(out TimeSpan cpuTime, out long peakJobMemory, out uint activeProcesses, out string? warning)
    {
        cpuTime = TimeSpan.Zero;
        peakJobMemory = 0;
        activeProcesses = 0;
        warning = null;
        if (_handle == 0) return false;
        var accountingSize = Marshal.SizeOf<JobObjectBasicAccountingInformation>();
        var extendedSize = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        var accountingMemory = Marshal.AllocHGlobal(accountingSize);
        var extendedMemory = Marshal.AllocHGlobal(extendedSize);
        try
        {
            if (!QueryInformationJobObject(_handle, BasicAccountingInformationClass, accountingMemory, (uint)accountingSize, out _) ||
                !QueryInformationJobObject(_handle, ExtendedLimitInformationClass, extendedMemory, (uint)extendedSize, out _))
            {
                warning = $"Windows Job Object accounting query failed ({Marshal.GetLastWin32Error()}); root-process resource metrics are reported.";
                return false;
            }
            var accounting = Marshal.PtrToStructure<JobObjectBasicAccountingInformation>(accountingMemory);
            var limits = Marshal.PtrToStructure<JobObjectExtendedLimitInformation>(extendedMemory);
            cpuTime = TimeSpan.FromTicks(checked(accounting.TotalUserTime + accounting.TotalKernelTime));
            peakJobMemory = checked((long)limits.PeakJobMemoryUsed);
            activeProcesses = accounting.ActiveProcesses;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(accountingMemory);
            Marshal.FreeHGlobal(extendedMemory);
        }
    }

    public bool TryGetActiveProcessCount(out uint activeProcesses, out string? warning)
    {
        var result = TryReadAccounting(out _, out _, out activeProcesses, out warning);
        return result;
    }

    public void Dispose()
    {
        if (_handle == 0) return;
        CloseHandle(_handle);
        _handle = 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint CreateJobObjectW(nint attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(nint job, int informationClass, nint information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(nint job, nint process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(nint job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(nint job, int informationClass, nint information, uint length, out uint returnLength);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}
