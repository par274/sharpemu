// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record BoundedProcessResult(
    int? ExitCode,
    bool TimedOut,
    bool Crash,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    double ElapsedSeconds,
    double CpuSeconds,
    long PeakWorkingSetBytes,
    string ResourceMeasurementScope,
    bool JobObjectOwned,
    bool ProcessTreeCleaned,
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
        using var process = new Process
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
        process.OutputDataReceived += (_, eventArgs) => { if (eventArgs.Data is not null) lock (stdout) stdout.WriteLine(eventArgs.Data); };
        process.ErrorDataReceived += (_, eventArgs) => { if (eventArgs.Data is not null) lock (stderr) stderr.WriteLine(eventArgs.Data); };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        using var job = WindowsJob.TryCreateAndAssign(process, out var jobWarning);
        if (jobWarning is not null) warnings.Add(jobWarning);
        var jobOwned = job is not null;
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
        try
        {
            var exitTask = process.WaitForExitAsync(cancellationToken);
            var completed = await Task.WhenAny(exitTask, Task.Delay(timeout, cancellationToken));
            if (completed != exitTask)
            {
                timedOut = true;
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
            process.WaitForExit();
        }

        stopwatch.Stop();
        var end = DateTimeOffset.UtcNow;
        int? exitCode = null;
        if (process.HasExited) exitCode = process.ExitCode;
        var cleaned = process.HasExited;
        var resourceScope = "root-process";
        string? accountingWarning = null;
        if (job is not null && job.TryReadAccounting(out var jobCpu, out var peakJobMemory, out accountingWarning))
        {
            lastCpu = jobCpu;
            peakWorkingSet = Math.Max(peakWorkingSet, peakJobMemory);
            resourceScope = "windows-job-object-process-tree";
        }
        else if (accountingWarning is not null)
        {
            warnings.Add(accountingWarning);
        }
        return new BoundedProcessResult(
            exitCode,
            timedOut,
            !timedOut && exitCode is not (null or 0 or 4),
            start,
            end,
            stopwatch.Elapsed.TotalSeconds,
            lastCpu.TotalSeconds,
            peakWorkingSet,
            resourceScope,
            jobOwned,
            cleaned,
            warnings);
    }
}

internal sealed class WindowsJob : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int ExtendedLimitInformationClass = 9;
    private const int BasicAccountingInformationClass = 1;
    private nint _handle;

    private WindowsJob(nint handle) => _handle = handle;

    public static WindowsJob? TryCreateAndAssign(Process process, out string? warning)
    {
        warning = null;
        if (!OperatingSystem.IsWindows()) return null;
        var handle = CreateJobObjectW(0, null);
        if (handle == 0)
        {
            warning = $"Windows Job Object creation failed ({Marshal.GetLastWin32Error()}); process-tree kill fallback is active.";
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
            if (!SetInformationJobObject(handle, ExtendedLimitInformationClass, memory, (uint)size) ||
                !AssignProcessToJobObject(handle, process.Handle))
            {
                warning = $"Windows Job Object assignment failed ({Marshal.GetLastWin32Error()}); process-tree kill fallback is active.";
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

    public void Terminate()
    {
        if (_handle != 0) _ = TerminateJobObject(_handle, 1460);
    }

    public bool TryReadAccounting(out TimeSpan cpuTime, out long peakJobMemory, out string? warning)
    {
        cpuTime = TimeSpan.Zero;
        peakJobMemory = 0;
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
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(accountingMemory);
            Marshal.FreeHGlobal(extendedMemory);
        }
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
