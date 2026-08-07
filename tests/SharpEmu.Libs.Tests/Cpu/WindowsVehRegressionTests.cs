// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

public sealed class WindowsVehRegressionTests
{
    private const int RegressionTimeoutMilliseconds = 30_000;
#if DEBUG
    private const string BuildConfiguration = "Debug";
#else
    private const string BuildConfiguration = "Release";
#endif

    private static readonly byte[] RetGuest = [0x31, 0xC0, 0xC3];
    private static readonly byte[] Ud2Guest = [0x0F, 0x0B];
    private static readonly byte[] AccessViolationGuest =
        [0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0xC3];

    [Fact]
    public void RetGuest_StillReturnsNormally()
    {
        if (!CanRunNativeWindowsGuest())
        {
            return;
        }

        var result = RunGuest("ret", RetGuest);

        AssertCompleted(result, "RET");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Guest returned: 0", result.Output);
    }

    [Fact]
    public void Ud2Guest_ReachesManagedVehWithoutCpuSpin()
    {
        if (!CanRunNativeWindowsGuest())
        {
            return;
        }

        var result = RunGuest("ud2", Ud2Guest);

        AssertFaultReachedManagedPathWithoutSpin(result, "UD2", "0xC000001D");
    }

    [Fact]
    public void AccessViolationGuest_ReachesManagedVehWithoutCpuSpin()
    {
        if (!CanRunNativeWindowsGuest())
        {
            return;
        }

        var result = RunGuest("access-violation", AccessViolationGuest);

        AssertFaultReachedManagedPathWithoutSpin(result, "access violation", "0xC0000005");
    }

    private static bool CanRunNativeWindowsGuest() =>
        OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X64;

    private static GuestProcessResult RunGuest(string name, ReadOnlySpan<byte> guestCode)
    {
        var appHost = FindAppHost();
        var tempDirectory = Directory.CreateTempSubdirectory($"sharpemu-779-{name}-");
        try
        {
            var imagePath = Path.Combine(tempDirectory.FullName, "eboot.bin");
            File.WriteAllBytes(imagePath, BuildElfImage(guestCode));
            return RunAppHost(appHost, imagePath, name);
        }
        finally
        {
            tempDirectory.Delete(recursive: true);
        }
    }

    private static string FindAppHost()
    {
        var repository = FindRepositoryRoot();
        var appHost = Path.Combine(
            repository,
            "artifacts",
            "bin",
            BuildConfiguration,
            "net10.0",
            "win-x64",
            "SharpEmu.exe");

        if (File.Exists(appHost))
        {
            return appHost;
        }

        throw new FileNotFoundException(
            $"The Windows CLI test host was not built for {BuildConfiguration}. " +
            $"Build SharpEmu.slnx with -c {BuildConfiguration} before running this regression test.",
            appHost);
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SharpEmu.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("Could not locate the SharpEmu repository root.");
    }

    private static GuestProcessResult RunAppHost(string appHost, string imagePath, string name)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = appHost,
            WorkingDirectory = Path.GetDirectoryName(appHost)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("--cpu-engine=native");
        startInfo.ArgumentList.Add("--log-level=info");
        startInfo.ArgumentList.Add(imagePath);
        // The test's external timeout must be the only hang detector.
        startInfo.Environment["SHARPEMU_STALL_WATCHDOG_SECONDS"] = "0";

        using var process = Process.Start(startInfo) ??
            throw new InvalidOperationException($"Could not start the SharpEmu CLI for {name}.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var exited = process.WaitForExit(RegressionTimeoutMilliseconds);
        var cpuSampleMilliseconds = 0.0;

        if (!exited)
        {
            process.Refresh();
            var cpuBefore = process.TotalProcessorTime;
            Thread.Sleep(250);
            process.Refresh();
            cpuSampleMilliseconds = (process.TotalProcessorTime - cpuBefore).TotalMilliseconds;

            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            process.WaitForExit();
        }
        else
        {
            process.WaitForExit();
        }

        return new GuestProcessResult(
            exited,
            process.ExitCode,
            cpuSampleMilliseconds,
            stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
    }

    private static void AssertCompleted(GuestProcessResult result, string caseName)
    {
        Assert.True(
            result.Completed,
            $"{caseName} did not terminate within the regression timeout; " +
            $"the 250 ms post-timeout CPU sample was {result.CpuSampleMilliseconds:F0} ms.\n" +
            result.Output);
    }

    private static void AssertFaultReachedManagedPathWithoutSpin(
        GuestProcessResult result,
        string caseName,
        string exceptionCode)
    {
        AssertCompleted(result, caseName);
        Assert.Contains("NATIVE EXCEPTION CAUGHT!", result.Output);
        Assert.Contains($"Code: {exceptionCode}", result.Output);
        Assert.NotEqual(0, result.ExitCode);
    }

    private static byte[] BuildElfImage(ReadOnlySpan<byte> guestCode)
    {
        const int fileOffset = 0x1000;
        const ulong guestEntry = 0x1000;
        var image = new byte[fileOffset + guestCode.Length];

        image[0] = 0x7F;
        image[1] = (byte)'E';
        image[2] = (byte)'L';
        image[3] = (byte)'F';
        image[4] = 2; // ELFCLASS64
        image[5] = 1; // little endian
        image[6] = 1; // ELF version
        image[7] = 9; // FreeBSD ABI, accepted by the loader
        image[8] = 2; // ABI version

        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x10), 3); // ET_DYN
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x12), 0x3E); // AMD64
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x14), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(0x18), guestEntry);
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(0x20), 0x40);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x34), 0x40);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x36), 0x38);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x38), 1);

        var programHeader = image.AsSpan(0x40, 0x38);
        BinaryPrimitives.WriteUInt32LittleEndian(programHeader, 1); // PT_LOAD
        BinaryPrimitives.WriteUInt32LittleEndian(programHeader[4..], 7); // R|W|X
        BinaryPrimitives.WriteUInt64LittleEndian(programHeader[8..], fileOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(programHeader[16..], guestEntry);
        BinaryPrimitives.WriteUInt64LittleEndian(programHeader[24..], guestEntry);
        BinaryPrimitives.WriteUInt64LittleEndian(programHeader[32..], (ulong)guestCode.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(programHeader[40..], (ulong)guestCode.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(programHeader[48..], 0x1000);
        guestCode.CopyTo(image.AsSpan(fileOffset));

        return image;
    }

    private sealed record GuestProcessResult(
        bool Completed,
        int ExitCode,
        double CpuSampleMilliseconds,
        string Output);
}
