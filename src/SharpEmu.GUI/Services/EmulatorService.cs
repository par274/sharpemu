// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services;

using System.Globalization;
using SharpEmu.Core.Cpu;
using SharpEmu.Core.Runtime;
using SharpEmu.GUI.Services.Abstractions;
using SharpEmu.Logging;

/// <summary>
/// Owns the isolated emulator process and the launch options applied to it.
/// Extracted verbatim from the MainWindow god-class: environment-variable
/// bookkeeping, effective-settings resolution, argument building, and the
/// <see cref="EmulatorProcess"/> lifecycle. Emits UI-thread-safe events; the
/// SessionViewModel and window subscribe instead of poking process state.
/// </summary>
internal sealed class EmulatorService : IEmulatorService
{
    // Names set on this process at the previous launch; children inherit the
    // process environment, so stale names must be cleared explicitly.
    private readonly HashSet<string> _appliedEnvironmentVariables = new(StringComparer.OrdinalIgnoreCase);
    private readonly ISettingsService _settings;

    private EmulatorProcess? _emulator;
    private EmulatorLaunchOptions? _pendingLaunch;
    private string? _emulatorExePath;

    public EmulatorService(ISettingsService settings)
    {
        _settings = settings;
    }

    public bool IsRunning => _emulator?.IsRunning == true;

    public string? EmulatorExePath => _emulatorExePath;

    public event Action<int>? Exited;
    public event Action<string, bool>? OutputReceived;

    public bool LocateEmulator()
    {
        var exeName = OperatingSystem.IsWindows() ? "SharpEmu.exe" : "SharpEmu";
        var baseDirectory = AppContext.BaseDirectory;
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(_settings.Settings.EmulatorPath))
        {
            candidates.Add(_settings.Settings.EmulatorPath);
        }

        // The GUI and CLI share one executable. The selected path is the
        // isolated child executable and also defines the portable data root.
        if (Environment.ProcessPath is { } selfPath &&
            Path.GetFileNameWithoutExtension(selfPath).Equals("SharpEmu", StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add(selfPath);
        }

        candidates.Add(Path.Combine(baseDirectory, exeName));
        candidates.Add(Path.Combine(baseDirectory, "win-x64", exeName));
        candidates.Add(Path.Combine(baseDirectory, "..", exeName));

        _emulatorExePath = candidates.FirstOrDefault(File.Exists) is { } found
            ? Path.GetFullPath(found)
            : null;

        return _emulatorExePath is not null;
    }

    public void PrepareLaunch(string ebootPath, string displayName, string? titleId)
    {
        if (IsRunning)
        {
            return;
        }

        var settings = _settings.Settings;
        // A title passed explicitly wins; otherwise look it up from the
        // scanned library by matching the eboot path.
        var resolvedTitleId = string.IsNullOrWhiteSpace(titleId)
            ? null
            : titleId;
        var effective = EffectiveLaunchSettings.Resolve(settings, PerGameSettings.Load(resolvedTitleId));

        // The isolated game child inherits these diagnostics. Keep them on the
        // launcher process so every platform receives the same launch options.
        foreach (var staleName in _appliedEnvironmentVariables)
        {
            if (!effective.EnvironmentToggles.Contains(staleName))
            {
                Environment.SetEnvironmentVariable(staleName, null);
            }
        }

        _appliedEnvironmentVariables.Clear();
        foreach (var name in effective.EnvironmentToggles)
        {
            Environment.SetEnvironmentVariable(name, "1");
            _appliedEnvironmentVariables.Add(name);
        }

        Environment.SetEnvironmentVariable(
            "SHARPEMU_RENDER_SCALE",
            settings.RenderResolutionScale.ToString("0.###", CultureInfo.InvariantCulture));

        if (SharpEmuLog.TryParseLevel(effective.LogLevel, out var logLevel))
        {
            SharpEmuLog.MinimumLevel = logLevel;
        }

        var runtimeOptions = new SharpEmuRuntimeOptions
        {
            CpuEngine = CpuExecutionEngine.NativeOnly,
            StrictDynlibResolution = effective.StrictDynlibResolution,
            ImportTraceLimit = Math.Max(0, effective.ImportTraceLimit),
        };

        _pendingLaunch = new EmulatorLaunchOptions(
            Path.GetFullPath(ebootPath),
            displayName,
            resolvedTitleId,
            effective.LogLevel,
            runtimeOptions);
    }

    public void StartPendingSession(
        string? childProcessDescriptor,
        string? overlayFrameDescriptor)
    {
        if (_pendingLaunch is not { } launch || _emulator is not null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_emulatorExePath))
        {
            Exited?.Invoke(3);
            return;
        }

        var process = new EmulatorProcess();
        process.OutputReceived += (line, isError) => OutputReceived?.Invoke(line, isError);
        process.Exited += code => Avalonia.Threading.Dispatcher.UIThread.Post(() => OnProcessExited(code));

        try
        {
            var arguments = BuildArguments(
                launch,
                childProcessDescriptor,
                overlayFrameDescriptor);
            _emulator = process;
            _pendingLaunch = null;
            process.Start(
                _emulatorExePath,
                arguments,
                Path.GetDirectoryName(_emulatorExePath));
        }
        catch (Exception)
        {
            _emulator = null;
            process.Dispose();
            Exited?.Invoke(3);
        }
    }

    public void Stop()
    {
        _emulator?.Stop();
    }

    public bool CancelPendingLaunch()
    {
        if (_pendingLaunch is null)
        {
            return false;
        }

        _pendingLaunch = null;
        return true;
    }

    private void OnProcessExited(int exitCode)
    {
        _emulator?.Dispose();
        _emulator = null;
        _pendingLaunch = null;
        Exited?.Invoke(exitCode);
    }

    private static List<string> BuildArguments(
        EmulatorLaunchOptions launch,
        string? childProcessDescriptor,
        string? overlayFrameDescriptor)
    {
        var arguments = new List<string>
        {
            "--cpu-engine=native",
            $"--log-level={launch.LogLevel}",
        };
        if (launch.RuntimeOptions.StrictDynlibResolution)
        {
            arguments.Add("--strict");
        }
        if (launch.RuntimeOptions.ImportTraceLimit > 0)
        {
            arguments.Add($"--trace-imports={launch.RuntimeOptions.ImportTraceLimit}");
        }

        // A null descriptor means embedded child surfaces are unavailable on
        // this platform (macOS Metal): the emulator opens its own window.
        if (!string.IsNullOrEmpty(childProcessDescriptor))
        {
            arguments.Add($"--host-surface={childProcessDescriptor}");
        }
        if (!string.IsNullOrEmpty(overlayFrameDescriptor))
        {
            arguments.Add($"--host-overlay={overlayFrameDescriptor}");
        }
        arguments.Add(launch.EbootPath);
        return arguments;
    }
}
