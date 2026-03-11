// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Collections.Concurrent;
using System.IO;

namespace SharpEmu.Logging;

public static class SharpEmuLog
{
    private static readonly ConcurrentDictionary<string, SharpEmuLogger> LoggerByCategory =
        new(StringComparer.Ordinal);
    private static readonly object ConfigurationSync = new();
    private static volatile LogLevel _minimumLevel = ResolveMinimumLevelFromEnvironment();
    private static ISharpEmuLogSink _sink = new ConsoleLogSink(
        useColors: ResolveColorEnabledFromEnvironment(),
        includeTimestamp: false);

    public static LogLevel MinimumLevel
    {
        get => _minimumLevel;
        set => _minimumLevel = value;
    }

    public static ISharpEmuLogSink Sink
    {
        get
        {
            lock (ConfigurationSync)
            {
                return _sink;
            }
        }

        set
        {
            ArgumentNullException.ThrowIfNull(value);
            lock (ConfigurationSync)
            {
                _sink = value;
            }
        }
    }

    public static void Configure(LogLevel? minimumLevel = null, ISharpEmuLogSink? sink = null)
    {
        if (minimumLevel.HasValue)
        {
            _minimumLevel = minimumLevel.Value;
        }

        if (sink is not null)
        {
            Sink = sink;
        }
    }

    public static SharpEmuLogger For(string category)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(category);
        return LoggerByCategory.GetOrAdd(category, static key => new SharpEmuLogger(key));
    }

    public static bool TryParseLevel(string? text, out LogLevel level)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            level = default;
            return false;
        }

        var normalized = text.Trim();
        if (Enum.TryParse<LogLevel>(normalized, ignoreCase: true, out level))
        {
            return true;
        }

        if (string.Equals(normalized, "warn", StringComparison.OrdinalIgnoreCase))
        {
            level = LogLevel.Warning;
            return true;
        }

        if (string.Equals(normalized, "fatal", StringComparison.OrdinalIgnoreCase))
        {
            level = LogLevel.Critical;
            return true;
        }

        return false;
    }

    internal static bool IsEnabled(LogLevel level)
    {
        var minimum = _minimumLevel;
        return minimum != LogLevel.None && level >= minimum;
    }

    internal static void Write(
        LogLevel level,
        string category,
        string message,
        Exception? exception,
        string sourceFilePath,
        int sourceLine,
        string sourceMemberName)
    {
        if (!IsEnabled(level))
        {
            return;
        }

        var entry = new LogEntry(
            DateTimeOffset.Now,
            level,
            category,
            message,
            Path.GetFileName(sourceFilePath),
            sourceLine,
            sourceMemberName,
            exception);

        ISharpEmuLogSink sink;
        lock (ConfigurationSync)
        {
            sink = _sink;
        }

        sink.Write(in entry);
    }

    private static LogLevel ResolveMinimumLevelFromEnvironment()
    {
        var raw = Environment.GetEnvironmentVariable("SHARPEMU_LOG_LEVEL");
        return TryParseLevel(raw, out var level) ? level : LogLevel.Info;
    }

    private static bool ResolveColorEnabledFromEnvironment()
    {
        if (Console.IsOutputRedirected)
        {
            return false;
        }

        var raw = Environment.GetEnvironmentVariable("SHARPEMU_LOG_NO_COLOR");
        return !IsTrueLike(raw);
    }

    private static bool IsTrueLike(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return text.Trim() switch
        {
            "1" => true,
            "true" => true,
            "TRUE" => true,
            "yes" => true,
            "YES" => true,
            "on" => true,
            "ON" => true,
            _ => false,
        };
    }
}
