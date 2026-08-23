// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace SharpEmu.Logging;

[Flags]
public enum DiagnosticCategory
{
    None = 0,
    Imports = 1 << 0,
    AgcUnsupported = 1 << 1,
    AgcShaders = 1 << 2,
    AgcPackets = 1 << 3,
    AgcDraws = 1 << 4,
    Memory = 1 << 5,
    Video = 1 << 6,
    All = Imports | AgcUnsupported | AgcShaders | AgcPackets | AgcDraws | Memory | Video,
}

public enum DiagnosticProfile
{
    Off,
    Compatibility,
    Full,
    Custom,
}

/// <summary>
/// Central, runtime-configurable diagnostics gate. The default profile is Off.
/// Its interpolated-string handler prevents argument evaluation and allocation
/// when a category is disabled, while enabled messages use a bounded background
/// writer so guest/GPU threads never wait on console or file I/O.
/// </summary>
public static class SharpEmuDiagnostics
{
    public const string ProfileEnvironmentName = "SHARPEMU_DIAGNOSTICS_PROFILE";
    public const string CategoriesEnvironmentName = "SHARPEMU_DIAGNOSTICS_CATEGORIES";
    private const int QueueCapacity = 4096;

    private static readonly object WriterGate = new();
    private static int _profile = (int)ResolveEnvironmentProfile();
    private static int _enabledCategories =
        (int)ResolveCategories((DiagnosticProfile)_profile, ResolveEnvironmentCategories());
    private static Channel<string>? _messages;
    private static Task? _writerTask;
    private static long _enqueuedMessages;
    private static long _droppedMessages;

    public static DiagnosticProfile Profile =>
        (DiagnosticProfile)Volatile.Read(ref _profile);

    public static DiagnosticCategory EnabledCategories =>
        (DiagnosticCategory)Volatile.Read(ref _enabledCategories);

    public static long EnqueuedMessages => Interlocked.Read(ref _enqueuedMessages);

    public static long DroppedMessages => Interlocked.Read(ref _droppedMessages);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsEnabled(DiagnosticCategory category) =>
        category != DiagnosticCategory.None &&
        (Volatile.Read(ref _enabledCategories) & (int)category) != 0;

    public static void Configure(
        DiagnosticProfile profile,
        DiagnosticCategory customCategories = DiagnosticCategory.None)
    {
        var categories = ResolveCategories(profile, customCategories);
        Volatile.Write(ref _enabledCategories, (int)categories);
        Volatile.Write(ref _profile, (int)profile);
    }

    public static void Configure(string? profile, IEnumerable<string>? customCategories)
    {
        Configure(
            ParseProfile(profile),
            ParseCategories(customCategories));
    }

    public static DiagnosticProfile ParseProfile(string? value) =>
        Enum.TryParse<DiagnosticProfile>(value?.Trim(), ignoreCase: true, out var profile) &&
        Enum.IsDefined(profile)
            ? profile
            : DiagnosticProfile.Off;

    public static DiagnosticCategory ParseCategories(IEnumerable<string>? values)
    {
        var categories = DiagnosticCategory.None;
        if (values is null)
        {
            return categories;
        }

        foreach (var value in values)
        {
            if (Enum.TryParse<DiagnosticCategory>(value?.Trim(), ignoreCase: true, out var category) &&
                category is not DiagnosticCategory.None and not DiagnosticCategory.All &&
                Enum.IsDefined(category))
            {
                categories |= category;
            }
        }

        return categories;
    }

    public static List<string> CategoryNames(DiagnosticCategory categories) =>
        Enum.GetValues<DiagnosticCategory>()
            .Where(category =>
                category is not DiagnosticCategory.None and not DiagnosticCategory.All &&
                (categories & category) != 0)
            .Select(static category => category.ToString())
            .ToList();

    public static DiagnosticCategory ResolveCategories(
        DiagnosticProfile profile,
        DiagnosticCategory customCategories = DiagnosticCategory.None) =>
        profile switch
        {
            DiagnosticProfile.Compatibility =>
                DiagnosticCategory.Imports | DiagnosticCategory.AgcUnsupported,
            DiagnosticProfile.Full => DiagnosticCategory.All,
            DiagnosticProfile.Custom => customCategories & DiagnosticCategory.All,
            _ => DiagnosticCategory.None,
        };

    public static void Write(
        DiagnosticCategory category,
        [InterpolatedStringHandlerArgument(nameof(category))]
        ref DiagnosticMessageInterpolatedStringHandler message)
    {
        if (message.Enabled)
        {
            Enqueue(message.ToStringAndClear());
        }
    }

    public static void Write(DiagnosticCategory category, string message)
    {
        if (IsEnabled(category))
        {
            Enqueue(message);
        }
    }

    public static void Shutdown()
    {
        Task? writerTask;
        lock (WriterGate)
        {
            _messages?.Writer.TryComplete();
            writerTask = _writerTask;
            _messages = null;
            _writerTask = null;
        }

        if (writerTask is null)
        {
            return;
        }

        try
        {
            writerTask.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
        }
    }

    private static DiagnosticProfile ResolveEnvironmentProfile() =>
        ParseProfile(Environment.GetEnvironmentVariable(ProfileEnvironmentName));

    private static DiagnosticCategory ResolveEnvironmentCategories()
    {
        var value = Environment.GetEnvironmentVariable(CategoriesEnvironmentName);
        return ParseCategories(value?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    private static void Enqueue(string message)
    {
        var channel = EnsureWriter();
        if (channel.Writer.TryWrite(message))
        {
            Interlocked.Increment(ref _enqueuedMessages);
        }
        else
        {
            Interlocked.Increment(ref _droppedMessages);
        }
    }

    private static Channel<string> EnsureWriter()
    {
        lock (WriterGate)
        {
            if (_messages is not null)
            {
                return _messages;
            }

            _messages = Channel.CreateBounded<string>(new BoundedChannelOptions(QueueCapacity)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false,
            });
            var reader = _messages.Reader;
            _writerTask = Task.Run(async () =>
            {
                await foreach (var line in reader.ReadAllAsync().ConfigureAwait(false))
                {
                    Console.Error.WriteLine(line);
                }
            });
            return _messages;
        }
    }
}

[InterpolatedStringHandler]
public ref struct DiagnosticMessageInterpolatedStringHandler
{
    private DefaultInterpolatedStringHandler _inner;

    public DiagnosticMessageInterpolatedStringHandler(
        int literalLength,
        int formattedCount,
        DiagnosticCategory category,
        out bool shouldAppend)
    {
        Enabled = SharpEmuDiagnostics.IsEnabled(category);
        shouldAppend = Enabled;
        _inner = Enabled
            ? new DefaultInterpolatedStringHandler(literalLength, formattedCount)
            : default;
    }

    public bool Enabled { get; }

    public void AppendLiteral(string value) => _inner.AppendLiteral(value);

    public void AppendFormatted<T>(T value) => _inner.AppendFormatted(value);

    public void AppendFormatted<T>(T value, string? format) =>
        _inner.AppendFormatted(value, format);

    public string ToStringAndClear() =>
        Enabled ? _inner.ToStringAndClear() : string.Empty;
}
