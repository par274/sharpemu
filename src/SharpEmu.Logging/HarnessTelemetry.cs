// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;
using System.Text.Json;

namespace SharpEmu.Logging;

/// <summary>
/// Optional, local-only structured diagnostics for the external agent harness.
/// The default null session makes all instrumentation calls behavior-neutral.
/// </summary>
public static class HarnessTelemetry
{
    private static Session? _session;

    public static bool IsEnabled => Volatile.Read(ref _session) is not null;

    public static void Configure(string configurationPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationPath);
        var fullPath = Path.GetFullPath(configurationPath);
        using var document = JsonDocument.Parse(File.ReadAllText(fullPath));
        var root = document.RootElement;
        var schemaVersion = root.GetProperty("schemaVersion").GetString();
        if (!string.Equals(schemaVersion, "1.0.0", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Unsupported harness configuration schema '{schemaVersion}'.");
        }

        var eventsPath = Path.GetFullPath(root.GetProperty("eventsPath").GetString()
            ?? throw new InvalidDataException("Harness eventsPath is required."));
        var frameDirectory = Path.GetFullPath(root.GetProperty("rawFrameDirectory").GetString()
            ?? throw new InvalidDataException("Harness rawFrameDirectory is required."));
        var redactionRoots = root.TryGetProperty("redactionRoots", out var roots)
            ? roots.EnumerateArray().Select(item => Path.GetFullPath(item.GetString()!)).ToArray()
            : [];
        var capture = root.TryGetProperty("capture", out var captureElement)
            ? CaptureConfiguration.Parse(captureElement)
            : new CaptureConfiguration(false, true, [], 0, 0);
        Directory.CreateDirectory(Path.GetDirectoryName(eventsPath)!);
        Directory.CreateDirectory(frameDirectory);
        var session = new Session(eventsPath, frameDirectory, redactionRoots, capture);
        var previous = Interlocked.Exchange(ref _session, session);
        previous?.Dispose();
    }

    public static void Emit(string kind, int? milestone = null, object? data = null)
    {
        var session = Volatile.Read(ref _session);
        session?.Emit(kind, milestone, data);
    }

    public static string Redact(string value)
    {
        var session = Volatile.Read(ref _session);
        return session?.Redact(value) ?? value;
    }

    public static bool ShouldCaptureNativeFrame(long frameNumber)
    {
        var session = Volatile.Read(ref _session);
        return session?.ShouldCapture(frameNumber) == true;
    }

    public static void WriteNativeFrame(
        ReadOnlySpan<byte> bytes,
        int width,
        int height,
        int rowPitch,
        string format,
        long frameNumber,
        string? colorSpace = null,
        bool flipVertical = false)
    {
        var session = Volatile.Read(ref _session);
        session?.WriteNativeFrame(bytes, width, height, rowPitch, format, frameNumber, colorSpace, flipVertical);
    }

    public static void Shutdown()
    {
        var session = Interlocked.Exchange(ref _session, null);
        session?.Dispose();
    }

    private sealed class Session : IDisposable
    {
        private readonly object _sync = new();
        private readonly StreamWriter _events;
        private readonly string _frameDirectory;
        private readonly string[] _redactionRoots;
        private readonly CaptureConfiguration _capture;
        private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
        private readonly HashSet<long> _requestedFrames = [];
        private long _sequence;
        private int _capturedFrames;
        private bool _disposed;

        public Session(string eventsPath, string frameDirectory, string[] redactionRoots, CaptureConfiguration capture)
        {
            _events = new StreamWriter(eventsPath, append: true) { AutoFlush = true };
            _frameDirectory = frameDirectory;
            _redactionRoots = redactionRoots;
            _capture = capture;
        }

        public void Emit(string kind, int? milestone, object? data)
        {
            lock (_sync)
            {
                if (_disposed) return;
                var entry = new
                {
                    schemaVersion = "1.0.0",
                    sequence = ++_sequence,
                    utcTimestamp = DateTimeOffset.UtcNow,
                    monotonicMilliseconds = _stopwatch.Elapsed.TotalMilliseconds,
                    kind,
                    milestone,
                    data,
                };
                var json = JsonSerializer.Serialize(entry);
                foreach (var root in _redactionRoots)
                {
                    json = json.Replace(JsonEncodedText.Encode(root).ToString(), $"<private-root-{Array.IndexOf(_redactionRoots, root) + 1}>", StringComparison.OrdinalIgnoreCase);
                    json = json.Replace(root, $"<private-root-{Array.IndexOf(_redactionRoots, root) + 1}>", StringComparison.OrdinalIgnoreCase);
                }
                _events.WriteLine(json);
            }
        }

        public string Redact(string value)
        {
            for (var index = 0; index < _redactionRoots.Length; index++)
            {
                value = value.Replace(_redactionRoots[index], $"<private-root-{index + 1}>", StringComparison.OrdinalIgnoreCase);
            }
            return value;
        }

        public bool ShouldCapture(long frameNumber)
        {
            if (!_capture.Enabled || _capture.MaxFrames <= 0) return false;
            lock (_sync)
            {
                if (_disposed || _capturedFrames >= _capture.MaxFrames || _requestedFrames.Contains(frameNumber)) return false;
                var requested = _capture.FirstFrame && frameNumber == 1 ||
                    _capture.FrameNumbers.Contains(frameNumber) ||
                    _capture.Interval > 0 && frameNumber % _capture.Interval == 0;
                if (!requested) return false;
                _requestedFrames.Add(frameNumber);
                _capturedFrames++;
                return true;
            }
        }

        public void WriteNativeFrame(ReadOnlySpan<byte> bytes, int width, int height, int rowPitch, string format, long frameNumber, string? colorSpace, bool flipVertical)
        {
            lock (_sync)
            {
                if (_disposed) return;
                var stem = $"native-{frameNumber:D8}";
                var rawFile = stem + ".raw";
                File.WriteAllBytes(Path.Combine(_frameDirectory, rawFile), bytes.ToArray());
                var descriptor = new
                {
                    rawFile,
                    width,
                    height,
                    rowPitch,
                    format,
                    captureSource = "emulator-native-final-frame",
                    frameNumber,
                    elapsedSeconds = _stopwatch.Elapsed.TotalSeconds,
                    utcTimestamp = DateTimeOffset.UtcNow,
                    colorSpace,
                    flipVertical,
                    nearestMilestone = "first-frame-available",
                };
                File.WriteAllText(Path.Combine(_frameDirectory, stem + ".raw.json"), JsonSerializer.Serialize(descriptor));
                Emit("capture.frame-written", 10, new { frameNumber, width, height, format, rawFile });
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                _events.Dispose();
            }
        }
    }

    private sealed record CaptureConfiguration(bool Enabled, bool FirstFrame, long[] FrameNumbers, int Interval, int MaxFrames)
    {
        public static CaptureConfiguration Parse(JsonElement element) => new(
            element.TryGetProperty("enabled", out var enabled) && enabled.GetBoolean(),
            !element.TryGetProperty("firstFrame", out var firstFrame) || firstFrame.GetBoolean(),
            element.TryGetProperty("frameNumbers", out var numbers) ? numbers.EnumerateArray().Select(item => item.GetInt64()).ToArray() : [],
            element.TryGetProperty("interval", out var interval) ? Math.Max(0, interval.GetInt32()) : 0,
            element.TryGetProperty("maxFrames", out var maximum) ? Math.Clamp(maximum.GetInt32(), 0, 8) : 0);
    }
}
