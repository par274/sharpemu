// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services;

using System.Text.Json;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Portable play-history store used by the in-game overlay. Records are kept
/// beside the emulator's other user data and pruned after they can no longer
/// contribute to the rolling two-week statistic.
/// </summary>
internal sealed class GameActivityService : IGameActivityService
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
    };

    private static readonly TimeSpan Retention = TimeSpan.FromDays(35);

    private readonly object _gate = new();
    private readonly string _storagePath;
    private ActivityFile _activity;
    private ActiveSession? _activeSession;

    public GameActivityService()
        : this(Path.Combine(AppContext.BaseDirectory, "user", "activity.json"))
    {
    }

    internal GameActivityService(string storagePath)
    {
        _storagePath = storagePath;
        _activity = Load(storagePath);
    }

    public void BeginSession(string gameKey, DateTimeOffset startedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(gameKey);

        lock (_gate)
        {
            if (_activeSession is not null)
            {
                CompleteSessionCore(startedAt);
            }

            _activeSession = new ActiveSession(gameKey, startedAt);
            _activity.LastPlayedAt[gameKey] = startedAt;
            Save();
        }
    }

    public void CompleteSession(DateTimeOffset endedAt)
    {
        lock (_gate)
        {
            CompleteSessionCore(endedAt);
        }
    }

    public TimeSpan GetPlayedSince(string gameKey, DateTimeOffset since, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(gameKey) || now <= since)
        {
            return TimeSpan.Zero;
        }

        lock (_gate)
        {
            var ticks = _activity.Sessions
                .Where(session => session.GameKey.Equals(gameKey, StringComparison.OrdinalIgnoreCase))
                .Sum(session => OverlapTicks(session.StartedAt, session.EndedAt, since, now));

            if (_activeSession is { } active &&
                active.GameKey.Equals(gameKey, StringComparison.OrdinalIgnoreCase))
            {
                ticks += OverlapTicks(active.StartedAt, now, since, now);
            }

            return TimeSpan.FromTicks(ticks);
        }
    }

    public DateTimeOffset? GetLastPlayedAt(string gameKey)
    {
        if (string.IsNullOrWhiteSpace(gameKey))
        {
            return null;
        }

        lock (_gate)
        {
            return _activity.LastPlayedAt.TryGetValue(gameKey, out var lastPlayedAt)
                ? lastPlayedAt
                : null;
        }
    }

    private void CompleteSessionCore(DateTimeOffset endedAt)
    {
        if (_activeSession is not { } active)
        {
            return;
        }

        _activeSession = null;
        if (endedAt > active.StartedAt)
        {
            _activity.Sessions.Add(new ActivitySession
            {
                GameKey = active.GameKey,
                StartedAt = active.StartedAt,
                EndedAt = endedAt,
            });
        }

        var oldestRetained = endedAt - Retention;
        _activity.Sessions.RemoveAll(session => session.EndedAt < oldestRetained);
        Save();
    }

    private void Save()
    {
        try
        {
            var directory = Path.GetDirectoryName(_storagePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(
                _storagePath,
                JsonSerializer.Serialize(_activity, SerializerOptions));
        }
        catch (Exception)
        {
            // Play statistics are useful presentation data, never a reason to
            // fail an emulator shutdown.
        }
    }

    private static ActivityFile Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                var activity = JsonSerializer.Deserialize<ActivityFile>(json, SerializerOptions);
                if (activity is not null)
                {
                    activity.Sessions ??= [];
                    activity.Sessions.RemoveAll(session =>
                        string.IsNullOrWhiteSpace(session.GameKey) ||
                        session.EndedAt <= session.StartedAt);
                    activity.LastPlayedAt = new Dictionary<string, DateTimeOffset>(
                        activity.LastPlayedAt ?? [],
                        StringComparer.OrdinalIgnoreCase);

                    // Older activity files contain only sessions. Recover their
                    // most recent launch instead of showing "Not played yet"
                    // after upgrading.
                    foreach (var session in activity.Sessions)
                    {
                        if (!activity.LastPlayedAt.TryGetValue(session.GameKey, out var recorded) ||
                            session.StartedAt > recorded)
                        {
                            activity.LastPlayedAt[session.GameKey] = session.StartedAt;
                        }
                    }

                    return activity;
                }
            }
        }
        catch (Exception)
        {
            // Corrupt or unreadable history starts fresh.
        }

        return new ActivityFile();
    }

    private static long OverlapTicks(
        DateTimeOffset startedAt,
        DateTimeOffset endedAt,
        DateTimeOffset rangeStart,
        DateTimeOffset rangeEnd)
    {
        var start = startedAt > rangeStart ? startedAt : rangeStart;
        var end = endedAt < rangeEnd ? endedAt : rangeEnd;
        return end > start ? (end - start).Ticks : 0;
    }

    private sealed record ActiveSession(string GameKey, DateTimeOffset StartedAt);

    private sealed class ActivityFile
    {
        public List<ActivitySession> Sessions { get; set; } = [];

        public Dictionary<string, DateTimeOffset> LastPlayedAt { get; set; } =
            new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class ActivitySession
    {
        public string GameKey { get; set; } = string.Empty;

        public DateTimeOffset StartedAt { get; set; }

        public DateTimeOffset EndedAt { get; set; }
    }
}
