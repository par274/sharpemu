// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Libs.Audio;

/// <summary>
/// Stable diagnostic identities for the host audio sources that can overlap
/// during movie startup. These are ownership identities, not backend stream
/// numbers or guest handles.
/// </summary>
internal enum HostAudioSourceOwner
{
    Movie,
    AudioOut2,
    AudioOut,
}

/// <summary>
/// Immutable, bounded source-isolation selection. It is created once from the
/// opt-in environment switch and performs no parsing or allocation per buffer.
/// </summary>
internal readonly struct HostAudioSourceIsolationSelection
{
    private const int MovieMask = 1 << (int)HostAudioSourceOwner.Movie;
    private const int AudioOut2Mask = 1 << (int)HostAudioSourceOwner.AudioOut2;
    private const int AudioOutMask = 1 << (int)HostAudioSourceOwner.AudioOut;

    private readonly int _mask;

    private HostAudioSourceIsolationSelection(int mask)
    {
        _mask = mask;
    }

    internal bool IsEnabled => _mask != 0;

    internal static HostAudioSourceIsolationSelection Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return default;
        }

        var mask = 0;
        foreach (var rawToken in value.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var token = rawToken.Trim();
            if (token.Equals("movie", StringComparison.OrdinalIgnoreCase))
            {
                mask |= MovieMask;
            }
            else if (token.Equals("audio-out2", StringComparison.OrdinalIgnoreCase))
            {
                mask |= AudioOut2Mask;
            }
            else if (token.Equals("audio-out", StringComparison.OrdinalIgnoreCase))
            {
                mask |= AudioOutMask;
            }
            else
            {
                throw new ArgumentException(
                    $"Unknown host audio isolation owner '{token}'. " +
                    "Use movie, audio-out2, or audio-out.",
                    nameof(value));
            }
        }

        return new HostAudioSourceIsolationSelection(mask);
    }

    internal bool IsSelected(HostAudioSourceOwner owner) =>
        (_mask & (1 << (int)owner)) != 0;

    /// <summary>
    /// Replaces selected PCM samples in the caller-owned submission buffer.
    /// The span length and its ownership remain unchanged; no payload is kept.
    /// </summary>
    internal void SilenceIfSelected(
        HostAudioSourceOwner owner,
        Span<byte> pcm)
    {
        if (IsSelected(owner))
        {
            pcm.Clear();
        }
    }
}

internal static class HostAudioSourceIsolation
{
    internal const string EnvironmentVariable = "SHARPEMU_AUDIO_ISOLATE";

    internal static HostAudioSourceIsolationSelection Current { get; } =
        HostAudioSourceIsolationSelection.Parse(
            Environment.GetEnvironmentVariable(EnvironmentVariable));
}
