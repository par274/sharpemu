// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE.Host;

/// <summary>
/// Overflow-safe admission for one bounded host PCM submission. The caller
/// must wait and retry when this returns false because the current queue is
/// temporarily full.
/// </summary>
internal static class HostAudioQueueAdmission
{
    internal static bool Fits(
        int queuedPcmBytes,
        int pendingPcmBytes,
        int maximumQueuedPcmBytes)
    {
        if (queuedPcmBytes < 0 ||
            pendingPcmBytes < 0 ||
            maximumQueuedPcmBytes < 0 ||
            queuedPcmBytes > maximumQueuedPcmBytes)
        {
            return false;
        }

        // Subtract first so a malformed or very large pending length cannot
        // wrap an addition and pass the bound.
        return pendingPcmBytes <= maximumQueuedPcmBytes - queuedPcmBytes;
    }
}
