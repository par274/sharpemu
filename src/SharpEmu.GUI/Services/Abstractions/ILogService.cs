// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Abstractions;

using Avalonia.Media;

/// <summary>
/// Owns the launcher's console log: an in-memory ring buffer plus optional
/// file mirroring. The MainWindow previously ran the buffer, flush timer and
/// file writer inline; extracting them here lets a ConsoleViewModel bind to
/// the buffer and keeps the file lifecycle testable.
/// </summary>
public interface ILogService
{
    /// <summary>The filtered, visible log lines (what the console list binds to).</summary>
    Avalonia.Collections.AvaloniaList<LogLine> VisibleLines { get; }

    /// <summary>The search query applied to the visible list.</summary>
    string SearchQuery { get; set; }

    /// <summary>Enqueues a line received from Console.Out/Err or the emulator pipe.</summary>
    void Enqueue(string line, bool isError);

    /// <summary>Appends a GUI-authored line immediately (not queued).</summary>
    void Append(string text, IBrush brush);

    /// <summary>Flushes queued lines into the buffer, capping the ring size.</summary>
    void Flush();

    /// <summary>Clears both the visible and full buffers.</summary>
    void Clear();

    /// <summary>Refreshes the visible list from the full buffer against the current query.</summary>
    void RefreshVisible();

    /// <summary>Sets the emulator exe path, used to resolve the default logs directory.</summary>
    void SetEmulatorExePath(string? path);

    /// <summary>Opens a file log for a launched title, applying override settings.</summary>
    void OpenFileLog(string? titleId);

    /// <summary>Closes the file log after a short delay (lets late pipe data land).</summary>
    void CloseFileLogSoon();

    /// <summary>Drops the file log immediately.</summary>
    void DropFileLog();
}
