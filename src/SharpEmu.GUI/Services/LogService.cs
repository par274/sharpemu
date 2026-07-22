// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services;

using System.Collections.Concurrent;
using Avalonia.Collections;
using Avalonia.Media;
using Avalonia.Threading;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// In-memory ring buffer plus optional file mirroring for the launcher console.
/// Extracted verbatim from the MainWindow god-class; the flush cadence (timer
/// driven from the window) and brush mapping move here too so a ConsoleViewModel
/// only needs to bind to <see cref="VisibleLines"/>.
/// </summary>
internal sealed class LogService : ILogService
{
    private const int MaxConsoleLines = 4000;
    private const int MaxConsoleLinesPerFlush = 500;

    private static readonly IBrush DefaultLineBrush = new SolidColorBrush(Color.Parse("#C7CFDE"));
    private static readonly IBrush DimLineBrush = new SolidColorBrush(Color.Parse("#6B7488"));
    private static readonly IBrush InfoLineBrush = new SolidColorBrush(Color.Parse("#6FA8FF"));
    private static readonly IBrush WarningLineBrush = new SolidColorBrush(Color.Parse("#E8B341"));
    private static readonly IBrush ErrorLineBrush = new SolidColorBrush(Color.Parse("#F2777C"));

    private readonly ISettingsService _settings;
    private readonly List<LogLine> _allLines = new();
    private readonly ConcurrentQueue<(string Line, bool IsError)> _pending = new();
    private StreamWriter? _fileLog;
    private string? _emulatorExePath;

    public LogService(ISettingsService settings)
    {
        _settings = settings;
        VisibleLines = new AvaloniaList<LogLine>();
    }

    public AvaloniaList<LogLine> VisibleLines { get; }

    public string SearchQuery { get; set; } = string.Empty;

    /// <summary>The emulator exe path, used to resolve the default logs directory.</summary>
    public void SetEmulatorExePath(string? path) => _emulatorExePath = path;

    public void Enqueue(string line, bool isError) => _pending.Enqueue((line, isError));

    public void Append(string text, IBrush brush)
    {
        WriteFileLog(text);
        FlushFileLog();

        var line = new LogLine(text, brush);
        _allLines.Add(line);

        var query = SearchQuery;
        if (string.IsNullOrWhiteSpace(query) ||
            (text != null && text.Contains(query, StringComparison.OrdinalIgnoreCase)))
        {
            VisibleLines.Add(line);
        }

        TrimOverflow();
    }

    public void Flush()
    {
        if (_pending.IsEmpty)
        {
            return;
        }

        var incoming = new List<LogLine>();
        while (incoming.Count < MaxConsoleLinesPerFlush &&
               _pending.TryDequeue(out var pending))
        {
            WriteFileLog(pending.Line);
            incoming.Add(new LogLine(pending.Line, BrushForLine(pending.Line)));
        }

        FlushFileLog();

        _allLines.AddRange(incoming);

        var query = SearchQuery;
        IEnumerable<LogLine> linesToAdd = incoming;
        if (!string.IsNullOrWhiteSpace(query))
        {
            linesToAdd = incoming.Where(line =>
                line.Text != null &&
                line.Text.Contains(query, StringComparison.OrdinalIgnoreCase));
        }
        VisibleLines.AddRange(linesToAdd);

        TrimOverflow();
    }

    public void Clear()
    {
        VisibleLines.Clear();
        _allLines.Clear();
    }

    /// <summary>Refreshes the visible list from the full buffer against the query.</summary>
    public void RefreshVisible()
    {
        VisibleLines.Clear();

        var query = SearchQuery;
        if (string.IsNullOrWhiteSpace(query))
        {
            VisibleLines.AddRange(_allLines);
        }
        else
        {
            var filtered = _allLines.Where(line =>
                line.Text != null &&
                line.Text.Contains(query, StringComparison.OrdinalIgnoreCase));
            VisibleLines.AddRange(filtered);
        }
    }

    public void OpenFileLog(string? titleId)
    {
        var filePath = ResolveLogFilePath(titleId);
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return;
        }

        try
        {
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            _fileLog = new StreamWriter(filePath, append: false) { AutoFlush = true };
        }
        catch (Exception)
        {
            DropFileLog();
        }
    }

    public void CloseFileLogSoon()
    {
        if (_fileLog is not { } writer)
        {
            return;
        }

        DispatcherTimer.RunOnce(() =>
        {
            if (ReferenceEquals(_fileLog, writer))
            {
                Flush();
                DropFileLog();
            }
        }, TimeSpan.FromMilliseconds(400));
    }

    public void DropFileLog()
    {
        var writer = _fileLog;
        _fileLog = null;
        try
        {
            writer?.Dispose();
        }
        catch (Exception)
        {
        }
    }

    private void TrimOverflow()
    {
        while (_allLines.Count > MaxConsoleLines)
        {
            var droppedLine = _allLines[0];
            _allLines.RemoveAt(0);
            if (VisibleLines.Count > 0 && VisibleLines[0] == droppedLine)
            {
                VisibleLines.RemoveAt(0);
            }
        }
    }

    private void WriteFileLog(string text)
    {
        if (_fileLog is not { } writer)
        {
            return;
        }

        try
        {
            writer.Write('[');
            writer.Write(DateTime.Now.ToString("HH:mm:ss.fff"));
            writer.Write("] ");
            writer.WriteLine(text);
        }
        catch (Exception)
        {
            DropFileLog(); // unwritable (disk full, etc.): stop mirroring
        }
    }

    private void FlushFileLog()
    {
        try
        {
            _fileLog?.Flush();
        }
        catch (Exception)
        {
            DropFileLog();
        }
    }

    private string? ResolveLogFilePath(string? titleId)
    {
        var s = _settings.Settings;
        if (string.IsNullOrWhiteSpace(s.LogFilePath))
        {
            return BuildLogFilePath(titleId);
        }

        if (s.OverrideLogFile)
        {
            return s.LogFilePath;
        }

        var path = s.LogFilePath;
        var id = string.IsNullOrWhiteSpace(titleId) ? "UNKNOWN" : titleId;
        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            id = id.Replace(invalid.ToString(), string.Empty, StringComparison.Ordinal);
        }

        var directory = Path.GetDirectoryName(path);
        var filename = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        var timestampedName = $"{filename}-{id}-{DateTime.Now:yyyyMMdd-HHmmss}{extension}";
        return string.IsNullOrEmpty(directory) ? timestampedName : Path.Combine(directory, timestampedName);
    }

    private string? BuildLogFilePath(string? titleId)
    {
        try
        {
            var exeDirectory = Path.GetDirectoryName(_emulatorExePath) ?? AppContext.BaseDirectory;
            if (string.IsNullOrEmpty(exeDirectory))
            {
                return null;
            }

            var logsDirectory = Path.Combine(exeDirectory, "user", "logs");
            Directory.CreateDirectory(logsDirectory);

            var id = string.IsNullOrWhiteSpace(titleId) ? "UNKNOWN" : titleId;
            foreach (var invalid in Path.GetInvalidFileNameChars())
            {
                id = id.Replace(invalid, '_');
            }

            return Path.Combine(logsDirectory, $"{id}-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        }
        catch (Exception)
        {
            return null; // unwritable location: launch continues without a log file
        }
    }

    private static IBrush BrushForLine(string line)
    {
        if (line.Contains("[ERROR]", StringComparison.Ordinal) ||
            line.Contains("[CRITICAL]", StringComparison.Ordinal))
        {
            return ErrorLineBrush;
        }

        if (line.Contains("[WARNING]", StringComparison.Ordinal))
        {
            return WarningLineBrush;
        }

        if (line.Contains("[INFO]", StringComparison.Ordinal))
        {
            return InfoLineBrush;
        }

        if (line.Contains("[DEBUG]", StringComparison.Ordinal) ||
            line.Contains("[TRACE]", StringComparison.Ordinal))
        {
            return DimLineBrush;
        }

        return DefaultLineBrush;
    }
}
