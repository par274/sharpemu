// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Media;

namespace SharpEmu.GUI;

/// <summary>Console page: log buffer view, auto scroll and the detached window.</summary>
public partial class MainWindow
{
    private void WireConsole()
    {
        // Bind the shared buffer before the search handler is attached, so the
        // first filter pass always sees a populated list.
        _consoleLines = _logService.VisibleLines;
        ConsoleList.ItemsSource = _consoleLines;
        _consoleMirror = GuiConsoleMirror.Install((line, isError) =>
            _logService.Enqueue(line, isError));
        _consoleFlushTimer.Tick += (_, _) =>
        {
            _logService.Flush();
            MaybeAutoScroll();
        };
        _consoleFlushTimer.Start();

        ConsoleSearchBox.TextChanged += (_, _) => RefreshVisibleConsoleLines();
        ClearLogButton.Click += (_, _) => _logService.Clear();
        CopyLogButton.Click += async (_, _) => await CopyConsoleAsync();
        DetachConsoleButton.Click += (_, _) => ShowConsoleWindow();
    }

    private void ApplyConsoleLocalization()
    {
        var loc = Localization.Instance;

        ConsoleSearchBox.PlaceholderText = loc.Get("Console.SearchWatermark");
        AutoScrollCheck.Content = loc.Get("Console.AutoScroll");
        DetachConsoleButtonLabel.Text = loc.Get("Console.Split");
        CopyLogButtonLabel.Text = loc.Get("Console.Copy");
        ClearLogButtonLabel.Text = loc.Get("Console.Clear");
    }

    // ---- Console ----
    // The buffer, file mirroring and brush mapping live in ILogService now;
    // the methods below are thin pass-throughs for the few call sites that
    // still route through the window (e.g. GUI-authored lines with a UI brush).

    private void AppendConsoleLine(string text, IBrush brush)
    {
        _logService.Append(text, brush);
        _autoScrollTicks = 3;
        MaybeAutoScroll();
    }

    private void RefreshVisibleConsoleLines()
    {
        _logService.SearchQuery = ConsoleSearchBox.Text ?? string.Empty;
        _logService.RefreshVisible();
    }

    private void CloseFileLogSoon() => _logService.CloseFileLogSoon();

    private void MaybeAutoScroll()
    {
        // ScrollToEnd is applied over a few flush-timer ticks because the
        // virtualizing panel re-estimates its extent after large batches, and
        // a single scroll can land short of the true end. A synchronous
        // ScrollIntoView during rapid adds is avoided entirely — it can crash
        // the panel with "Invalid Arrange rectangle".
        if (_autoScrollTicks <= 0 || AutoScrollCheck.IsChecked != true)
        {
            return;
        }

        _autoScrollTicks--;
        (ConsoleList.Scroll as ScrollViewer)?.ScrollToEnd();
    }

    private async Task CopyConsoleAsync()
    {
        if (_consoleLines.Count == 0 || Clipboard is null)
        {
            return;
        }

        var text = string.Join(Environment.NewLine, _consoleLines.Select(line => line.Text));
        await Clipboard.SetTextAsync(text);
    }

    private void ShowConsoleWindow()
    {
        if (_consoleWindow is { } window)
        {
            window.Activate();
            return;
        }

        ConsoleSearchBox.Text = string.Empty;
        // The detached window shares the same log buffer as the inline panel,
        // owned by ILogService; clearing it clears both views.
        _consoleWindow = new ConsoleWindow(
            _logService.VisibleLines,
            () => _logService.Clear(),
            AutoScrollCheck.IsChecked == true);
        _consoleWindow.Closed += (_, _) =>
        {
            _consoleWindow = null;
        };
        _consoleWindow.Show(this);
    }
}
