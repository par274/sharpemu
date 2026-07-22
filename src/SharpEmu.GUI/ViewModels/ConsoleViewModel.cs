// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using System.Reactive.Linq;
using Avalonia.Collections;
using ReactiveUI;
using ReactiveUI.SourceGenerators;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// Backs the console panel: the visible log buffer (owned by
/// <see cref="ILogService"/>), the search filter and the autoscroll flag.
/// The heavy lifting (ring buffer, file mirroring, brush mapping) lives in the
/// service; this view-model only exposes what the XAML binds to.
/// </summary>
public partial class ConsoleViewModel : ReactiveObject
{
    private readonly ILogService _log;

    public ConsoleViewModel(ILogService log)
    {
        _log = log;

        // Re-apply the search filter when the query changes. Throttled so
        // typing does not rebuild the filtered buffer per keystroke.
        this.WhenAnyValue(x => x.SearchText)
            .Throttle(TimeSpan.FromMilliseconds(120))
            .Subscribe(query =>
            {
                _log.SearchQuery = query ?? string.Empty;
                Avalonia.Threading.Dispatcher.UIThread.Post(_log.RefreshVisible);
            });
    }

    /// <summary>The log lines the console list binds to (filtered by the query).</summary>
    public AvaloniaList<LogLine> Lines => _log.VisibleLines;

    [Reactive] private string _searchText = string.Empty;

    [Reactive] private bool _isAutoScroll = true;

    /// <summary>Clears the visible and full buffers.</summary>
    public void Clear() => _log.Clear();
}
