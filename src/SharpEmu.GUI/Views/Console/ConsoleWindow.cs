// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Threading;
using System.Collections.Specialized;

namespace SharpEmu.GUI;

public sealed class ConsoleWindow : Window
{
    private readonly AvaloniaList<LogLine> _sourceLines;
    private readonly AvaloniaList<LogLine> _visibleLines = new();
    private readonly ListBox _list;
    private readonly TextBox _searchBox;
    private readonly CheckBox _autoScrollCheck;

    public ConsoleWindow(
        AvaloniaList<LogLine> lines,
        Action clear,
        bool autoScroll)
    {
        var loc = Localization.Instance;

        _sourceLines = lines;
        Title = loc.Get("Console.WindowTitle");
        Width = 980;
        Height = 620;
        MinWidth = 760;
        MinHeight = 380;
        Background = new SolidColorBrush(Color.Parse("#0C0C0C"));
        Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://SharpEmu.GUI/Assets/SharpEmu.ico")));

        _searchBox = new TextBox
        {
            Classes = { "consoleSearch" },
            PlaceholderText = loc.Get("Console.SearchWatermark"),
            Width = 288,
            InnerLeftContent = new TextBlock
            {
                Classes = { "materialSymbol", "compact", "consoleSearchIcon" },
                Text = "search",
            },
        };
        _autoScrollCheck = new CheckBox
        {
            Classes = { "consoleAutoScroll" },
            Content = loc.Get("Console.AutoScroll"),
            IsChecked = autoScroll,
            FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center,
        };
        var copyButton = CreateActionButton("content_copy", loc.Get("Console.Copy"));
        var clearButton = CreateActionButton("delete_sweep", loc.Get("Console.Clear"));
        copyButton.Click += async (_, _) => await CopyAsync();
        clearButton.Click += (_, _) => clear();
        _searchBox.TextChanged += (_, _) => RefreshVisibleLines();

        _list = new ListBox
        {
            Classes = { "console" },
            ItemsSource = _visibleLines,
            Padding = new Thickness(0, 0, 0, 12),
            BorderThickness = new Thickness(0, 1, 0, 0),
            BorderBrush = new SolidColorBrush(Color.Parse("#12FFFFFF")),
            ItemTemplate = new FuncDataTemplate<LogLine>((_, _) =>
            {
                var text = new TextBlock { TextWrapping = TextWrapping.NoWrap };
                text.Bind(TextBlock.TextProperty, new Binding(nameof(LogLine.Text)));
                text.Bind(TextBlock.ForegroundProperty, new Binding(nameof(LogLine.Brush)));
                return text;
            }),
        };

        var actions = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            VerticalAlignment = VerticalAlignment.Center,
            Spacing = 10,
            Children =
            {
                copyButton,
                clearButton,
            },
        };

        var header = new Grid
        {
            Margin = new Thickness(18, 14),
            ColumnDefinitions = new ColumnDefinitions("Auto,Auto,*,Auto"),
            ColumnSpacing = 10,
            Children =
            {
                _searchBox.WithGridColumn(0),
                _autoScrollCheck.WithGridColumn(1),
                actions.WithGridColumn(3),
            },
        };

        Content = new Grid
        {
            RowDefinitions = new RowDefinitions("Auto,*"),
            Children =
            {
                header,
                _list.WithGridRow(1),
            },
        };

        lines.CollectionChanged += OnLinesChanged;
        Closed += (_, _) => lines.CollectionChanged -= OnLinesChanged;
        RefreshVisibleLines();
    }

    private static Button CreateActionButton(string icon, string text)
    {
        return new Button
        {
            Classes = { "consoleAction" },
            Content = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center,
                Spacing = 8,
                Children =
                {
                    new TextBlock
                    {
                        Classes = { "materialSymbol", "compact" },
                        Text = icon,
                    },
                    new TextBlock
                    {
                        Text = text,
                        VerticalAlignment = VerticalAlignment.Center,
                    },
                },
            },
        };
    }

    private void OnLinesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        RefreshVisibleLines();
        if (_autoScrollCheck.IsChecked == true)
        {
            Dispatcher.UIThread.Post(() => (_list.Scroll as ScrollViewer)?.ScrollToEnd());
        }
    }

    private void RefreshVisibleLines()
    {
        var query = _searchBox.Text ?? string.Empty;
        _visibleLines.Clear();
        _visibleLines.AddRange(string.IsNullOrWhiteSpace(query)
            ? _sourceLines
            : _sourceLines.Where(line => line.Text.Contains(query, StringComparison.OrdinalIgnoreCase)));
    }

    private async Task CopyAsync()
    {
        if (_visibleLines.Count == 0 || Clipboard is null)
        {
            return;
        }

        await Clipboard.SetTextAsync(string.Join(Environment.NewLine, _visibleLines.Select(line => line.Text)));
    }
}

file static class GridExtensions
{
    public static T WithGridColumn<T>(this T control, int column) where T : Control
    {
        Grid.SetColumn(control, column);
        return control;
    }

    public static T WithGridRow<T>(this T control, int row) where T : Control
    {
        Grid.SetRow(control, row);
        return control;
    }
}
