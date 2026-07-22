// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using SharpEmu.GUI.ViewModels;

namespace SharpEmu.GUI;

public sealed class PerGameSettingsDialog : Window
{
    private readonly PerGameSettingsViewModel _vm;

    private readonly SettingRow _logLevelRow;
    private readonly ComboBox _logLevel = new() { Width = 160 };

    private readonly SettingRow _traceRow;
    private readonly NumericUpDown _trace = new()
    {
        Minimum = 0, Maximum = 4096, Increment = 16, Width = 160, FormatString = "0",
    };

    private readonly SettingRow _strictRow;
    private readonly ToggleSwitch _strict = new();

    private readonly SettingRow _logToFileRow;
    private readonly ToggleSwitch _logToFile = new();

    private readonly SettingRow _envRow;
    private readonly StackPanel _envList = new() { Orientation = Orientation.Vertical, Spacing = 8, Margin = new(0, 4, 0, 0) };
    private readonly List<(string Name, ToggleSwitch Box)> _envBoxes = new();

    /// <summary>
    /// Opens a per-game settings dialog. The editable state lives in
    /// <paramref name="vm"/>; this window only builds the controls and pushes
    /// their final values back into the VM on save.
    /// </summary>
    public PerGameSettingsDialog(PerGameSettingsViewModel vm)
    {
        _vm = vm;
        var loc = Localization.Instance;

        Title = vm.Title;
        Width = 520;
        MaxHeight = 720;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        CanResize = false;

        Background = new SolidColorBrush(Color.Parse("#0D1017"));

        _logLevel.ItemsSource = PerGameSettingsViewModel.LogLevels;
        _strict.OnContent = _logToFile.OnContent = loc.Get("Common.On");
        _strict.OffContent = _logToFile.OffContent = loc.Get("Common.Off");

        _logLevelRow = Row(loc.Get("Options.LogLevel.Label"), loc.Get("Options.LogLevel.Desc"), _logLevel);
        _traceRow = Row(loc.Get("Options.TraceImports.Label"), loc.Get("Options.TraceImports.Desc"), _trace);
        _strictRow = Row(loc.Get("Options.Strict.Label"), loc.Get("Options.Strict.Desc"), _strict);
        _logToFileRow = Row(loc.Get("Options.LogToFile.Label"), loc.Get("Options.LogToFile.Desc"), _logToFile);
        _envRow = new SettingRow
        {
            Label = loc.Get("PerGame.EnvToggles.Label"),
            Description = loc.Get("PerGame.EnvToggles.Desc"),
            ShowOverride = true,
        };

        foreach (var name in PerGameSettingsViewModel.EnvironmentToggleNames)
        {
            var box = new ToggleSwitch { OnContent = name, OffContent = name };
            _envBoxes.Add((name, box));
            _envList.Children.Add(box);
        }

        var content = new StackPanel { Orientation = Orientation.Vertical, Spacing = 12, Margin = new(16) };
        content.Children.Add(new TextBlock
        {
            Text = loc.Get("PerGame.InheritNote"),
            Foreground = new SolidColorBrush(Color.Parse("#8B94A7")),
            FontSize = 12,
        });
        content.Children.Add(Card(loc.Get("Options.Section.Emulation"), _strictRow));
        content.Children.Add(Card(loc.Get("Options.Section.Logging"), _logLevelRow, _traceRow, _logToFileRow));
        content.Children.Add(Card(loc.Get("Options.Section.Environment"), _envRow, _envList));

        var save = new Button { Content = loc.Get("Common.Save"), Classes = { "accent" } };
        var cancel = new Button { Content = loc.Get("Common.Cancel"), Classes = { "ghost" } };
        save.Click += (_, _) => { Persist(); Close(); };
        cancel.Click += (_, _) => Close();

        var buttonBar = new Border
        {
            BorderBrush = new SolidColorBrush(Color.Parse("#8B94A7")) { Opacity = 0.25 },
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new(16),
            Child = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                HorizontalAlignment = HorizontalAlignment.Right,
                Children = { cancel, save },
            },
        };

        var root = new Grid { RowDefinitions = new RowDefinitions("*,Auto") };
        var scroller = new ScrollViewer { Content = content };
        Grid.SetRow(scroller, 0);
        Grid.SetRow(buttonBar, 1);
        root.Children.Add(scroller);
        root.Children.Add(buttonBar);
        Content = root;

        LoadFromVm();
        _envRow.PropertyChanged += (_, e) =>
        {
            if (e.Property == SettingRow.IsOverriddenProperty)
            {
                _envList.IsEnabled = _envRow.IsOverridden;
            }
        };
        _envList.IsEnabled = _envRow.IsOverridden;
    }

    private static SettingRow Row(string label, string description, Control value) => new()
    {
        Label = label,
        Description = description,
        ShowOverride = true,
        Content = value,
    };

    private static Border Card(string title, params Control[] rows)
    {
        var stack = new StackPanel { Orientation = Orientation.Vertical, Spacing = 14 };
        stack.Children.Add(new TextBlock { Text = title, Classes = { "sectionTitle" } });
        foreach (var row in rows)
        {
            stack.Children.Add(row);
        }

        var card = new Border { Child = stack };
        card.Classes.Add("card");
        return card;
    }

    /// <summary>Seeds the controls from the view-model's resolved state.</summary>
    private void LoadFromVm()
    {
        _logLevel.SelectedItem = _vm.SelectedLogLevel;
        _trace.Value = _vm.ImportTraceLimit;
        _strict.IsChecked = _vm.IsStrictDynlibResolution;
        _logToFile.IsChecked = _vm.IsLogToFile;
        foreach (var (name, box) in _envBoxes)
        {
            box.IsChecked = _vm.GetEnvironment(name);
        }

        _logLevelRow.IsOverridden = _vm.IsLogLevelOverridden;
        _traceRow.IsOverridden = _vm.IsImportTraceOverridden;
        _strictRow.IsOverridden = _vm.IsStrictOverridden;
        _logToFileRow.IsOverridden = _vm.IsLogToFileOverridden;
        _envRow.IsOverridden = _vm.IsEnvironmentOverridden;
    }

    /// <summary>Pushes the control values back into the VM and persists.</summary>
    private void Persist()
    {
        _vm.IsLogLevelOverridden = _logLevelRow.IsOverridden;
        _vm.SelectedLogLevel = (string?)_logLevel.SelectedItem ?? "Info";
        _vm.IsImportTraceOverridden = _traceRow.IsOverridden;
        _vm.ImportTraceLimit = (int)(_trace.Value ?? 0);
        _vm.IsStrictOverridden = _strictRow.IsOverridden;
        _vm.IsStrictDynlibResolution = _strict.IsChecked == true;
        _vm.IsLogToFileOverridden = _logToFileRow.IsOverridden;
        _vm.IsLogToFile = _logToFile.IsChecked == true;
        _vm.IsEnvironmentOverridden = _envRow.IsOverridden;
        foreach (var (name, box) in _envBoxes)
        {
            _vm.SetEnvironment(name, box.IsChecked == true);
        }

        _vm.Save();
    }
}

