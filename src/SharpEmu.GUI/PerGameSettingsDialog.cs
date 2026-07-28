// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using SharpEmu.Libs.VideoOut;

namespace SharpEmu.GUI;

public sealed class PerGameSettingsDialog : Window
{
    private static readonly string[] LogLevels =
        { "Trace", "Debug", "Info", "Warning", "Error", "Critical" };
    private static readonly string[] WindowModes = { "Windowed", "Borderless", "Exclusive" };
    private static readonly string[] ScalingModes = { "Fit", "Cover", "Stretch", "Integer" };
    private static readonly string[] HdrModes = { "Auto", "On", "Off" };

    private static readonly string[] EnvToggles =
    {
        "SHARPEMU_BTHID_UNAVAILABLE",
        "SHARPEMU_DISABLE_IMPORT_LOOP_GUARD",
        "SHARPEMU_WRITABLE_APP0",
        "SHARPEMU_VK_VALIDATION",
        "SHARPEMU_DUMP_SPIRV",
        "SHARPEMU_LOG_DIRECT_MEMORY",
        "SHARPEMU_LOG_IO",
        "SHARPEMU_LOG_NP",
        "SHARPEMU_GUEST_IMAGE_CPU_SYNC",
    };

    private readonly string _titleId;
    private IReadOnlyList<HostDisplayOption> _hostDisplays = [];
    private bool _updatingHostDisplayOptions;

    private readonly SettingRow _logLevelRow;
    private readonly ComboBox _logLevel = new() { ItemsSource = LogLevels, Width = 160 };

    private readonly SettingRow _traceRow;
    private readonly NumericUpDown _trace = new()
    {
        Minimum = 0, Maximum = 4096, Increment = 16, Width = 160, FormatString = "0",
    };

    private readonly SettingRow _strictRow;
    private readonly ToggleSwitch _strict = new();

    private readonly SettingRow _logToFileRow;
    private readonly ToggleSwitch _logToFile = new();

    private readonly SettingRow _windowModeRow;
    private readonly ComboBox _windowMode = new() { ItemsSource = WindowModes, Width = 160 };

    private readonly SettingRow _resolutionRow;
    private readonly ComboBox _resolution = new() { Width = 160 };

    private readonly SettingRow _displayIndexRow;
    private readonly ComboBox _displayIndex = new() { Width = 240 };

    private readonly SettingRow _refreshRateRow;
    private readonly ComboBox _refreshRate = new() { Width = 160 };

    private readonly SettingRow _scalingModeRow;
    private readonly ComboBox _scalingMode = new() { ItemsSource = ScalingModes, Width = 160 };

    private readonly SettingRow _vsyncRow;
    private readonly ToggleSwitch _vsync = new();

    private readonly SettingRow _hdrModeRow;
    private readonly ComboBox _hdrMode = new() { ItemsSource = HdrModes, Width = 160 };

    private readonly SettingRow _envRow;
    private readonly StackPanel _envList = new() { Orientation = Orientation.Vertical, Spacing = 8, Margin = new(0, 4, 0, 0) };
    private readonly List<(string Name, ToggleSwitch Box)> _envBoxes = new();

    public PerGameSettingsDialog(string titleId, string displayName, GuiSettings global)
    {
        _titleId = titleId;
        var loc = Localization.Instance;

        Title = loc.Format("PerGame.Title", displayName, titleId);
        Width = 520;
        MaxHeight = 720;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        CanResize = false;

        Background = new SolidColorBrush(Color.Parse("#0D1017"));

        _strict.OnContent = _logToFile.OnContent = _vsync.OnContent = loc.Get("Common.On");
        _strict.OffContent = _logToFile.OffContent = _vsync.OffContent = loc.Get("Common.Off");

        _logLevelRow = Row(loc.Get("Options.LogLevel.Label"), loc.Get("Options.LogLevel.Desc"), _logLevel);
        _traceRow = Row(loc.Get("Options.TraceImports.Label"), loc.Get("Options.TraceImports.Desc"), _trace);
        _strictRow = Row(loc.Get("Options.Strict.Label"), loc.Get("Options.Strict.Desc"), _strict);
        _logToFileRow = Row(loc.Get("Options.LogToFile.Label"), loc.Get("Options.LogToFile.Desc"), _logToFile);
        _windowModeRow = Row(loc.Get("Options.WindowMode.Label"), loc.Get("Options.WindowMode.Desc"), _windowMode);
        _resolutionRow = Row(loc.Get("Options.Resolution.Label"), loc.Get("Options.Resolution.Desc"), _resolution);
        _displayIndexRow = Row(loc.Get("Options.Display.Label"), loc.Get("Options.Display.Desc"), _displayIndex);
        _refreshRateRow = Row(loc.Get("Options.RefreshRate.Label"), loc.Get("Options.RefreshRate.Desc"), _refreshRate);
        _scalingModeRow = Row(loc.Get("Options.Scaling.Label"), loc.Get("Options.Scaling.Desc"), _scalingMode);
        _vsyncRow = Row(loc.Get("Options.VSync.Label"), loc.Get("Options.VSync.Desc"), _vsync);
        _hdrModeRow = Row(loc.Get("Options.Hdr.Label"), loc.Get("Options.Hdr.Desc"), _hdrMode);
        _envRow = new SettingRow
        {
            Label = loc.Get("PerGame.EnvToggles.Label"),
            Description = loc.Get("PerGame.EnvToggles.Desc"),
            ShowOverride = true,
        };

        foreach (var name in EnvToggles)
        {
            var box = new ToggleSwitch { OnContent = name, OffContent = name };
            _envBoxes.Add((name, box));
            _envList.Children.Add(box);
        }

        var general = new StackPanel { Orientation = Orientation.Vertical, Spacing = 12, Margin = new(0, 12, 0, 0) };
        general.Children.Add(Card(loc.Get("Options.Section.Emulation"), _strictRow));
        general.Children.Add(Card(loc.Get("Options.Section.Logging"), _logLevelRow, _traceRow, _logToFileRow));
        general.Children.Add(Card(loc.Get("Options.Section.Environment"), _envRow, _envList));

        var graphics = new StackPanel { Orientation = Orientation.Vertical, Spacing = 12, Margin = new(0, 12, 0, 0) };
        graphics.Children.Add(Card(
            loc.Get("Options.Section.Display"),
            _windowModeRow,
            _resolutionRow,
            _displayIndexRow,
            _refreshRateRow,
            _scalingModeRow,
            _vsyncRow,
            _hdrModeRow));

        var content = new StackPanel { Orientation = Orientation.Vertical, Spacing = 12, Margin = new(16) };
        content.Children.Add(new TextBlock
        {
            Text = loc.Get("PerGame.InheritNote"),
            Foreground = new SolidColorBrush(Color.Parse("#8B94A7")),
            FontSize = 12,
        });
        content.Children.Add(new TabControl
        {
            ItemsSource = new[]
            {
                new TabItem { Header = loc.Get("PerGame.Tab.General"), Content = general },
                new TabItem { Header = loc.Get("PerGame.Tab.Graphics"), Content = graphics },
            },
        });

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

        _displayIndex.SelectionChanged += (_, _) => OnHostDisplayChanged();
        _resolution.SelectionChanged += (_, _) => OnHostResolutionChanged();
        LoadValues(global);
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

    private void LoadValues(GuiSettings global)
    {
        var existing = PerGameSettings.Load(_titleId);
        var displayIndex = Math.Max(0, existing?.DisplayIndex ?? global.DisplayIndex);
        var resolution = existing?.Resolution ?? global.Resolution;
        var refreshRate = Math.Clamp(existing?.RefreshRate ?? global.RefreshRate, 0, 1000);

        _updatingHostDisplayOptions = true;
        try
        {
            _hostDisplays = HostDisplayOptions.BuildDisplays(HostDisplayCatalog.Query(), displayIndex);
            _displayIndex.ItemsSource = _hostDisplays;
            var display = HostDisplayOptions.SelectDisplay(_hostDisplays, displayIndex);
            _displayIndex.SelectedItem = display;
            PopulateHostModes(display, resolution, refreshRate);
        }
        finally
        {
            _updatingHostDisplayOptions = false;
        }

        _logLevel.SelectedItem = Array.IndexOf(LogLevels, global.LogLevel) >= 0 ? global.LogLevel : "Info";
        _trace.Value = global.ImportTraceLimit;
        _strict.IsChecked = global.StrictDynlibResolution;
        _logToFile.IsChecked = global.LogToFile;
        _windowMode.SelectedItem = ChoiceOrDefault(WindowModes, global.WindowMode, "Windowed");
        _scalingMode.SelectedItem = ChoiceOrDefault(ScalingModes, global.ScalingMode, "Fit");
        _vsync.IsChecked = global.VSync;
        _hdrMode.SelectedItem = ChoiceOrDefault(HdrModes, global.HdrMode, "Auto");
        foreach (var (name, box) in _envBoxes)
        {
            box.IsChecked = IsEnvironmentEnabled(global.EnvironmentToggles, name, defaultValue: name == "SHARPEMU_GUEST_IMAGE_CPU_SYNC");
        }

        if (existing is null)
        {
            return;
        }

        if (existing.LogLevel is { } level && Array.IndexOf(LogLevels, level) >= 0)
        {
            _logLevelRow.IsOverridden = true;
            _logLevel.SelectedItem = level;
        }

        if (existing.ImportTraceLimit is { } t) { _traceRow.IsOverridden = true; _trace.Value = t; }
        if (existing.StrictDynlibResolution is { } s) { _strictRow.IsOverridden = true; _strict.IsChecked = s; }
        if (existing.LogToFile is { } l) { _logToFileRow.IsOverridden = true; _logToFile.IsChecked = l; }
        if (existing.WindowMode is { } windowMode && WindowModes.Contains(windowMode, StringComparer.OrdinalIgnoreCase))
        {
            _windowModeRow.IsOverridden = true;
            _windowMode.SelectedItem = ChoiceOrDefault(WindowModes, windowMode, "Windowed");
        }
        if (existing.Resolution is not null)
        {
            _resolutionRow.IsOverridden = true;
        }
        if (existing.DisplayIndex is not null)
        {
            _displayIndexRow.IsOverridden = true;
        }
        if (existing.RefreshRate is not null)
        {
            _refreshRateRow.IsOverridden = true;
        }
        if (existing.ScalingMode is { } scalingMode && ScalingModes.Contains(scalingMode, StringComparer.OrdinalIgnoreCase))
        {
            _scalingModeRow.IsOverridden = true;
            _scalingMode.SelectedItem = ChoiceOrDefault(ScalingModes, scalingMode, "Fit");
        }
        if (existing.VSync is { } vsync)
        {
            _vsyncRow.IsOverridden = true;
            _vsync.IsChecked = vsync;
        }
        if (existing.HdrMode is { } hdrMode && HdrModes.Contains(hdrMode, StringComparer.OrdinalIgnoreCase))
        {
            _hdrModeRow.IsOverridden = true;
            _hdrMode.SelectedItem = ChoiceOrDefault(HdrModes, hdrMode, "Auto");
        }
        if (existing.EnvironmentToggles is { } env)
        {
            _envRow.IsOverridden = true;
            foreach (var (name, box) in _envBoxes)
            {
                box.IsChecked = IsEnvironmentEnabled(env, name, defaultValue: name == "SHARPEMU_GUEST_IMAGE_CPU_SYNC");
            }
        }
    }

    private static string ChoiceOrDefault(string[] choices, string? value, string fallback) =>
        choices.FirstOrDefault(choice => string.Equals(choice, value, StringComparison.OrdinalIgnoreCase)) ?? fallback;

    private void OnHostDisplayChanged()
    {
        if (_updatingHostDisplayOptions || _displayIndex.SelectedItem is not HostDisplayOption display)
        {
            return;
        }

        _updatingHostDisplayOptions = true;
        try
        {
            PopulateHostModes(
                display,
                _resolution.SelectedItem as string ?? "1920x1080",
                SelectedRefreshRate());
        }
        finally
        {
            _updatingHostDisplayOptions = false;
        }
    }

    private void OnHostResolutionChanged()
    {
        if (_updatingHostDisplayOptions || _displayIndex.SelectedItem is not HostDisplayOption display)
        {
            return;
        }

        var selectedRefreshRate = SelectedRefreshRate();
        _updatingHostDisplayOptions = true;
        try
        {
            PopulateRefreshRates(display, _resolution.SelectedItem as string, selectedRefreshRate);
        }
        finally
        {
            _updatingHostDisplayOptions = false;
        }
    }

    private void PopulateHostModes(
        HostDisplayOption display,
        string selectedResolution,
        int selectedRefreshRate)
    {
        var resolutions = HostDisplayOptions.BuildResolutions(display, selectedResolution);
        _resolution.ItemsSource = resolutions;
        _resolution.SelectedItem = resolutions.FirstOrDefault(resolution =>
            string.Equals(resolution, selectedResolution, StringComparison.OrdinalIgnoreCase)) ?? resolutions[0];
        PopulateRefreshRates(display, _resolution.SelectedItem as string, selectedRefreshRate);
    }

    private void PopulateRefreshRates(
        HostDisplayOption display,
        string? resolution,
        int selectedRefreshRate)
    {
        var rates = HostDisplayOptions.BuildRefreshRates(
            display,
            resolution,
            selectedRefreshRate,
            Localization.Instance.Get("Options.RefreshRate.Automatic"));
        _refreshRate.ItemsSource = rates;
        _refreshRate.SelectedItem = rates.FirstOrDefault(rate => rate.Value == selectedRefreshRate) ?? rates[0];
    }

    private int SelectedRefreshRate() =>
        _refreshRate.SelectedItem is HostRefreshRateOption refreshRate ? refreshRate.Value : 0;

    private void Persist()
    {
        var settings = new PerGameSettings
        {
            LogLevel = _logLevelRow.IsOverridden ? _logLevel.SelectedItem as string : null,
            ImportTraceLimit = _traceRow.IsOverridden ? (int)(_trace.Value ?? 0) : null,
            StrictDynlibResolution = _strictRow.IsOverridden ? _strict.IsChecked == true : null,
            LogToFile = _logToFileRow.IsOverridden ? _logToFile.IsChecked == true : null,
            WindowMode = _windowModeRow.IsOverridden ? _windowMode.SelectedItem as string : null,
            Resolution = _resolutionRow.IsOverridden ? _resolution.SelectedItem as string : null,
            DisplayIndex = _displayIndexRow.IsOverridden && _displayIndex.SelectedItem is HostDisplayOption display
                ? display.Index
                : null,
            RefreshRate = _refreshRateRow.IsOverridden ? SelectedRefreshRate() : null,
            ScalingMode = _scalingModeRow.IsOverridden ? _scalingMode.SelectedItem as string : null,
            VSync = _vsyncRow.IsOverridden ? _vsync.IsChecked == true : null,
            HdrMode = _hdrModeRow.IsOverridden ? _hdrMode.SelectedItem as string : null,
            EnvironmentToggles = _envRow.IsOverridden ? BuildEnvironmentEntries() : null,
        };
        settings.Save(_titleId);
    }

    private List<string> BuildEnvironmentEntries()
    {
        const string guestImageCpuSync = "SHARPEMU_GUEST_IMAGE_CPU_SYNC";
        var entries = _envBoxes
            .Where(entry => entry.Name != guestImageCpuSync && entry.Box.IsChecked == true)
            .Select(entry => entry.Name)
            .ToList();
        if (_envBoxes.First(entry => entry.Name == guestImageCpuSync).Box.IsChecked != true)
        {
            entries.Add(guestImageCpuSync + "=0");
        }

        return entries;
    }

    private static bool IsEnvironmentEnabled(
        IEnumerable<string> entries,
        string name,
        bool defaultValue)
    {
        foreach (var entry in entries)
        {
            if (string.Equals(entry, name + "=0", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (string.Equals(entry, name, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(entry, name + "=1", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return defaultValue;
    }
}
