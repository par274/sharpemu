// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace SharpEmu.GUI;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // The launcher UI renders in a WebView; WebLauncher hosts it plus the
            // native game surface. The legacy Avalonia MainWindow remains as a
            // fallback (swap back here if the web launcher misbehaves).
            desktop.MainWindow = new WebLauncher();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
