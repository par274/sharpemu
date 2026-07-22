// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using SharpEmu.GUI.ViewModels;

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
            // Resolve the composed shell view-model from the DI container built
            // in GuiLauncher. MainViewModel composes Library/Options/Console/
            // Session, so the window receives the whole graph in one shot.
            var main = GuiLauncher.Services.GetRequiredService<MainViewModel>();
            desktop.MainWindow = new MainWindow(main);
        }

        base.OnFrameworkInitializationCompleted();
    }
}
