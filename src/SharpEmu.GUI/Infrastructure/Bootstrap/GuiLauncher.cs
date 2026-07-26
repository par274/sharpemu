// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia;
using Microsoft.Extensions.DependencyInjection;
using ReactiveUI.Avalonia;
using SharpEmu.GUI.Services.Infrastructure;

namespace SharpEmu.GUI;

/// <summary>
/// Entry point for the desktop frontend, hosted by the SharpEmu executable
/// when it is started without command-line arguments.
/// </summary>
public static class GuiLauncher
{
    /// <summary>
    /// The application's service provider, exposed so the legacy code paths
    /// still wired into <c>MainWindow</c> can reach services while they are
    /// being migrated. ViewModels should prefer constructor injection.
    /// </summary>
    internal static IServiceProvider Services { get; private set; } = default!;

    public static int Run()
    {
        try
        {
            // Build the application's DI container up front. ReactiveUI's own
            // Splat locator initializes itself separately during Avalonia setup
            // (UseReactiveUI/RegisterReactiveUIViewsFromEntryAssembly).
            var services = new ServiceCollection();
            services.AddSharpEmuGui();
            Services = services.BuildServiceProvider(validateScopes: true);

            BuildAvaloniaApp().StartWithClassicDesktopLifetime(Array.Empty<string>());
            return 0;
        }
        catch (Exception ex)
        {
            WriteCrashLog(ex);
            throw;
        }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .UseReactiveUI(_ => { })
            .RegisterReactiveUIViewsFromEntryAssembly()
            .LogToTrace();

    private static void WriteCrashLog(Exception ex)
    {
        try
        {
            File.AppendAllText(
                Path.Combine(AppContext.BaseDirectory, "gui-crash.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // Crash logging is best-effort.
        }
    }
}
