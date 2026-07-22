// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.Services.Infrastructure;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Composes the launcher's dependency graph. Microsoft.Extensions.DependencyInjection
/// is the master container; Splat (ReactiveUI's service locator) is bridged onto it
/// so ViewModels and Views resolve through the same graph.
/// </summary>
internal static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the services the launcher needs. Today these are thin adapters
    /// over the existing singletons/helpers; as the MainWindow god-class is
    /// broken up, the extracted logic moves behind these registrations.
    /// </summary>
    public static IServiceCollection AddSharpEmuGui(this IServiceCollection services)
    {
        // Localization: a stateful singleton wrapping the embedded language store.
        services.AddSingleton<Abstractions.ILocalizationService, LocalizationService>();

        // Game library: a stateless filesystem scanner. Singleton so its (warm)
        // helpers are reused, though it holds no mutable state.
        services.AddSingleton<Abstractions.IGameLibraryService, GameLibraryService>();

        // Settings: a single shared settings instance for the whole app.
        services.AddSingleton<Abstractions.ISettingsService, SettingsService>();

        // Logging: a single ring buffer + optional file mirror shared by the
        // in-window console and the detached console window.
        services.AddSingleton<Abstractions.ILogService, LogService>();

        // Emulator: owns the isolated game process and launch options.
        services.AddSingleton<Abstractions.IEmulatorService, EmulatorService>();

        // Gamepad: polls DualSense/XInput and raises navigation intents.
        services.AddSingleton<Abstractions.IGamepadInputService, GamepadInputService>();

        // ViewModels. MainViewModel is the shell that composes the others, so it
        // must be a singleton the window and any sub-view resolve consistently.
        services.AddSingleton<ViewModels.MainViewModel>();
        services.AddTransient<ViewModels.LibraryViewModel>();
        services.AddTransient<ViewModels.OptionsViewModel>();
        services.AddSingleton<ViewModels.ConsoleViewModel>();
        services.AddSingleton<ViewModels.SessionViewModel>();
        // PerGameSettingsViewModel is constructed ad-hoc with title-specific
        // arguments when a dialog opens, so it is not registered here.

        // ViewModels are transient: each window/dialog gets a fresh instance.
        // More are registered here as the MainWindow is split apart (Library,
        // Options, Console, Session) in subsequent steps.

        return services;
    }
}
