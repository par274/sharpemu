// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using ReactiveUI;
using ReactiveUI.SourceGenerators;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// The launcher's shell view-model: owns the active page
/// (Library/Options/Console) and
/// composes the screen view-models (Library, Options, Console, Session). The
/// MainWindow binds its top-level navigation and surfaces these children to the
/// XAML via <see cref="Library"/>, <see cref="Options"/>, <see cref="Console"/>
/// and <see cref="Session"/>.
/// </summary>
public partial class MainViewModel : ReactiveObject
{
    public MainViewModel(
        LibraryViewModel library,
        OptionsViewModel options,
        ConsoleViewModel console,
        SessionViewModel session,
        ISettingsService settings)
    {
        Library = library;
        Options = options;
        Console = console;
        Session = session;
        _settings = settings;
    }

    /// <summary>0 = Library, 1 = Options, 2 = Console.</summary>
    [Reactive] private int _activePage;

    public LibraryViewModel Library { get; }
    public OptionsViewModel Options { get; }
    public ConsoleViewModel Console { get; }
    public SessionViewModel Session { get; }
    private readonly ISettingsService _settings;

    /// <summary>Switches to the Library (0), Options (1), or Console (2) page.</summary>
    public void NavigateTo(int page)
    {
        page = Math.Clamp(page, 0, 2);
        if (page == ActivePage)
        {
            return;
        }

        // Leaving the Options page persists any in-progress setting edits.
        if (ActivePage == 1)
        {
            _settings.Save();
        }

        ActivePage = page;
    }
}
