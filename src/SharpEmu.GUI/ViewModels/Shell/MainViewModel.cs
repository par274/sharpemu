// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.GUI.ViewModels;

using System.Reactive;
using ReactiveUI;
using SharpEmu.GUI.Navigation;
using SharpEmu.GUI.Services.Abstractions;

/// <summary>
/// The launcher's shell view-model: owns the persistent active page
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
        NavigateCommand = ReactiveCommand.Create<ShellPage>(NavigateTo);
    }

    private ShellPage _activePage = ShellPage.Library;

    public LibraryViewModel Library { get; }
    public OptionsViewModel Options { get; }
    public ConsoleViewModel Console { get; }
    public SessionViewModel Session { get; }
    public ReactiveCommand<ShellPage, Unit> NavigateCommand { get; }

    /// <summary>The single source of truth for top-level shell navigation.</summary>
    public ShellPage ActivePage
    {
        get => _activePage;
        private set
        {
            if (_activePage == value)
            {
                return;
            }

            this.RaiseAndSetIfChanged(ref _activePage, value);
            this.RaisePropertyChanged(nameof(ActivePageIndex));
            this.RaisePropertyChanged(nameof(NavigationOffset));
            this.RaisePropertyChanged(nameof(IsLibraryActive));
            this.RaisePropertyChanged(nameof(IsOptionsActive));
            this.RaisePropertyChanged(nameof(IsConsoleActive));
            this.RaisePropertyChanged(nameof(SystemPageSurfaceOpacity));
        }
    }

    public int ActivePageIndex => (int)ActivePage;
    public double NavigationOffset => ActivePageIndex * 132;
    public bool IsLibraryActive => ActivePage == ShellPage.Library;
    public bool IsOptionsActive => ActivePage == ShellPage.Options;
    public bool IsConsoleActive => ActivePage == ShellPage.Console;
    public double SystemPageSurfaceOpacity => IsLibraryActive ? 0 : 1;

    private readonly ISettingsService _settings;

    /// <summary>Compatibility entry point for controller navigation.</summary>
    public void NavigateTo(int page)
        => NavigateTo((ShellPage)Math.Clamp(page, 0, 2));

    /// <summary>Switches the shell to one of its already-created page instances.</summary>
    public void NavigateTo(ShellPage page)
    {
        if (!Enum.IsDefined(page))
        {
            return;
        }

        if (page == ActivePage)
        {
            return;
        }

        // Leaving the Options page persists any in-progress setting edits.
        if (ActivePage == ShellPage.Options)
        {
            _settings.Save();
        }

        ActivePage = page;
    }
}
