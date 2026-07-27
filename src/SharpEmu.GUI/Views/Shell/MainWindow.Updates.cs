// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using Avalonia.Controls;
using SharpEmu.Logging;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Net.Http.Headers;

namespace SharpEmu.GUI;

/// <summary>Update checks, the update action button and the latest-commit link.</summary>
public partial class MainWindow
{
    private enum UpdateActionState
    {
        Idle,
        Checking,
        Available,
    }

    /// <summary>
    /// Wires the About section: the updater action plus the outbound project
    /// links, which sit on the same page as the update button.
    /// </summary>
    private void WireUpdates()
    {
        UpdateButton.Click += async (_, _) => await OnUpdateButtonAsync();

        GithubButton.Click += (_, _) =>
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://github.com/sharpemu/sharpemu",
                UseShellExecute = true
            });
        };

        DiscordButton.Click += (_, _) =>
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://discord.com/invite/6GejPEDqpc",
                UseShellExecute = true
            });
        };

        LatestCommitButton.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(_latestCommitSha))
            {
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName =
                    $"https://github.com/sharpemu/sharpemu/commit/{_latestCommitSha}",
                UseShellExecute = true
            });
        };
    }

    private void ApplyAboutLocalization()
    {
        var loc = Localization.Instance;

        GithubLabel.Text = loc.Get("About.Github.Label");
        GithubDesc.Text = loc.Get("About.Github.Desc");
        DiscordServerLabel.Text = loc.Get("About.Discord.Label");
        DiscordServerDesc.Text = loc.Get("About.Discord.Desc");
        AboutTagline.Text = loc.Get("About.Tagline");
        GithubButtonLabel.Text = loc.Get("About.GithubButton");
        DiscordButtonLabel.Text = loc.Get("About.DiscordButton");
        UpdateLabel.Text = loc.Get("Updater.Label");
        LatestCommitLabel.Text = loc.Get("About.Github.LatestCommitLabel");
        LatestCommitDescription.Text = loc.Get("About.Github.LatestCommitDescription");
        RefreshUpdateText();
    }

    // ---- Github http client config ----
    // This is for getting lash commit id
    private static HttpClient CreateGithubHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };

        client.DefaultRequestHeaders.UserAgent.ParseAdd("SharpEmu/1.0");
        client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github.sha"));

        client.DefaultRequestHeaders.Add(
            "X-GitHub-Api-Version",
            "2026-03-10");

        return client;
    }

    private async Task LoadLatestCommitAsync()
    {
        const string apiUrl =
            "https://api.github.com/repos/sharpemu/sharpemu/commits/main";

        _latestCommitSha = null;
        LatestCommitHashText.Text = "Loading…";
        LatestCommitButton.IsEnabled = false;

        try
        {
            using var response = await GithubHttpClient.GetAsync(apiUrl);
            var responseBody =
                (await response.Content.ReadAsStringAsync()).Trim();

            if (!response.IsSuccessStatusCode)
            {
                LatestCommitHashText.Text =
                    $"HTTP {(int)response.StatusCode}";

                ToolTip.SetTip(
                    LatestCommitButton,
                    string.IsNullOrWhiteSpace(responseBody)
                        ? response.ReasonPhrase
                        : responseBody);

                return;
            }

            if (responseBody.Length < 7)
            {
                LatestCommitHashText.Text = "Invalid response";
                ToolTip.SetTip(LatestCommitButton, responseBody);
                return;
            }

            // Keep the complete SHA for the URL.
            _latestCommitSha = responseBody;

            // Display only the short SHA.
            LatestCommitHashText.Text =
                responseBody[..Math.Min(7, responseBody.Length)];

            LatestCommitButton.IsEnabled = true;

            ToolTip.SetTip(
                LatestCommitButton,
                $"Open commit {_latestCommitSha}");
        }
        catch (TaskCanceledException ex)
        {
            LatestCommitHashText.Text = "Timeout";
            ToolTip.SetTip(LatestCommitButton, ex.Message);
        }
        catch (HttpRequestException ex)
        {
            LatestCommitHashText.Text = "Connection error";
            ToolTip.SetTip(LatestCommitButton, ex.Message);
        }
        catch (Exception ex)
        {
            LatestCommitHashText.Text = "Error";
            ToolTip.SetTip(LatestCommitButton, ex.Message);
        }
    }

    private async Task OnUpdateButtonAsync()
    {
        if (_isUpdateOperationRunning)
        {
            return;
        }

        if (_availableUpdate is null)
        {
            await CheckForUpdatesAsync();
            return;
        }

        _isUpdateOperationRunning = true;
        UpdateButton.IsHitTestVisible = false;
        try
        {
            var progress = new Progress<int>(value =>
                SetUpdateStatus("Updater.Status.Downloading", value));
            await Updater.DownloadAndRestartAsync(_availableUpdate, progress);
            SetUpdateStatus("Updater.Status.Installing");
            Close();
        }
        catch (InvalidDataException)
        {
            SetUpdateStatus("Updater.Status.ChecksumFailed");
        }
        catch
        {
            SetUpdateStatus("Updater.Status.Failed");
        }
        finally
        {
            _isUpdateOperationRunning = false;
            UpdateButton.IsHitTestVisible = true;
        }
    }

    private async Task CheckForUpdatesAsync()
    {
        if (_isUpdateOperationRunning)
        {
            return;
        }

        _isUpdateOperationRunning = true;
        _availableUpdate = null;
        UpdateButton.IsHitTestVisible = false;
        SetUpdateActionState(UpdateActionState.Checking);
        SetUpdateStatus("Updater.Status.Checking");
        try
        {
            _availableUpdate = await Updater.CheckAsync(BuildInfo.CommitSha);
            SetUpdateStatus(
                _availableUpdate is null ? "Updater.Status.Current" : "Updater.Status.Available",
                _availableUpdate?.Sha ?? BuildInfo.CommitSha ?? "dev");
        }
        catch (OperationCanceledException)
        {
            SetUpdateStatus("Updater.Status.Timeout");
        }
        catch (PlatformNotSupportedException)
        {
            SetUpdateStatus("Updater.Status.Unsupported");
        }
        catch
        {
            SetUpdateStatus("Updater.Status.Failed");
        }
        finally
        {
            _isUpdateOperationRunning = false;
            UpdateButton.IsHitTestVisible = true;
            SetUpdateActionState(
                _availableUpdate is null ? UpdateActionState.Idle : UpdateActionState.Available);
            RefreshUpdateText();
        }
    }

    private void SetUpdateStatus(string key, params object?[] args)
    {
        _updateStatusKey = key;
        _updateStatusArgs = args;
        RefreshUpdateText();
    }

    private void RefreshUpdateText()
    {
        var loc = Localization.Instance;
        UpdateStatusText.Text = loc.Format(_updateStatusKey, _updateStatusArgs);
        UpdateCheckLabel.Text = loc.Get("Updater.Check");
        UpdateCheckingLabel.Text = loc.Get("Updater.Checking");
        UpdateInstallLabel.Text = loc.Get("Updater.Install");
    }

    private void SetUpdateActionState(UpdateActionState state)
    {
        UpdateButton.Classes.Set("idle", state == UpdateActionState.Idle);
        UpdateButton.Classes.Set("checking", state == UpdateActionState.Checking);
        UpdateButton.Classes.Set("available", state == UpdateActionState.Available);
    }
}
