// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;
using SharpEmu.Libs.VideoOut;
using SharpEmu.Logging;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

public sealed class VulkanNativeCaptureIntegrationTests
{
    [Fact]
    public async Task SyntheticFrameCapturesWithValidationWhenExplicitlyRequested()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_RUN_VULKAN_CAPTURE_INTEGRATION"), "1", StringComparison.Ordinal)) return;

        var configuredOutput = Environment.GetEnvironmentVariable("SHARPEMU_VULKAN_CAPTURE_OUTPUT");
        var output = string.IsNullOrWhiteSpace(configuredOutput)
            ? Path.Combine(Path.GetTempPath(), "sharpemu-vulkan-capture", Guid.NewGuid().ToString("N"))
            : Path.GetFullPath(configuredOutput);
        var frames = Path.Combine(output, "frames");
        Directory.CreateDirectory(frames);
        var eventsPath = Path.Combine(output, "events.jsonl");
        var configPath = Path.Combine(output, "harness-config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            schemaVersion = "1.0.0",
            eventsPath,
            rawFrameDirectory = frames,
            redactionRoots = Array.Empty<string>(),
            capture = new { enabled = true, firstFrame = true, frameNumbers = Array.Empty<long>(), interval = 0, maxFrames = 1 },
        }));

        var originalError = Console.Error;
        using var error = new StringWriter();
        Console.SetError(error);
        try
        {
            Environment.SetEnvironmentVariable("SHARPEMU_VK_VALIDATION", "1");
            HarnessTelemetry.Configure(configPath);
            var pixels = new byte[64 * 64 * 4];
            for (var offset = 0; offset < pixels.Length; offset += 4)
            {
                pixels[offset] = 0x20;
                pixels[offset + 1] = 0x80;
                pixels[offset + 2] = 0xE0;
                pixels[offset + 3] = 0xFF;
            }
            VulkanVideoPresenter.Submit(pixels, 64, 64);
            VulkanVideoPresenter.EnsureStarted(64, 64);
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (!Directory.EnumerateFiles(frames, "*.raw.json").Any() && DateTime.UtcNow < deadline)
            {
                await Task.Delay(100);
            }
            VulkanVideoPresenter.RequestClose();
            await Task.Delay(1_000);
            HarnessTelemetry.Shutdown();
        }
        finally
        {
            Console.SetError(originalError);
        }

        var log = error.ToString();
        await File.WriteAllTextAsync(Path.Combine(output, "validation-messages.log"), log);
        var active = log.Contains("Vulkan Validation Layers active", StringComparison.OrdinalIgnoreCase);
        var unavailable = log.Contains("validation", StringComparison.OrdinalIgnoreCase) && log.Contains("not found", StringComparison.OrdinalIgnoreCase);
        var messages = log.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Where(line => line.StartsWith("[VULKAN]", StringComparison.OrdinalIgnoreCase)).Take(100).ToArray();
        var captured = Directory.EnumerateFiles(frames, "*.raw.json").Any();
        await File.WriteAllTextAsync(Path.Combine(output, "validation-status.json"), JsonSerializer.Serialize(new
        {
            validationStatus = active ? "active" : unavailable ? "unavailable" : "requested-not-confirmed",
            captured,
            validationMessageCount = messages.Length,
            messages,
        }, new JsonSerializerOptions { WriteIndented = true }));

        if (unavailable) return;
        Assert.True(active, log);
        Assert.True(captured, log);
        Assert.DoesNotContain(messages, message => message.StartsWith("[VULKAN][ERROR]", StringComparison.OrdinalIgnoreCase));
    }
}
