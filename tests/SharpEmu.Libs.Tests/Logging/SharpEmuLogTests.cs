// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Globalization;
using SharpEmu.Logging;
using Xunit;

namespace SharpEmu.Libs.Tests.Logging;

public sealed class SharpEmuLogTests
{
    [Fact]
    public void FileLogSinkFormatsTimestampsWithInvariantCulture()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sharpemu-{Guid.NewGuid():N}.log");
        var originalCulture = CultureInfo.CurrentCulture;

        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            using (var sink = new FileLogSink(path, append: false))
            {
                var entry = new LogEntry(
                    new DateTimeOffset(2026, 7, 25, 14, 5, 6, 789, TimeSpan.Zero),
                    LogLevel.Info,
                    "Test",
                    "message",
                    "Test.cs",
                    1,
                    nameof(FileLogSinkFormatsTimestampsWithInvariantCulture));

                sink.Write(in entry);
            }

            var line = File.ReadAllText(path);
            Assert.StartsWith("[2026-07-25 14:05:06.789]", line, StringComparison.Ordinal);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("Trace", LogLevel.Trace)]
    [InlineData("debug", LogLevel.Debug)]
    [InlineData(" Info ", LogLevel.Info)]
    [InlineData("WARNING", LogLevel.Warning)]
    [InlineData("Error", LogLevel.Error)]
    [InlineData("critical", LogLevel.Critical)]
    [InlineData("None", LogLevel.None)]
    [InlineData("warn", LogLevel.Warning)]
    [InlineData("fatal", LogLevel.Critical)]
    public void TryParseLevelAcceptsDefinedNamesAndAliases(string text, LogLevel expected)
    {
        Assert.True(SharpEmuLog.TryParseLevel(text, out var actual));
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("unknown")]
    [InlineData("999")]
    [InlineData("-1")]
    public void TryParseLevelRejectsInvalidValues(string? text)
    {
        Assert.False(SharpEmuLog.TryParseLevel(text, out var level));
        Assert.Equal(default, level);
    }
}
