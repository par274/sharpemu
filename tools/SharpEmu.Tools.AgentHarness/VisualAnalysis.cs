// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Text.Json;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record ImageMetrics(
    int Width,
    int Height,
    string Sha256,
    double MeanLuminance,
    double LuminanceStandardDeviation,
    double NearBlackPercent,
    double NearWhitePercent,
    long AlphaAnomalyPixels,
    string DifferenceHash,
    bool LikelyBlank);

internal sealed record ImageDifference(double ChangedPixelRatio, double NormalizedMeanAbsoluteDifference);

internal sealed record VisualFrame(
    string File,
    string CaptureSource,
    long? FrameNumber,
    double? ElapsedSeconds,
    string SourcePixelFormat,
    string CanonicalFormat,
    string? ColorSpace,
    string? NearestMilestone,
    bool VerticalFlipApplied,
    string EncoderStatus,
    ImageMetrics Metrics,
    ImageDifference? DifferenceFromPrevious);

internal static class VisualAnalyzer
{
    public static ImageMetrics Analyze(RgbaImage image, string sha256)
    {
        var count = checked(image.Width * image.Height);
        if (count == 0) throw new ArgumentException("Image is empty.", nameof(image));
        double sum = 0;
        double squared = 0;
        var black = 0L;
        var white = 0L;
        var alpha = 0L;
        for (var offset = 0; offset < image.Pixels.Length; offset += 4)
        {
            var luminance = 0.2126 * image.Pixels[offset] + 0.7152 * image.Pixels[offset + 1] + 0.0722 * image.Pixels[offset + 2];
            sum += luminance;
            squared += luminance * luminance;
            if (luminance <= 10) black++;
            if (luminance >= 245) white++;
            if (image.Pixels[offset + 3] != 255) alpha++;
        }
        var mean = sum / count;
        var variance = Math.Max(0, squared / count - mean * mean);
        var blackPercent = black * 100.0 / count;
        var whitePercent = white * 100.0 / count;
        var standardDeviation = Math.Sqrt(variance);
        return new ImageMetrics(
            image.Width,
            image.Height,
            sha256,
            mean,
            standardDeviation,
            blackPercent,
            whitePercent,
            alpha,
            DifferenceHash(image),
            standardDeviation < 1.5 || blackPercent > 99.5 || whitePercent > 99.5);
    }

    public static ImageDifference Compare(RgbaImage before, RgbaImage after)
    {
        if (before.Width != after.Width || before.Height != after.Height) throw new ArgumentException("Image dimensions do not match.");
        var pixels = before.Width * before.Height;
        var changed = 0L;
        double absolute = 0;
        for (var offset = 0; offset < before.Pixels.Length; offset += 4)
        {
            var pixelChanged = false;
            for (var channel = 0; channel < 4; channel++)
            {
                var difference = Math.Abs(before.Pixels[offset + channel] - after.Pixels[offset + channel]);
                absolute += difference;
                pixelChanged |= difference != 0;
            }
            if (pixelChanged) changed++;
        }
        return new ImageDifference(changed / (double)pixels, absolute / (pixels * 4.0 * 255.0));
    }

    public static RgbaImage AbsoluteDifference(RgbaImage before, RgbaImage after)
    {
        if (before.Width != after.Width || before.Height != after.Height) throw new ArgumentException("Image dimensions do not match.");
        var pixels = new byte[before.Pixels.Length];
        for (var index = 0; index < pixels.Length; index += 4)
        {
            pixels[index] = (byte)Math.Abs(before.Pixels[index] - after.Pixels[index]);
            pixels[index + 1] = (byte)Math.Abs(before.Pixels[index + 1] - after.Pixels[index + 1]);
            pixels[index + 2] = (byte)Math.Abs(before.Pixels[index + 2] - after.Pixels[index + 2]);
            pixels[index + 3] = 255;
        }
        return new RgbaImage(before.Width, before.Height, pixels);
    }

    public static bool IsFrozen(IReadOnlyList<RgbaImage> images)
    {
        if (images.Count < 2) return false;
        return images.Skip(1).All(image => Compare(images[0], image).ChangedPixelRatio < 0.0001);
    }

    private static string DifferenceHash(RgbaImage image)
    {
        Span<double> values = stackalloc double[64];
        for (var y = 0; y < 8; y++)
        {
            for (var x = 0; x < 8; x++)
            {
                var sourceX = Math.Min(image.Width - 1, x * image.Width / 8);
                var sourceY = Math.Min(image.Height - 1, y * image.Height / 8);
                var offset = (sourceY * image.Width + sourceX) * 4;
                values[y * 8 + x] = 0.2126 * image.Pixels[offset] + 0.7152 * image.Pixels[offset + 1] + 0.0722 * image.Pixels[offset + 2];
            }
        }
        var mean = values.ToArray().Average();
        ulong hash = 0;
        for (var index = 0; index < values.Length; index++) if (values[index] >= mean) hash |= 1UL << index;
        return hash.ToString("X16");
    }
}

internal static class ContactSheet
{
    private const int PanelWidth = 320;
    private const int ImageHeight = 180;
    private const int TextHeight = 48;
    private const int HeaderHeight = 18;

    public static RgbaImage Create(string title, IReadOnlyList<(RgbaImage Image, string Label)> frames)
    {
        var columns = Math.Min(3, Math.Max(1, frames.Count));
        var rows = Math.Max(1, (frames.Count + columns - 1) / columns);
        var width = columns * PanelWidth;
        var height = HeaderHeight + rows * (ImageHeight + TextHeight);
        var pixels = Enumerable.Repeat((byte)18, width * height * 4).ToArray();
        for (var index = 3; index < pixels.Length; index += 4) pixels[index] = 255;
        var canvas = new RasterCanvas(new RgbaImage(width, height, pixels));
        canvas.DrawText(4, 4, title, 220, 220, 220);
        for (var index = 0; index < frames.Count; index++)
        {
            var x = index % columns * PanelWidth;
            var y = HeaderHeight + index / columns * (ImageHeight + TextHeight);
            canvas.BlitScaled(frames[index].Image, x, y, PanelWidth, ImageHeight);
            var lines = Wrap(frames[index].Label.ToUpperInvariant(), 50).Take(3).ToArray();
            for (var line = 0; line < lines.Length; line++) canvas.DrawText(x + 3, y + ImageHeight + 5 + line * 12, lines[line], 240, 240, 240);
        }
        return canvas.Image;
    }

    private static IEnumerable<string> Wrap(string value, int width)
    {
        for (var offset = 0; offset < value.Length; offset += width) yield return value.Substring(offset, Math.Min(width, value.Length - offset));
    }
}

internal sealed class RasterCanvas
{
    private static readonly IReadOnlyDictionary<char, string[]> Font = CreateFont();

    public RasterCanvas(RgbaImage image) => Image = image;

    public RgbaImage Image { get; }

    public void BlitScaled(RgbaImage source, int x, int y, int width, int height)
    {
        for (var destinationY = 0; destinationY < height; destinationY++)
        {
            var sourceY = destinationY * source.Height / height;
            for (var destinationX = 0; destinationX < width; destinationX++)
            {
                var sourceX = destinationX * source.Width / width;
                var sourceOffset = (sourceY * source.Width + sourceX) * 4;
                var destinationOffset = ((y + destinationY) * Image.Width + x + destinationX) * 4;
                source.Pixels.AsSpan(sourceOffset, 4).CopyTo(Image.Pixels.AsSpan(destinationOffset, 4));
            }
        }
    }

    public void DrawText(int x, int y, string text, byte red, byte green, byte blue)
    {
        var cursor = x;
        foreach (var character in text)
        {
            if (!Font.TryGetValue(character, out var glyph)) glyph = Font['?'];
            for (var row = 0; row < glyph.Length; row++)
            {
                for (var column = 0; column < glyph[row].Length; column++)
                {
                    if (glyph[row][column] != '#') continue;
                    var px = cursor + column;
                    var py = y + row;
                    if (px < 0 || py < 0 || px >= Image.Width || py >= Image.Height) continue;
                    var offset = (py * Image.Width + px) * 4;
                    Image.Pixels[offset] = red;
                    Image.Pixels[offset + 1] = green;
                    Image.Pixels[offset + 2] = blue;
                    Image.Pixels[offset + 3] = 255;
                }
            }
            cursor += 4;
        }
    }

    private static IReadOnlyDictionary<char, string[]> CreateFont()
    {
        var patterns = new Dictionary<char, string[]>(64);
        void Add(char value, params string[] rows) => patterns[value] = rows;
        Add(' ', "...", "...", "...", "...", "..."); Add('?', "##.", "..#", ".#.", "...", ".#.");
        Add('-', "...", "...", "###", "...", "..."); Add('.', "...", "...", "...", "...", ".#."); Add(':', "...", ".#.", "...", ".#.", "...");
        Add('/', "..#", "..#", ".#.", "#..", "#.."); Add('_', "...", "...", "...", "...", "###"); Add('%', "#.#", "..#", ".#.", "#..", "#.#"); Add('=', "...", "###", "...", "###", "...");
        Add('0', "###", "#.#", "#.#", "#.#", "###"); Add('1', ".#.", "##.", ".#.", ".#.", "###"); Add('2', "##.", "..#", ".#.", "#..", "###"); Add('3', "##.", "..#", ".#.", "..#", "##."); Add('4', "#.#", "#.#", "###", "..#", "..#"); Add('5', "###", "#..", "##.", "..#", "##."); Add('6', ".##", "#..", "###", "#.#", "###"); Add('7', "###", "..#", ".#.", ".#.", ".#."); Add('8', "###", "#.#", "###", "#.#", "###"); Add('9', "###", "#.#", "###", "..#", "##.");
        Add('A', ".#.", "#.#", "###", "#.#", "#.#"); Add('B', "##.", "#.#", "##.", "#.#", "##."); Add('C', ".##", "#..", "#..", "#..", ".##"); Add('D', "##.", "#.#", "#.#", "#.#", "##."); Add('E', "###", "#..", "##.", "#..", "###"); Add('F', "###", "#..", "##.", "#..", "#.."); Add('G', ".##", "#..", "#.#", "#.#", ".##"); Add('H', "#.#", "#.#", "###", "#.#", "#.#"); Add('I', "###", ".#.", ".#.", ".#.", "###"); Add('J', "..#", "..#", "..#", "#.#", ".#."); Add('K', "#.#", "#.#", "##.", "#.#", "#.#"); Add('L', "#..", "#..", "#..", "#..", "###"); Add('M', "#.#", "###", "###", "#.#", "#.#"); Add('N', "#.#", "###", "###", "###", "#.#"); Add('O', ".#.", "#.#", "#.#", "#.#", ".#."); Add('P', "##.", "#.#", "##.", "#..", "#.."); Add('Q', ".#.", "#.#", "#.#", ".#.", "..#"); Add('R', "##.", "#.#", "##.", "#.#", "#.#"); Add('S', ".##", "#..", ".#.", "..#", "##."); Add('T', "###", ".#.", ".#.", ".#.", ".#."); Add('U', "#.#", "#.#", "#.#", "#.#", "###"); Add('V', "#.#", "#.#", "#.#", "#.#", ".#."); Add('W', "#.#", "#.#", "###", "###", "#.#"); Add('X', "#.#", "#.#", ".#.", "#.#", "#.#"); Add('Y', "#.#", "#.#", ".#.", ".#.", ".#."); Add('Z', "###", "..#", ".#.", "#..", "###");
        return patterns;
    }
}
