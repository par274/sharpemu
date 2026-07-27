// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using System.IO.Compression;

namespace SharpEmu.Tools.AgentHarness;

internal sealed record RgbaImage(int Width, int Height, byte[] Pixels)
{
    public int Stride => checked(Width * 4);

    public static RgbaImage FromRaw(int width, int height, ReadOnlySpan<byte> source, string format, int rowPitch = 0, bool flipVertical = false)
    {
        if (width <= 0 || height <= 0) throw new ArgumentOutOfRangeException(nameof(width));
        rowPitch = rowPitch <= 0 ? checked(width * 4) : rowPitch;
        if (source.Length < checked(rowPitch * height)) throw new ArgumentException("Raw frame is shorter than its dimensions and row pitch.", nameof(source));
        var rgba = new byte[checked(width * height * 4)];
        var bgra = format.Contains("B8G8R8A8", StringComparison.OrdinalIgnoreCase) || format.Contains("BGRA", StringComparison.OrdinalIgnoreCase);
        var rgbaFormat = format.Contains("R8G8B8A8", StringComparison.OrdinalIgnoreCase) || format.Contains("RGBA", StringComparison.OrdinalIgnoreCase);
        if (!bgra && !rgbaFormat) throw new NotSupportedException($"Unsupported raw pixel format '{format}'.");
        for (var y = 0; y < height; y++)
        {
            var sourceY = flipVertical ? height - 1 - y : y;
            var sourceRow = source.Slice(sourceY * rowPitch, width * 4);
            var destinationRow = rgba.AsSpan(y * width * 4, width * 4);
            for (var x = 0; x < width; x++)
            {
                var offset = x * 4;
                destinationRow[offset] = bgra ? sourceRow[offset + 2] : sourceRow[offset];
                destinationRow[offset + 1] = sourceRow[offset + 1];
                destinationRow[offset + 2] = bgra ? sourceRow[offset] : sourceRow[offset + 2];
                destinationRow[offset + 3] = sourceRow[offset + 3];
            }
        }
        return new RgbaImage(width, height, rgba);
    }
}

internal static class PngCodec
{
    private static readonly byte[] Signature = [137, 80, 78, 71, 13, 10, 26, 10];
    private static readonly uint[] CrcTable = BuildCrcTable();

    public static void Write(string path, RgbaImage image)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (image.Pixels.Length != checked(image.Width * image.Height * 4)) throw new ArgumentException("RGBA buffer size is invalid.", nameof(image));
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = File.Create(path);
        output.Write(Signature);
        Span<byte> ihdr = stackalloc byte[13];
        BinaryPrimitives.WriteInt32BigEndian(ihdr, image.Width);
        BinaryPrimitives.WriteInt32BigEndian(ihdr[4..], image.Height);
        ihdr[8] = 8;
        ihdr[9] = 6;
        WriteChunk(output, "IHDR", ihdr);
        using var raw = new MemoryStream();
        for (var y = 0; y < image.Height; y++)
        {
            raw.WriteByte(0);
            raw.Write(image.Pixels, y * image.Stride, image.Stride);
        }
        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            raw.Position = 0;
            raw.CopyTo(zlib);
        }
        WriteChunk(output, "IDAT", compressed.ToArray());
        WriteChunk(output, "IEND", []);
    }

    public static RgbaImage Read(string path)
    {
        using var input = File.OpenRead(path);
        Span<byte> signature = stackalloc byte[8];
        input.ReadExactly(signature);
        if (!signature.SequenceEqual(Signature)) throw new InvalidDataException("Not a PNG file.");
        var width = 0;
        var height = 0;
        using var idat = new MemoryStream();
        while (input.Position < input.Length)
        {
            Span<byte> header = new byte[8];
            input.ReadExactly(header);
            var length = BinaryPrimitives.ReadInt32BigEndian(header);
            if (length < 0) throw new InvalidDataException("Invalid PNG chunk length.");
            var type = System.Text.Encoding.ASCII.GetString(header[4..]);
            var data = new byte[length];
            input.ReadExactly(data);
            Span<byte> crc = new byte[4];
            input.ReadExactly(crc);
            if (type == "IHDR")
            {
                if (data.Length != 13 || data[8] != 8 || data[9] != 6 || data[12] != 0) throw new NotSupportedException("Only non-interlaced 8-bit RGBA PNG is supported.");
                width = BinaryPrimitives.ReadInt32BigEndian(data);
                height = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(4));
            }
            else if (type == "IDAT") idat.Write(data);
            else if (type == "IEND") break;
        }
        if (width <= 0 || height <= 0) throw new InvalidDataException("PNG has no valid IHDR.");
        idat.Position = 0;
        using var decompressed = new MemoryStream();
        using (var zlib = new ZLibStream(idat, CompressionMode.Decompress)) zlib.CopyTo(decompressed);
        var filtered = decompressed.ToArray();
        var stride = checked(width * 4);
        if (filtered.Length != checked((stride + 1) * height)) throw new InvalidDataException("PNG scanline size is inconsistent.");
        var pixels = new byte[checked(stride * height)];
        for (var y = 0; y < height; y++)
        {
            var filter = filtered[y * (stride + 1)];
            var source = filtered.AsSpan(y * (stride + 1) + 1, stride);
            var destination = pixels.AsSpan(y * stride, stride);
            var previous = y == 0 ? ReadOnlySpan<byte>.Empty : pixels.AsSpan((y - 1) * stride, stride);
            Unfilter(filter, source, destination, previous, 4);
        }
        return new RgbaImage(width, height, pixels);
    }

    private static void Unfilter(byte filter, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> previous, int bytesPerPixel)
    {
        for (var index = 0; index < source.Length; index++)
        {
            var left = index >= bytesPerPixel ? destination[index - bytesPerPixel] : 0;
            var up = previous.IsEmpty ? 0 : previous[index];
            var upperLeft = previous.IsEmpty || index < bytesPerPixel ? 0 : previous[index - bytesPerPixel];
            destination[index] = filter switch
            {
                0 => source[index],
                1 => unchecked((byte)(source[index] + left)),
                2 => unchecked((byte)(source[index] + up)),
                3 => unchecked((byte)(source[index] + ((left + up) >> 1))),
                4 => unchecked((byte)(source[index] + Paeth(left, up, upperLeft))),
                _ => throw new InvalidDataException($"Unsupported PNG filter {filter}."),
            };
        }
    }

    private static int Paeth(int left, int up, int upperLeft)
    {
        var estimate = left + up - upperLeft;
        var leftDistance = Math.Abs(estimate - left);
        var upDistance = Math.Abs(estimate - up);
        var upperLeftDistance = Math.Abs(estimate - upperLeft);
        return leftDistance <= upDistance && leftDistance <= upperLeftDistance ? left : upDistance <= upperLeftDistance ? up : upperLeft;
    }

    private static void WriteChunk(Stream output, string type, ReadOnlySpan<byte> data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, data.Length);
        output.Write(length);
        var typeBytes = System.Text.Encoding.ASCII.GetBytes(type);
        output.Write(typeBytes);
        output.Write(data);
        var crcBytes = new byte[typeBytes.Length + data.Length];
        typeBytes.CopyTo(crcBytes, 0);
        data.CopyTo(crcBytes.AsSpan(typeBytes.Length));
        Span<byte> crc = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(crc, ComputeCrc(crcBytes));
        output.Write(crc);
    }

    private static uint ComputeCrc(ReadOnlySpan<byte> data)
    {
        var crc = uint.MaxValue;
        foreach (var value in data) crc = CrcTable[(crc ^ value) & 0xFF] ^ (crc >> 8);
        return crc ^ uint.MaxValue;
    }

    private static uint[] BuildCrcTable()
    {
        var table = new uint[256];
        for (uint value = 0; value < table.Length; value++)
        {
            var crc = value;
            for (var bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
            table[value] = crc;
        }
        return table;
    }
}
