// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using System.Text;

namespace SharpEmu.GUI.FontSubsetter;

/// <summary>
/// Rewrites the small set of OpenType name records affected by instantiating
/// a variable font. HarfBuzz produces the correct static outlines and weight,
/// but intentionally preserves the default instance's "Thin" names.
/// </summary>
internal static class OpenTypeNameEditor
{
    private const uint NameTag = 0x6E616D65; // name
    private const uint HeadTag = 0x68656164; // head
    private const uint ChecksumMagic = 0xB1B0AFBA;

    public static void Rewrite(
        string path,
        string familyName,
        string postScriptFamilyName,
        string style)
    {
        var font = File.ReadAllBytes(path);
        if (font.Length < 12)
        {
            throw new InvalidDataException($"Invalid OpenType font: {path}");
        }

        var tableCount = ReadUInt16(font, 4);
        var directoryLength = checked(12 + tableCount * 16);
        if (directoryLength > font.Length)
        {
            throw new InvalidDataException($"Invalid OpenType table directory: {path}");
        }

        var tables = new List<Table>(tableCount);
        for (var index = 0; index < tableCount; index++)
        {
            var recordOffset = 12 + index * 16;
            var tag = ReadUInt32(font, recordOffset);
            var tableOffset = checked((int)ReadUInt32(font, recordOffset + 8));
            var tableLength = checked((int)ReadUInt32(font, recordOffset + 12));
            if (tableOffset < 0
                || tableLength < 0
                || tableOffset > font.Length - tableLength)
            {
                throw new InvalidDataException($"Invalid OpenType table bounds: {path}");
            }

            var data = font.AsSpan(tableOffset, tableLength).ToArray();
            if (tag == NameTag)
            {
                data = RewriteNameTable(
                    data,
                    familyName,
                    postScriptFamilyName,
                    style);
            }
            else if (tag == HeadTag)
            {
                if (data.Length < 12)
                {
                    throw new InvalidDataException($"Invalid OpenType head table: {path}");
                }

                data.AsSpan(8, 4).Clear();
            }

            tables.Add(new Table(tag, data));
        }

        if (tables.All(table => table.Tag != NameTag)
            || tables.All(table => table.Tag != HeadTag))
        {
            throw new InvalidDataException($"Required OpenType tables are missing: {path}");
        }

        var rebuilt = RebuildFont(font.AsSpan(0, 12), tables, out var headOffset);
        var checksumAdjustment = unchecked(ChecksumMagic - Checksum(rebuilt));
        WriteUInt32(rebuilt, headOffset + 8, checksumAdjustment);
        File.WriteAllBytes(path, rebuilt);
    }

    private static byte[] RewriteNameTable(
        byte[] table,
        string familyName,
        string postScriptFamilyName,
        string style)
    {
        if (table.Length < 6 || ReadUInt16(table, 0) != 0)
        {
            throw new NotSupportedException(
                "Only OpenType name table format 0 is supported.");
        }

        var recordCount = ReadUInt16(table, 2);
        var stringOffset = ReadUInt16(table, 4);
        var recordsLength = checked(6 + recordCount * 12);
        if (recordsLength > table.Length || stringOffset > table.Length)
        {
            throw new InvalidDataException("Invalid OpenType name table.");
        }

        using var strings = new MemoryStream();
        var rebuilt = new byte[recordsLength];
        WriteUInt16(rebuilt, 0, 0);
        WriteUInt16(rebuilt, 2, recordCount);
        WriteUInt16(rebuilt, 4, checked((ushort)recordsLength));

        for (var index = 0; index < recordCount; index++)
        {
            var sourceRecordOffset = 6 + index * 12;
            var destinationRecordOffset = sourceRecordOffset;
            var platformId = ReadUInt16(table, sourceRecordOffset);
            var nameId = ReadUInt16(table, sourceRecordOffset + 6);
            var sourceLength = ReadUInt16(table, sourceRecordOffset + 8);
            var sourceStringOffset = checked(
                stringOffset + ReadUInt16(table, sourceRecordOffset + 10));
            if (sourceStringOffset > table.Length - sourceLength)
            {
                throw new InvalidDataException("Invalid OpenType name record.");
            }

            var replacement = ReplacementFor(
                nameId,
                familyName,
                postScriptFamilyName,
                style);
            byte[] encoded;
            if (replacement is null)
            {
                encoded = table.AsSpan(sourceStringOffset, sourceLength).ToArray();
            }
            else if (platformId is 0 or 3)
            {
                encoded = EncodeBigEndianUnicode(replacement);
            }
            else
            {
                // Noto CJK uses Windows Unicode records. Preserve any
                // unfamiliar legacy-platform record instead of guessing its
                // encoding.
                encoded = table.AsSpan(sourceStringOffset, sourceLength).ToArray();
            }

            table.AsSpan(sourceRecordOffset, 8)
                .CopyTo(rebuilt.AsSpan(destinationRecordOffset, 8));
            WriteUInt16(
                rebuilt,
                destinationRecordOffset + 8,
                checked((ushort)encoded.Length));
            WriteUInt16(
                rebuilt,
                destinationRecordOffset + 10,
                checked((ushort)strings.Position));
            strings.Write(encoded);
        }

        return [.. rebuilt, .. strings.ToArray()];
    }

    private static string? ReplacementFor(
        ushort nameId,
        string familyName,
        string postScriptFamilyName,
        string style) =>
        nameId switch
        {
            1 or 16 => familyName,
            2 or 17 => style,
            3 => $"{familyName.Replace(" ", string.Empty, StringComparison.Ordinal)}-{style};SharpEmu",
            4 => style == "Regular" ? familyName : $"{familyName} {style}",
            6 => $"{postScriptFamilyName}-{style}",
            _ => null,
        };

    private static byte[] EncodeBigEndianUnicode(string value)
    {
        var encoded = Encoding.BigEndianUnicode.GetBytes(value);
        return encoded;
    }

    private static byte[] RebuildFont(
        ReadOnlySpan<byte> offsetTable,
        IReadOnlyList<Table> tables,
        out int headOffset)
    {
        var directoryLength = checked(12 + tables.Count * 16);
        var totalLength = directoryLength
                          + tables.Sum(table => Align4(table.Data.Length));
        var rebuilt = new byte[totalLength];
        offsetTable.CopyTo(rebuilt);
        headOffset = -1;
        var currentOffset = directoryLength;

        for (var index = 0; index < tables.Count; index++)
        {
            var table = tables[index];
            var recordOffset = 12 + index * 16;
            WriteUInt32(rebuilt, recordOffset, table.Tag);
            WriteUInt32(rebuilt, recordOffset + 4, Checksum(table.Data));
            WriteUInt32(rebuilt, recordOffset + 8, checked((uint)currentOffset));
            WriteUInt32(rebuilt, recordOffset + 12, checked((uint)table.Data.Length));
            table.Data.CopyTo(rebuilt, currentOffset);

            if (table.Tag == HeadTag)
            {
                headOffset = currentOffset;
            }

            currentOffset += Align4(table.Data.Length);
        }

        if (headOffset < 0)
        {
            throw new InvalidDataException("OpenType head table is missing.");
        }

        return rebuilt;
    }

    private static uint Checksum(ReadOnlySpan<byte> data)
    {
        uint checksum = 0;
        Span<byte> word = stackalloc byte[4];
        for (var offset = 0; offset < data.Length; offset += 4)
        {
            word.Clear();
            var count = Math.Min(4, data.Length - offset);
            data.Slice(offset, count).CopyTo(word);
            checksum = unchecked(checksum + BinaryPrimitives.ReadUInt32BigEndian(word));
        }

        return checksum;
    }

    private static int Align4(int value) => checked((value + 3) & ~3);

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, 4));

    private static void WriteUInt16(Span<byte> data, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16BigEndian(data.Slice(offset, 2), value);

    private static void WriteUInt32(Span<byte> data, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32BigEndian(data.Slice(offset, 4), value);

    private sealed record Table(uint Tag, byte[] Data);
}
