// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Agc;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

// GnmTiling had no test coverage while it carries the AddrLib address
// equations every sampled texture goes through: an off-by-one in one of the
// XOR patterns shows up as a plausible-looking but wrong image, not as a
// crash. These tests pin the produced layout per (swizzle mode, bytes per
// element) so the inner loop can be rewritten for speed without silently
// changing which source byte ends up in which linear texel.
//
// The digests are of this implementation's own output. They guard against
// accidental change, not against an equation being wrong in the first place
// (that is judged against real game output). Changing an equation on purpose
// means updating the digest in the same commit.
public sealed class GnmTilingTests
{
    // Wide enough to exercise x bit 8 and cross several blocks on both axes,
    // which is where the pipe/bank XOR terms (x bits 7-8, y bits 6-8) differ
    // from a plain in-block interleave.
    private const int ElementsWide = 300;
    private const int ElementsHigh = 260;

    [Theory]
    // Modes 4/8 have no exact XOR equation and go through the in-block lookup
    // table instead. Mode 1 (256-byte standard) has a dedicated exact-XOR
    // equation (GFX10_SW_256_S_PATINFO, see Standard256) restored by
    // da84c6d/c1db69a after real-game verification against Silent Hill and
    // BC7 UI atlases -- these digests are of THAT equation's output, not the
    // generic in-block table this test file's original author assumed.
    [InlineData(1u, 1, 9373457174742985018UL)]
    [InlineData(1u, 2, 1535095006861030149UL)]
    [InlineData(1u, 4, 15322246220556221652UL)]
    [InlineData(1u, 8, 16778130063301205745UL)]
    [InlineData(1u, 16, 14754308494608776987UL)]
    [InlineData(4u, 1, 4896927349800003199UL)]
    [InlineData(4u, 2, 7440824389071839579UL)]
    [InlineData(4u, 4, 12417885670086142753UL)]
    [InlineData(4u, 8, 9456317421549486312UL)]
    [InlineData(4u, 16, 10995937233086780193UL)]
    [InlineData(8u, 1, 11685874823863667647UL)]
    [InlineData(8u, 2, 17707567930476074095UL)]
    [InlineData(8u, 4, 4600870536214423075UL)]
    [InlineData(8u, 8, 12173043538343114599UL)]
    [InlineData(8u, 16, 1156856920356599754UL)]
    [InlineData(5u, 1, 7246415878745753432UL)]
    [InlineData(5u, 2, 14435384688678695318UL)]
    [InlineData(5u, 4, 16813426762859418361UL)]
    [InlineData(5u, 8, 1305029830924435541UL)]
    [InlineData(5u, 16, 1761949662825481149UL)]
    [InlineData(9u, 1, 781594426468798681UL)]
    [InlineData(9u, 2, 9384984530253819586UL)]
    [InlineData(9u, 4, 6335803366186683427UL)]
    [InlineData(9u, 8, 5202842595239197855UL)]
    [InlineData(9u, 16, 271505013880843386UL)]
    [InlineData(24u, 1, 12728123615436850450UL)]
    [InlineData(24u, 2, 16634758631384626540UL)]
    [InlineData(24u, 4, 9040512703311957873UL)]
    [InlineData(24u, 8, 7101474595040955476UL)]
    // 16 bytes/element is the same equation as R_X below for a 2D
    // single-sample image, so these two digests matching is expected.
    [InlineData(24u, 16, 299874270212214466UL)]
    [InlineData(27u, 1, 14602703818998845965UL)]
    [InlineData(27u, 2, 14277964247548676447UL)]
    [InlineData(27u, 4, 111154174251802185UL)]
    [InlineData(27u, 8, 13241207831334217638UL)]
    [InlineData(27u, 16, 299874270212214466UL)]
    public void DetiledLayoutIsStable(uint swizzleMode, int bytesPerElement, ulong expectedDigest)
    {
        var tiled = BuildSource(swizzleMode, bytesPerElement);
        var linear = new byte[ElementsWide * ElementsHigh * bytesPerElement];

        Assert.True(GnmTiling.TryDetile(
            tiled,
            linear,
            swizzleMode,
            ElementsWide,
            ElementsHigh,
            bytesPerElement));

        Assert.Equal(expectedDigest, Digest(linear));
    }

    [Theory]
    [InlineData(1u, 4)]
    [InlineData(1u, 8)]
    [InlineData(1u, 16)]
    [InlineData(4u, 4)]
    [InlineData(4u, 8)]
    [InlineData(4u, 16)]
    [InlineData(8u, 4)]
    [InlineData(8u, 8)]
    [InlineData(8u, 16)]
    [InlineData(5u, 4)]
    [InlineData(5u, 8)]
    [InlineData(5u, 16)]
    [InlineData(9u, 4)]
    [InlineData(9u, 8)]
    [InlineData(9u, 16)]
    [InlineData(24u, 4)]
    [InlineData(24u, 8)]
    [InlineData(24u, 16)]
    [InlineData(27u, 4)]
    [InlineData(27u, 8)]
    [InlineData(27u, 16)]
    public void DetileMapsEveryLinearElementToADistinctSourceElement(uint swizzleMode, int bytesPerElement)
    {
        // Address equations are permutations: every linear element must come
        // from its own source element. A wrong offset shows up here as two
        // linear elements carrying the same source marker, which the digest
        // above would flag but not localise. Restricted to elements of at
        // least 4 bytes because smaller ones cannot hold a unique marker for
        // a surface of this many elements.
        var tiled = BuildMarkedSource(swizzleMode, bytesPerElement, out var sourceElements);
        var linear = new byte[ElementsWide * ElementsHigh * bytesPerElement];

        Assert.True(GnmTiling.TryDetile(
            tiled,
            linear,
            swizzleMode,
            ElementsWide,
            ElementsHigh,
            bytesPerElement));

        var seen = new HashSet<uint>();
        for (var index = 0; index < ElementsWide * ElementsHigh; index++)
        {
            var marker = ReadMarker(linear, index, bytesPerElement);
            Assert.InRange(marker, 0u, (uint)sourceElements - 1);
            Assert.True(seen.Add(marker), $"element {index} duplicates source element {marker}");
        }
    }

    [Fact]
    public void LinearSurfaceIsNotDetiled()
    {
        // Mode 0 is already linear; detiling it would scramble a correct image.
        Assert.False(GnmTiling.NeedsDetile(0));
        Assert.False(GnmTiling.TryDetile(
            new byte[64],
            new byte[64],
            swizzleMode: 0,
            elementsWide: 8,
            elementsHigh: 8,
            bytesPerElement: 1));
    }

    [Fact]
    public void UnsupportedSwizzleModeLeavesOutputUntouched()
    {
        // Callers rely on "false means fall back to the raw bytes"; writing a
        // partial result here would upload a half-deswizzled texture.
        var linear = new byte[64];
        Assert.False(GnmTiling.TryDetile(
            new byte[256],
            linear,
            swizzleMode: 31,
            elementsWide: 8,
            elementsHigh: 8,
            bytesPerElement: 1));
        Assert.All(linear, value => Assert.Equal(0, value));
    }

    [Fact]
    public void ShortDestinationIsRejected()
    {
        Assert.False(GnmTiling.TryDetile(
            new byte[65536],
            new byte[8],
            swizzleMode: 9,
            elementsWide: 64,
            elementsHigh: 64,
            bytesPerElement: 4));
    }

    private static byte[] BuildSource(uint swizzleMode, int bytesPerElement)
    {
        var tiled = new byte[TiledByteCount(swizzleMode, bytesPerElement)];
        for (var index = 0; index < tiled.Length; index++)
        {
            // Deliberately NOT a linear ramp. Every swizzle block is a
            // multiple of 256 bytes and the low 8 offset bits agree between
            // several of these modes, so a byte value that depends only on
            // offset mod 256 produces the SAME digest for genuinely different
            // layouts (observed while writing this test). Taking the high
            // bits of a multiplicative hash makes the value depend on the
            // whole offset.
            tiled[index] = (byte)((uint)index * 0x9E3779B1u >> 24);
        }

        return tiled;
    }

    // Fills a tiled surface so that each source element holds its own element
    // index, letting the caller check the mapping is a permutation.
    private static byte[] BuildMarkedSource(
        uint swizzleMode,
        int bytesPerElement,
        out int sourceElements)
    {
        var tiled = new byte[TiledByteCount(swizzleMode, bytesPerElement)];
        sourceElements = tiled.Length / bytesPerElement;
        for (var element = 0; element < sourceElements; element++)
        {
            var offset = element * bytesPerElement;
            for (var index = 0; index < sizeof(uint); index++)
            {
                tiled[offset + index] = (byte)((uint)element >> (index * 8));
            }
        }

        return tiled;
    }

    private static int TiledByteCount(uint swizzleMode, int bytesPerElement)
    {
        Assert.True(GnmTiling.TryGetTiledByteCount(
            swizzleMode,
            ElementsWide,
            ElementsHigh,
            bytesPerElement,
            out var tiledByteCount));
        return checked((int)tiledByteCount);
    }

    private static uint ReadMarker(byte[] buffer, int element, int bytesPerElement)
    {
        var offset = element * bytesPerElement;
        uint marker = 0;
        for (var index = 0; index < sizeof(uint); index++)
        {
            marker |= (uint)buffer[offset + index] << (index * 8);
        }

        return marker;
    }

    private static ulong Digest(byte[] data)
    {
        var hash = 0xCBF29CE484222325UL;
        foreach (var value in data)
        {
            hash = (hash ^ value) * 0x100000001B3UL;
        }

        return hash;
    }
}
