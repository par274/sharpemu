// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.VideoOut;
using SharpEmu.ShaderCompiler.Vulkan;
using Silk.NET.Vulkan;
using Xunit;

namespace SharpEmu.Libs.Tests.VideoOut;

public sealed class VulkanGameOverlayColorTests
{
    [Theory]
    [InlineData(Format.B8G8R8A8Srgb, true)]
    [InlineData(Format.R8G8B8A8Srgb, true)]
    [InlineData(Format.B8G8R8A8Unorm, false)]
    [InlineData(Format.R8G8B8A8Unorm, false)]
    [InlineData(Format.A2B10G10R10UnormPack32, false)]
    public void LinearizationDependsOnlyOnSrgbOverlayTarget(
        Format swapchainFormat,
        bool expected)
    {
        Assert.Equal(
            expected,
            VulkanVideoPresenter.GameOverlayNeedsLinearization(swapchainFormat));
    }

    [Fact]
    public void SrgbTargetUsesDedicatedGpuColorFragment()
    {
        var unorm = VulkanVideoPresenter.CreateGameOverlayFragment(
            Format.B8G8R8A8Unorm);
        var srgb = VulkanVideoPresenter.CreateGameOverlayFragment(
            Format.B8G8R8A8Srgb);

        Assert.Equal(0x07230203u, BitConverter.ToUInt32(unorm));
        Assert.Equal(0x07230203u, BitConverter.ToUInt32(srgb));
        Assert.NotEqual(Convert.ToHexString(unorm), Convert.ToHexString(srgb));
        Assert.True(srgb.Length > unorm.Length);
        Assert.DoesNotContain(SpirvOp.FDiv, ReadOpcodes(unorm));
        Assert.Contains(SpirvOp.FDiv, ReadOpcodes(srgb));
    }

    [Fact]
    public void EquivalentUnormTargetsShareOverlayFragment()
    {
        var bgra = VulkanVideoPresenter.CreateGameOverlayFragment(
            Format.B8G8R8A8Unorm);
        var rgba = VulkanVideoPresenter.CreateGameOverlayFragment(
            Format.R8G8B8A8Unorm);

        Assert.Equal(bgra, rgba);
    }

    private static IReadOnlyList<SpirvOp> ReadOpcodes(byte[] spirv)
    {
        var result = new List<SpirvOp>();
        for (var offset = 5 * sizeof(uint); offset < spirv.Length;)
        {
            var instruction = BitConverter.ToUInt32(spirv, offset);
            var wordCount = checked((int)(instruction >> 16));
            Assert.True(wordCount > 0);
            result.Add((SpirvOp)(instruction & ushort.MaxValue));
            offset = checked(offset + (wordCount * sizeof(uint)));
        }

        return result;
    }
}
