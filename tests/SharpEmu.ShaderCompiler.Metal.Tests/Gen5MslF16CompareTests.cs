// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.ShaderCompiler;
using SharpEmu.ShaderCompiler.Metal;
using Xunit;

namespace SharpEmu.ShaderCompiler.Metal.Tests;

public sealed class Gen5MslF16CompareTests
{
    public static TheoryData<string> Opcodes = new()
    {
        "VCmpFF16",
        "VCmpLtF16",
        "VCmpEqF16",
        "VCmpLeF16",
        "VCmpGtF16",
        "VCmpLgF16",
        "VCmpGeF16",
        "VCmpOF16",
        "VCmpxFF16",
        "VCmpxLtF16",
        "VCmpxEqF16",
        "VCmpxLeF16",
        "VCmpxGtF16",
        "VCmpxLgF16",
        "VCmpxGeF16",
        "VCmpxOF16",
        "VCmpUF16",
        "VCmpNgeF16",
        "VCmpNlgF16",
        "VCmpNgtF16",
        "VCmpNleF16",
        "VCmpNeqF16",
        "VCmpNltF16",
        "VCmpTruF16",
        "VCmpxUF16",
        "VCmpxNgeF16",
        "VCmpxNlgF16",
        "VCmpxNgtF16",
        "VCmpxNleF16",
        "VCmpxNeqF16",
        "VCmpxNltF16",
        "VCmpxTruF16",
    };

    [Theory]
    [MemberData(nameof(Opcodes))]
    public void F16CompareOpcodeLowersToMsl(string opcode)
    {
        var compare = new Gen5ShaderInstruction(
            0,
            Gen5ShaderEncoding.Vopc,
            opcode,
            [0u],
            [Gen5Operand.Vector(0), Gen5Operand.Vector(1)],
            [],
            null);
        var state = new Gen5ShaderState(
            new Gen5ShaderProgram(0x1000, [compare]),
            [],
            null);
        var scalars = new uint[256];
        var evaluation = new Gen5ShaderEvaluation(scalars, scalars, [], []);

        Assert.True(
            Gen5MslTranslator.TryCompileComputeShader(
                state,
                evaluation,
                1,
                1,
                1,
                out var shader,
                out var error),
            error);
        Assert.NotEmpty(shader.Source);
        if (opcode is not (
            "VCmpFF16" or "VCmpxFF16" or
            "VCmpTruF16" or "VCmpxTruF16"))
        {
            Assert.Contains("half", shader.Source, StringComparison.Ordinal);
        }
    }
}
