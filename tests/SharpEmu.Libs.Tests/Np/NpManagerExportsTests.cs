// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.Np;
using Xunit;

namespace SharpEmu.Libs.Tests.Np;

public sealed class NpManagerExportsTests
{
    [Theory]
    [InlineData("+yqjab2fUJA", "sceNpRegisterPremiumEventCallback")]
    [InlineData("-Rjp3-YViXc", "sceNpUnregisterPremiumEventCallback")]
    public void PremiumEventCallbackExportsRegisterForBothGenerations(string nid, string name)
    {
        foreach (var generation in new[] { Generation.Gen4, Generation.Gen5 })
        {
            var manager = new ModuleManager();
            manager.RegisterExports(
                SharpEmu.Generated.SysAbiExportRegistry.CreateExports(generation));

            Assert.True(manager.TryGetExport(nid, out var export));
            Assert.Equal(name, export.Name);
            Assert.Equal("libSceNpManager", export.LibraryName);
        }
    }

    [Fact]
    public void PremiumEventCallbackRegistrationSucceedsForOfflineProfile()
    {
        var context = new CpuContext(new FakeCpuMemory(0x1_0000_0000, 0x1000), Generation.Gen5);

        Assert.Equal((int)OrbisGen2Result.ORBIS_GEN2_OK, NpManagerExports.NpRegisterPremiumEventCallback(context));
        Assert.Equal(0UL, context[CpuRegister.Rax]);

        Assert.Equal((int)OrbisGen2Result.ORBIS_GEN2_OK, NpManagerExports.NpUnregisterPremiumEventCallback(context));
        Assert.Equal(0UL, context[CpuRegister.Rax]);
    }
}
