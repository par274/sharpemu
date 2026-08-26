// Registrations derived from audited Ghidra evidence and pinned by tests.
// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libSceSysmodule.sprx
// Analyzed provider SHA-256: ba80a6c669e034fae536f3ef97eda3704c658a56989be126a2e6086a3af83711
// Each registration prefers the loaded guest export. The shared HLE handler
// is deliberately fail-closed and never claims provider behavior.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class SysmoduleLleExports
{
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] Sysmodule LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
