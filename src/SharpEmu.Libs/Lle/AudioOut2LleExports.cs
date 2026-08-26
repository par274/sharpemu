// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ghidra 12.1.2_PUBLIC_20260605 program: libSceAudioOut.sprx
// Analyzed provider SHA-256: 948dfdc30b9c974c5447d9078853beb1555a2e548de6093b05a114e99445ab33
// The three stateful speaker-array registrations formerly generated here now
// have Ghidra-backed HLE fallbacks in AudioOut2Exports. This legacy handler is
// retained for direct fail-closed contract checks but owns no registrations.

using SharpEmu.HLE;

namespace SharpEmu.Libs.Lle;

public static class AudioOut2LleExports
{
    public static int MissingGuestProvider(CpuContext ctx)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_IMPORTS"), "1", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[LOADER][ERROR] AudioOut2 LLE-preferred export reached its fail-closed HLE fallback");
        }

        return ctx.SetReturn(OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED);
    }
}
