// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Core.Cpu;

public enum CpuControlTransferKind
{
    Call = 0,

    Jump = 1,

    Return = 2,
}
