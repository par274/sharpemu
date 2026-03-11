// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Core.Cpu;

public enum CpuExitReason
{
    Exited = 0,

    SentinelReturn = 1,

    ReturnedToHost = 2,

    Halted = 3,

    BudgetExceeded = 4,

    CpuTrap = 5,

    UnhandledException = 6,

    UnhandledSyscall = 7,

    NativeBackendUnavailable = 8,
}
