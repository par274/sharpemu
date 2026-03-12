// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE;

/// <summary>
/// Represents synthetic kernel-style result codes used by the Gen5 runtime.
/// Prefixed with ORBIS_GEN2 to distinguish from PS4-oriented ORBIS_* codes
/// used by other emulators such as shadPS4.
/// </summary>
public enum OrbisGen2Result : int
{
    /// <summary>
    /// Indicates successful completion.
    /// </summary>
    ORBIS_GEN2_OK = 0,

    /// <summary>
    /// Indicates that the operation is not permitted for the calling thread.
    /// </summary>
    ORBIS_GEN2_ERROR_PERMISSION_DENIED = unchecked((int)0x80020001),

    /// <summary>
    /// Indicates that the requested export was not found.
    /// </summary>
    ORBIS_GEN2_ERROR_NOT_FOUND = unchecked((int)0x80020002),

    /// <summary>
    /// Indicates that one or more arguments were invalid.
    /// </summary>
    ORBIS_GEN2_ERROR_INVALID_ARGUMENT = unchecked((int)0x80020003),

    /// <summary>
    /// Indicates that an item already exists.
    /// </summary>
    ORBIS_GEN2_ERROR_ALREADY_EXISTS = unchecked((int)0x80020004),

    /// <summary>
    /// Indicates that completing the operation would deadlock.
    /// </summary>
    ORBIS_GEN2_ERROR_DEADLOCK = unchecked((int)0x8002000B),

    /// <summary>
    /// Indicates that the target resource is busy.
    /// </summary>
    ORBIS_GEN2_ERROR_BUSY = unchecked((int)0x80020010),

    /// <summary>
    /// Indicates that behavior is recognized but not implemented yet.
    /// </summary>
    ORBIS_GEN2_ERROR_NOT_IMPLEMENTED = unchecked((int)0x8002FFFF),

    /// <summary>
    /// Indicates that the operation timed out.
    /// </summary>
    ORBIS_GEN2_ERROR_TIMED_OUT = unchecked((int)0x8002003C),

    /// <summary>
    /// Indicates that memory access failed.
    /// </summary>
    ORBIS_GEN2_ERROR_MEMORY_FAULT = unchecked((int)0x80020101),

    /// <summary>
    /// Indicates that CPU execution trapped on an unsupported instruction.
    /// </summary>
    ORBIS_GEN2_ERROR_CPU_TRAP = unchecked((int)0x80020102),
}
