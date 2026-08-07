// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.Core.Cpu.Emulation;

/// <summary>
/// Decoder for the guest thread-pointer load <c>mov reg, fs:[0]</c>.
///
/// On the PS5 this reads the thread's TCB self-pointer. The host process has no guest FS base -
/// on Windows the FS base is zero - so the instruction cannot run natively: it would read linear
/// address 0 and fault. The backend therefore rewrites every occurrence it finds at load time
/// into a call to the TLS handler, which returns the guest TLS base for the calling thread.
///
/// The same encoding has to be recognised in two places: by the ahead-of-time patcher walking
/// module bytes, and by the access-violation handler when an occurrence reaches the CPU
/// unrewritten. Keeping one decoder means the fault-time path accepts exactly what the patcher
/// accepts, and the two can never drift apart.
///
/// The decoder works on a plain byte span with no native state, so it can be unit-tested against
/// the instruction bytes captured in crash logs.
/// </summary>
public static class TlsThreadPointerLoad
{
    /// <summary>
    /// Longest form this decoder accepts: three operand-size prefixes, the segment override, a
    /// REX byte, the opcode, ModRM, SIB and a 32-bit displacement.
    /// </summary>
    public const int MaxLength = 12;

    /// <summary>
    /// Decodes <c>mov reg, fs:[0]</c> at the start of <paramref name="code"/>.
    ///
    /// The accepted shape is any number of <c>0x66</c> operand-size prefixes (LLVM's TLS
    /// general-dynamic relaxation emits three), the <c>0x64</c> FS override, an optional REX,
    /// then <c>8B /r</c> with <c>mod=00</c>, <c>rm=100</c>, <c>SIB=0x25</c> and a zero
    /// displacement - the absolute-address form that names offset 0 in the segment.
    /// </summary>
    /// <param name="destinationRegister">
    /// The x86 register number the thread pointer is loaded into, 0-15 in encoding order
    /// (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15).
    /// </param>
    /// <param name="length">Total instruction length in bytes, prefixes included.</param>
    public static bool TryDecode(ReadOnlySpan<byte> code, out int destinationRegister, out int length)
    {
        destinationRegister = 0;
        length = 0;

        var offset = 0;
        while (offset < code.Length && code[offset] == 0x66)
        {
            offset++;
        }

        if (offset >= code.Length || code[offset] != 0x64)
        {
            return false;
        }

        offset++;
        if (offset >= code.Length)
        {
            return false;
        }

        var rex = (byte)0;
        if (code[offset] >= 0x40 && code[offset] <= 0x4F)
        {
            rex = code[offset];
            offset++;
        }

        // opcode + ModRM + SIB + disp32
        if (offset + 7 > code.Length || code[offset] != 0x8B)
        {
            return false;
        }

        var modRm = code[offset + 1];
        var sib = code[offset + 2];
        if ((modRm >> 6) != 0 || (modRm & 7) != 4 || sib != 0x25)
        {
            return false;
        }

        var displacement =
            code[offset + 3] |
            (code[offset + 4] << 8) |
            (code[offset + 5] << 16) |
            (code[offset + 6] << 24);
        if (displacement != 0)
        {
            return false;
        }

        destinationRegister = ((modRm >> 3) & 7) | (((rex & 4) != 0) ? 8 : 0);
        length = offset + 7;
        return true;
    }
}
