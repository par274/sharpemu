// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Reflection;
using System.Runtime.Serialization;
using SharpEmu.Core.Cpu.Native;
using SharpEmu.HLE;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

/// <summary>
/// Coverage for the guest TLS thread-pointer load patcher used by
/// DirectExecutionBackend.PatchTlsPatterns.
///
/// The encodings exercised here are the exact bytes seen at the faulting RIP of
/// God of War Ragnarök, Minecraft and EA UFC 5 (#789): LLVM's TLS
/// general-dynamic relaxation emits three 0x66 operand-size prefixes before the
/// 0x64 FS override, i.e. `66 66 66 64 48 8B 04 25 00000000` (mov reg, fs:[0]).
///
/// The out-of-range case is the regression guard: the patcher used to write the
/// E8 opcode before validating the rel32 displacement, so a handler that was
/// out of ±2 GiB reach (the pre-fix state for God of War / UFC 5, whose
/// handlers landed in host memory ~2.6 TB from the guest image) left the guest
/// instruction half-corrupted.
/// </summary>
public sealed unsafe class TlsLoadPatcherTests
{
    private static readonly MethodInfo TryPatchTlsLoadInstruction = typeof(DirectExecutionBackend).GetMethod(
        "TryPatchTlsLoadInstruction",
        BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly FieldInfo TlsHandlerAddress = typeof(DirectExecutionBackend).GetField(
        "_tlsHandlerAddress",
        BindingFlags.Instance | BindingFlags.NonPublic)!;

    private delegate bool TryPatchTlsLoadInstructionDelegate(nint address, byte* source, int availableLength);

    // mov rax, fs:[0] — the exact faulting encoding from the three title logs.
    private static readonly byte[] ThreadPointerLoadRax =
        [0x66, 0x66, 0x66, 0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00];

    // mov r13, fs:[0] — same shape, REX.R destination (r13 = index 13).
    private static readonly byte[] ThreadPointerLoadR13 =
        [0x66, 0x66, 0x66, 0x64, 0x4C, 0x8B, 0x2C, 0x25, 0x00, 0x00, 0x00, 0x00];

    private static DirectExecutionBackend CreateBackend()
    {
        // Bypass the constructor: it allocates TLS slots and native state that
        // the patcher does not need and that are awkward to provision in a
        // unit test. Only the _tlsHandlerAddress field is read on this path.
        return (DirectExecutionBackend)FormatterServices.GetUninitializedObject(
            typeof(DirectExecutionBackend));
    }

    private static TryPatchTlsLoadInstructionDelegate GetPatcher(DirectExecutionBackend backend) =>
        (TryPatchTlsLoadInstructionDelegate)Delegate.CreateDelegate(
            typeof(TryPatchTlsLoadInstructionDelegate), backend, TryPatchTlsLoadInstruction);

    private static byte* AllocateExecutablePage()
    {
        // Apple Silicon macOS denies anonymous PROT_EXEC mappings without the
        // JIT entitlement (errno EACCES); CI runs osx-x64 (Rosetta) and
        // Linux/Windows where they succeed. Callers skip when unsupported.
        var memory = HostMemory.Alloc(null, 4096u, 12288u, 64u); // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
        return memory == null ? null : (byte*)memory;
    }

    [Fact]
    public void PatchesLlvmPaddedTlsLoadInRange()
    {
        var backend = CreateBackend();
        var patcher = GetPatcher(backend);
        byte* page = AllocateExecutablePage();
        if (page == null)
        {
            return; // host denies executable mappings (see AllocateExecutablePage)
        }

        try
        {
            // Handler 0x10 past the instruction end: comfortably inside rel32 reach.
            TlsHandlerAddress.SetValue(backend, (nint)(page + 12 + 0x10));

            fixed (byte* code = ThreadPointerLoadRax)
            {
                for (int i = 0; i < ThreadPointerLoadRax.Length; i++)
                {
                    page[i] = code[i];
                }

                bool patched = patcher((nint)page, page, ThreadPointerLoadRax.Length);

                Assert.True(patched);
                Assert.Equal(0xE8, page[0]); // call rel32

                long expectedDisplacement = (long)(nint)(page + 12 + 0x10) - ((long)(nint)page + 5);
                Assert.Equal((int)expectedDisplacement, *(int*)(page + 1));

                // Destination rax: no register move needed, remainder is NOP padding.
                for (int i = 5; i < ThreadPointerLoadRax.Length; i++)
                {
                    Assert.Equal(0x90, page[i]);
                }
            }
        }
        finally
        {
            HostMemory.Free(page, 4096u, 32768u); // MEM_RELEASE
        }
    }

    [Fact]
    public void PatchesRexBDestinationRegister()
    {
        var backend = CreateBackend();
        var patcher = GetPatcher(backend);
        byte* page = AllocateExecutablePage();
        if (page == null)
        {
            return; // host denies executable mappings (see AllocateExecutablePage)
        }

        try
        {
            TlsHandlerAddress.SetValue(backend, (nint)(page + 12 + 0x10));

            fixed (byte* code = ThreadPointerLoadR13)
            {
                for (int i = 0; i < ThreadPointerLoadR13.Length; i++)
                {
                    page[i] = code[i];
                }

                bool patched = patcher((nint)page, page, ThreadPointerLoadR13.Length);

                Assert.True(patched);
                Assert.Equal(0xE8, page[0]);

                // mov r13, rax: REX.WB (0x49) 0x89 /r with modrm 0xC5.
                Assert.Equal(0x49, page[5]);
                Assert.Equal(0x89, page[6]);
                Assert.Equal(0xC5, page[7]);

                for (int i = 8; i < ThreadPointerLoadR13.Length; i++)
                {
                    Assert.Equal(0x90, page[i]);
                }
            }
        }
        finally
        {
            HostMemory.Free(page, 4096u, 32768u); // MEM_RELEASE
        }
    }

    [Fact]
    public void OutOfRangeHandlerLeavesInstructionUntouched()
    {
        var backend = CreateBackend();
        var patcher = GetPatcher(backend);
        byte* page = AllocateExecutablePage();
        if (page == null)
        {
            return; // host denies executable mappings (see AllocateExecutablePage)
        }

        try
        {
            // Handler 3 GiB past the instruction: beyond the ±2 GiB rel32 limit.
            // This is the pre-fix God of War / UFC 5 condition (handler in host
            // memory, guest image unreachable).
            TlsHandlerAddress.SetValue(backend, (nint)(page + 0xC0000000L));

            fixed (byte* code = ThreadPointerLoadRax)
            {
                for (int i = 0; i < ThreadPointerLoadRax.Length; i++)
                {
                    page[i] = code[i];
                }

                bool patched = patcher((nint)page, page, ThreadPointerLoadRax.Length);

                Assert.False(patched);

                // Regression guard: the patcher must not have written the E8
                // opcode before discovering the displacement was out of range.
                for (int i = 0; i < ThreadPointerLoadRax.Length; i++)
                {
                    Assert.Equal(ThreadPointerLoadRax[i], page[i]);
                }
            }
        }
        finally
        {
            HostMemory.Free(page, 4096u, 32768u); // MEM_RELEASE
        }
    }
}
