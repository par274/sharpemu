<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# POSIX Signal EFLAGS Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve guest EFLAGS while SharpEmu recovers BMI/ABM illegal instructions through Linux and macOS signal contexts.

**Architecture:** Extend the existing POSIX-to-Win64 context adapter with one platform-selected EFLAGS offset and a low-32-bit capture/write-back pair. Exercise the production adapter through its established fabricated-signal-frame test seam, using Linux ABI storage on Windows/Linux and Darwin ABI storage on macOS.

**Tech Stack:** C# 14, .NET 10, xUnit, SharpEmu's native direct-execution backend, Git

## Global Constraints

- Linux x86-64 EFLAGS is `gregs[17]`, byte offset 136 from `GetPosixRegisterBase`.
- Darwin x86-64 EFLAGS is `__rflags`, byte offset 152 from `GetPosixRegisterBase`.
- Copy only the low 32 bits so the Win64 `CONTEXT.EFlags` contract is exact and upper platform storage bits remain untouched.
- Write EFLAGS back only after the existing recovery chain returns success.
- Do not change BMI/ABM instruction semantics, install real signal handlers in tests, bridge Darwin XMM state, add dependencies, or alter public APIs.
- Keep the patch limited to the POSIX signal bridge, its existing test fixture, and the approved design/plan records.

---

### Task 1: Round-trip EFLAGS through POSIX signal recovery

**Files:**

- Modify: `src/SharpEmu.Core/Cpu/Native/DirectExecutionBackend.PosixSignals.cs:42-75,261-369`
- Move: `tests/SharpEmu.Libs.Tests/Cpu/Sse4aPosixSignalRecoveryTests.cs` to `tests/SharpEmu.Libs.Tests/Cpu/PosixSignalRecoveryTests.cs`
- Modify: `tests/SharpEmu.Libs.Tests/Cpu/PosixSignalRecoveryTests.cs:13-223`

**Interfaces:**

- Consumes: `DirectExecutionBackend.TryHandlePosixFault(int signal, nint siginfo, nint ucontext)`, `CTX_EFLAGS`, `ReadCtxU32`, and `WriteCtxU32`.
- Produces: no new public interface; the existing adapter additionally round-trips the platform EFLAGS field.

- [ ] **Step 1: Restore the isolated worktree**

Run:

```powershell
dotnet restore SharpEmu.slnx --disable-parallel
```

Expected: exit code 0 and all projects restored.

- [ ] **Step 2: Generalize the existing POSIX recovery test fixture**

Move the test file to `PosixSignalRecoveryTests.cs`, rename the class to
`PosixSignalRecoveryTests`, and replace its class summary with:

```csharp
/// <summary>
/// Coverage for illegal-instruction recovery through the POSIX signal bridge. Tests
/// fabricate the platform signal frames consumed by TryHandlePosixFault and verify
/// that recovered register state is written back exactly as sigreturn would restore it.
/// </summary>
public sealed unsafe class PosixSignalRecoveryTests
```

Add these constants beside the existing signal-frame offsets:

```csharp
private const uint CarryFlag = 1u << 0;
private const uint ReservedFlag = 1u << 1;
private const uint ZeroFlag = 1u << 6;
private const uint DirectionFlag = 1u << 10;

private const int DarwinUcontextMcontextOffset = 48;
private const int DarwinRaxOffset = 16;
private const int DarwinRipOffset = 144;
private const int DarwinRflagsOffset = 152;
private const int LinuxGregsRaxOffset = 13 * 8;
private const int LinuxGregsRflagsOffset = 17 * 8;
```

Replace the existing `FakeSignalFrame` class with this platform-aware fixture:

```csharp
private sealed class FakeSignalFrame
{
    private readonly byte[] _ucontext = new byte[512];
    private readonly byte[] _mcontext = new byte[512];
    private readonly byte[] _fpstate = new byte[512];
    private readonly bool _wireFpstate;

    public FakeSignalFrame(ulong rip, bool wireFpstate = true)
    {
        _wireFpstate = wireFpstate;
        WriteRegisterU64(PlatformRipOffset, rip);
    }

    public ulong Rax
    {
        get => ReadRegisterU64(PlatformRaxOffset);
        set => WriteRegisterU64(PlatformRaxOffset, value);
    }

    public uint EFlags
    {
        get => ReadRegisterU32(PlatformRflagsOffset);
        set => WriteRegisterU32(PlatformRflagsOffset, value);
    }

    public ulong Rip => ReadRegisterU64(PlatformRipOffset);

    public void SetXmmLow(int fxsaveOffset, ulong value)
    {
        fixed (byte* fpstate = _fpstate)
        {
            *(ulong*)(fpstate + fxsaveOffset) = value;
        }
    }

    public ulong XmmLow(int fxsaveOffset)
    {
        fixed (byte* fpstate = _fpstate)
        {
            return *(ulong*)(fpstate + fxsaveOffset);
        }
    }

    public ulong XmmHigh(int fxsaveOffset)
    {
        fixed (byte* fpstate = _fpstate)
        {
            return *(ulong*)(fpstate + fxsaveOffset + 8);
        }
    }

    public bool Dispatch()
    {
        EnsureBridgeBackend();
        fixed (byte* ucontext = _ucontext)
        fixed (byte* mcontext = _mcontext)
        fixed (byte* fpstate = _fpstate)
        {
            if (OperatingSystem.IsMacOS())
            {
                *(byte**)(ucontext + DarwinUcontextMcontextOffset) = mcontext;
            }
            else if (_wireFpstate)
            {
                *(byte**)(ucontext + LinuxUcontextGregsOffset + LinuxGregsFpstateOffset) = fpstate;
            }

            return (bool)TryHandlePosixFault.Invoke(
                null,
                [PosixSigIll, (nint)0, (nint)ucontext])!;
        }
    }

    private static int PlatformRaxOffset =>
        OperatingSystem.IsMacOS() ? DarwinRaxOffset : LinuxGregsRaxOffset;

    private static int PlatformRipOffset =>
        OperatingSystem.IsMacOS() ? DarwinRipOffset : LinuxGregsRipOffset;

    private static int PlatformRflagsOffset =>
        OperatingSystem.IsMacOS() ? DarwinRflagsOffset : LinuxGregsRflagsOffset;

    private byte[] RegisterStorage => OperatingSystem.IsMacOS() ? _mcontext : _ucontext;

    private int RegisterBaseOffset => OperatingSystem.IsMacOS() ? 0 : LinuxUcontextGregsOffset;

    private ulong ReadRegisterU64(int offset)
    {
        var storage = RegisterStorage;
        fixed (byte* registers = storage)
        {
            return *(ulong*)(registers + RegisterBaseOffset + offset);
        }
    }

    private uint ReadRegisterU32(int offset)
    {
        var storage = RegisterStorage;
        fixed (byte* registers = storage)
        {
            return *(uint*)(registers + RegisterBaseOffset + offset);
        }
    }

    private void WriteRegisterU64(int offset, ulong value)
    {
        var storage = RegisterStorage;
        fixed (byte* registers = storage)
        {
            *(ulong*)(registers + RegisterBaseOffset + offset) = value;
        }
    }

    private void WriteRegisterU32(int offset, uint value)
    {
        var storage = RegisterStorage;
        fixed (byte* registers = storage)
        {
            *(uint*)(registers + RegisterBaseOffset + offset) = value;
        }
    }
}
```

Keep the three existing SSE4a tests and their Linux/x64 guards unchanged.

- [ ] **Step 3: Add the failing EFLAGS regression**

Add this test before `RecoveryDeclinesWhenNoXmmStateWasBridged`:

```csharp
[Fact]
public void TzcntSigillRoundTripsEflagsThroughTheBridge()
{
    if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
    {
        return;
    }

    // tzcnt eax, eax
    var code = AllocateProbeVisibleCode([0xF3, 0x0F, 0xBC, 0xC0]);
    try
    {
        var frame = new FakeSignalFrame((ulong)code)
        {
            Rax = 1,
            EFlags = ReservedFlag | CarryFlag | DirectionFlag,
        };

        Assert.True(frame.Dispatch());

        Assert.Equal(0UL, frame.Rax);
        Assert.Equal((ulong)code + 4, frame.Rip);
        Assert.Equal(0u, frame.EFlags & CarryFlag);
        Assert.Equal(ZeroFlag, frame.EFlags & ZeroFlag);
        Assert.Equal(DirectionFlag, frame.EFlags & DirectionFlag);
    }
    finally
    {
        FreeProbeVisibleCode(code);
    }
}
```

- [ ] **Step 4: Run the regression and record RED**

Run:

```powershell
dotnet test tests/SharpEmu.Libs.Tests/SharpEmu.Libs.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~PosixSignalRecoveryTests.TzcntSigillRoundTripsEflagsThroughTheBridge" --verbosity minimal
```

Expected: one failed test. `frame.EFlags & CarryFlag` remains `1` instead of
the expected `0`, proving the current bridge does not write emulated flags
back to the signal frame.

- [ ] **Step 5: Add the minimal platform EFLAGS bridge**

In `DirectExecutionBackend.PosixSignals.cs`, add this value beside
`PosixRegisterOffsets`:

```csharp
private static readonly int PosixEflagsOffset = OperatingSystem.IsMacOS() ? 152 : 17 * 8;
```

Immediately after the loop that copies GPRs into `contextRecord`, capture
EFLAGS:

```csharp
WriteCtxU32(contextRecord, CTX_EFLAGS, *(uint*)(registers + PosixEflagsOffset));
```

Immediately after the successful-recovery loop that copies GPRs back to the
platform registers, write EFLAGS back:

```csharp
*(uint*)(registers + PosixEflagsOffset) = ReadCtxU32(contextRecord, CTX_EFLAGS);
```

- [ ] **Step 6: Run focused tests and record GREEN**

Run:

```powershell
dotnet test tests/SharpEmu.Libs.Tests/SharpEmu.Libs.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~PosixSignalRecoveryTests" --verbosity minimal
```

Expected: four passed tests and zero failed tests.

- [ ] **Step 7: Verify the complete solution**

Run:

```powershell
dotnet build SharpEmu.slnx -c Release --no-restore --verbosity minimal
dotnet test SharpEmu.slnx -c Release --no-build --no-restore --verbosity minimal
git diff --check
git status --short
```

Expected:

- Release build exits 0.
- All 653 tests pass: 589 Libs, 27 Metal, 4 ShaderCompiler, and 33 SourceGenerators.
- `git diff --check` exits 0.
- Status lists only the source bridge, renamed test, and this plan; the
  approved design is already committed.
- No new dependency or proprietary asset appears.

- [ ] **Step 8: Commit the implementation**

Run:

```powershell
git add src/SharpEmu.Core/Cpu/Native/DirectExecutionBackend.PosixSignals.cs tests/SharpEmu.Libs.Tests/Cpu/Sse4aPosixSignalRecoveryTests.cs tests/SharpEmu.Libs.Tests/Cpu/PosixSignalRecoveryTests.cs docs/superpowers/plans/2026-07-26-posix-eflags-signal-bridge.md
git diff --cached --check
git commit -m "fix(cpu): preserve EFLAGS in POSIX recovery"
```

Expected: one implementation commit containing the minimal bridge, regression,
test-fixture rename, and implementation plan.
