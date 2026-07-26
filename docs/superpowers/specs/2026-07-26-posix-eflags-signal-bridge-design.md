<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# POSIX Signal EFLAGS Bridge Design

## Problem

`DirectExecutionBackend.TryHandlePosixFault` translates Linux and macOS signal
contexts into the Win64 `CONTEXT` layout used by SharpEmu's shared exception
recovery code. It currently copies general-purpose and, on Linux, XMM
registers, but leaves `CONTEXT.EFlags` zero.

The BMI/ABM illegal-instruction fallback reads and updates `CONTEXT.EFlags`.
After a successful recovery, the POSIX bridge also omits EFLAGS from its
write-back. Recovered instructions therefore calculate flags from an
incorrect initial value and resume with stale guest flags on Linux and macOS.

## Goal

Round-trip the low 32 bits of the trapped EFLAGS value through the existing
Win64 scratch context whenever POSIX fault recovery succeeds.

## Non-goals

- Refactoring the existing register bridge.
- Changing BMI/ABM emulation semantics.
- Installing or exercising process-wide signal handlers in tests.
- Bridging Darwin XMM state.
- Addressing unrelated CPU, audio, debugger, or analyzer findings.

## Platform ABI mapping

The offsets are relative to the pointer returned by
`GetPosixRegisterBase`:

- Linux x86-64: `gregs[REG_EFL]`, index 17, byte offset 136.
- Darwin x86-64: `__darwin_x86_thread_state64.__rflags`, byte offset 152.

Only the low 32 bits are copied because Win64 `CONTEXT.EFlags` is a 32-bit
field. A 32-bit write-back also preserves any upper storage bits in the
platform signal context.

## Design

Define a platform-selected EFLAGS offset next to the existing POSIX register
layout constants.

During signal capture:

1. Resolve the platform register base as today.
2. Copy the existing general-purpose registers.
3. Copy the platform EFLAGS value into `CONTEXT.EFlags`.
4. Run the unchanged recovery chain.

After successful recovery:

1. Copy general-purpose registers back as today.
2. Copy `CONTEXT.EFlags` back to the platform signal context.
3. Copy bridged XMM registers back as today.

No register state is written back when recovery declines.

## Regression test

Generalize the existing fabricated POSIX signal-frame fixture so it can expose
RAX and EFLAGS and can represent both supported x86-64 layouts. Existing Linux
SSE4a tests remain unchanged in behavior.

Add a regression that dispatches a synthetic `SIGILL` for:

```text
F3 0F BC C0    tzcnt eax, eax
```

Initial state:

- RAX = 1.
- EFLAGS includes the reserved bit, carry flag, and direction flag.

Expected recovered state:

- RAX = 0.
- RIP advances by four bytes.
- Carry is cleared.
- Zero is set.
- Direction is preserved.

The assertions prove both directions of the bridge: preserving Direction
requires capture of the initial flags, while changed Carry and Zero values
require write-back of the emulated result.

The test uses the Linux layout on Linux and Windows hosts and the Darwin layout
on macOS. Windows execution is a deterministic test of the Linux marshalling
path; production use remains POSIX-only.

## Verification

- Run the focused POSIX signal recovery tests before and after the production
  change to record the expected red/green transition.
- Run the complete Release test suite.
- Run a Release build and `git diff --check`.
- Confirm the final diff contains no unrelated changes or new dependencies.

## Risks

- An incorrect ABI offset would corrupt signal-frame state. The regression
  exercises both layout selections in CI, and the constants stay adjacent to
  the existing verified register maps.
- A real signal handler test could destabilize the test process. The design
  instead invokes the production bridge over a fabricated frame, matching the
  established SSE4a test seam.
