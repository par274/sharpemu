---
name: sharpemu-clean-room-research
description: Research unknown PS5 ABI or API behavior, AGC or RDNA packets and instructions, public kernel or FreeBSD behavior, ELF relocations, calling conventions, and licensed public emulator comparisons. Do not use for routine source navigation or to obtain restricted material.
---

<!-- Copyright (C) 2026 SharpEmu Emulator Project -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# SharpEmu clean-room research

## Inputs

Require one precise, falsifiable research question and the guest-visible behavior it affects.

## Workflow

1. Search the checked-out SharpEmu source and tests first.
2. Search official public specifications and source next, then AMD, Khronos, FreeBSD, System V ABI, and language/runtime references.
3. Use reproducible clean-room observations after specifications. Consult maintained open-source emulator implementations only after license review; use community wikis only as leads.
4. Exclude keys, leaked SDKs, proprietary modules, exploit repositories, unauthorized dumps, and access-control bypasses. Stop if the question requires them.
5. Corroborate material claims. Distinguish `specification`, `public implementation`, `community inference`, and `original observation`.
6. Append one JSON object per source to `.local/research/research.jsonl` with `question`, `url`, `title`, `accessDate`, `claim`, `sourceClass`, `confidence`, and `license` fields. Do not track the ledger.
7. Convert evidence into the smallest generic implementation hypothesis; do not copy source or create a source dump.

## Output

Return the question, concise findings, corroborating sources, licenses, confidence, unresolved contradictions, guest-visible hypothesis, and proposed narrow test. Cite public URLs and clearly label inference.
