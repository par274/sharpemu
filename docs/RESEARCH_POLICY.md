<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Research policy

SharpEmu’s contribution rules remain authoritative. This document defines how the fork turns external knowledge and local observations into evidence.

## Clean-room boundary

Do not use or add leaked SDK material, firmware, keys, proprietary Sony code, decrypted assets, or copyrighted game content. Do not request, reproduce, summarize, or derive implementation details from material that cannot lawfully be used.

Local testing uses a lawfully obtained title. Keep game paths, binaries, raw shaders, captures, dumps, and other game-derived artifacts outside Git. Public CI uses only authored or clearly redistributable fixtures. Commit sanitized metadata, hashes, measurements, and original regression tests only when they do not reproduce protected content.

## Evidence order

Treat model output as a hypothesis, never as evidence. Prefer sources in this order:

1. Reproducible observation from a lawful local test.
2. An official architecture, ABI, or API specification.
3. A focused synthetic experiment.
4. A compatible, licensed open-source implementation.
5. A community source whose relevant claim can be independently checked.

Record the source and uncertainty for non-obvious PS5 behavior. A source can suggest an experiment without proving its result. Do not treat a matching screen, suppressed error, success-returning stub, guessed NID, or single benchmark run as confirmation.

## External code

Check the exact revision, license, provenance, and semantic fit before using another implementation. Reimplementing an idea does not make proprietary or unlicensed source acceptable. Preserve required notices for licensed code and explain any semantic adaptation in the change.

Use KytyPS5 and other emulators as comparative references, not interchangeable architectures. Do not merge implementations or introduce a new dependency until a measured blocker shows why the fork needs it.

## Research records

`docs/SOURCES.md` is the curated source index. Add only sources that can change an implementation decision. Durable findings may be recorded under `docs/research/` when they are verified, reusable, and clearer outside a regression test. Do not store investigation diaries, copied manuals, or unverified model summaries.
