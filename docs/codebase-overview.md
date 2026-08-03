<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# SharpEmu Codebase Overview

> **Note**
>
> This document provides a high-level overview of the SharpEmu codebase. It is
> primarily intended for contributors, helping them navigate the repository and
> locate the appropriate project or directory when making changes.

---

# Repository Layout

```text
SharpEmu
├── assets/
├── docs/
├── LICENSES/
├── scripts/
├── src/
├── tests/
└── tools/
```

---

# assets/

The `assets` directory contains static resources used throughout the project.

Examples include:

* Application icons
* Logos
* Images used by the project


---

# docs/

The `docs` directory contains project documentation.

It includes documentation for various subsystems and developer-related topics.
New documentation should generally be added here.

---

# LICENSES/

The `LICENSES` directory contains the licenses used by the project.

it includes licenses such as:

* Apache 2.0
* GPL-2.0-or-later
* MIT

---

# src/

The `src` directory contains the primary source code of SharpEmu.

Each major component of the emulator is organized as a separate project to keep
the codebase modular and easier to maintain.

---

# SharpEmu.CLI

`src/SharpEmu.CLI` is the application's entry point.

Based on the current implementation, this project is responsible for:

* Starting the application.
* Launching the GUI when no command-line arguments are provided.
* Processing command-line arguments.
* Preparing the host environment before emulation.
* Creating the emulator runtime.
* Starting emulation by loading the provided `eboot.bin`.

Further details about the startup flow and runtime initialization will be
documented in future sections.
