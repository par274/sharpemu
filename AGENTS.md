# Repository workflow reminders

- When the user asks to create a draft PR after implementation work is complete, first inspect the current repository and CI state, then run the relevant local tests/builds using the current code before creating or updating the draft.
- For updater changes, include the full solution test command when Release artifacts are available:
  `dotnet test SharpEmu.slnx -c Release --no-build --verbosity normal`
- If CI uses architecture-specific environment settings, reproduce those settings locally where possible and report when the host cannot emulate the runner architecture exactly.
