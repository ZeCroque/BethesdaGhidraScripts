# Instructions for AI assistants

This repo imports CommonLib types/symbols into per-runtime Ghidra projects for Bethesda games
(see `README.md`), and is also used as a workbench to reverse engineer Skyrim executables for
mods built on CommonLibSSE/CommonLibNG.

## Layout you need to know

- `runtimes/<version>/exes/skyrim/<se|ae>/SkyrimSE.exe` - one executable per runtime (1.5.97.0 = SE,
  1.6.x / 1.7.x = AE). `SkyrimSE.exe.unpacked.exe` (Steamless output) is the one to analyse when present.
- `runtimes/<version>/ghidraprojects/` - Ghidra projects (huge binary DBs, don't touch by hand).
- `addresslibrary/sse/*.bin` - Address Library ID -> RVA tables. Formats 1/2 are sparse delta-coded,
  format 5 (1.7.x) is a dense `uint32` table starting at byte `0x60` indexed by ID.
  Fallback sources: `extern/CommonLibSSE/tests/REL/`, `extern/AddressLibraryDatabase/skyrimae.relib`.
- `input/` - **the user's mod project(s) under work; its content changes between sessions.** Never assume
  what is in there: look. It is where `REL::ID(...)` calls to port live (e.g. grep for `REL::ID`,
  `RELOCATION_ID`, `REL::Relocate`, `Offset2ID`).
- `scripts/idport.py` - ID porting tool (below). `extras/`, `tools/`, `ghidrascripts/` are inputs/outputs
  of the import pipeline; `tools/` and `runtimes/*/exes|ghidraprojects` are git-ignored.

All addresses below are **RVAs** (image base `0x140000000` excluded), as in the Address Library.

## Workflow: port `REL::ID` hooks to another runtime

Goal example: a hook is `REL::ID(36541).address() - 0x63` (1.5.97.0) and the matching ID for 1.7.104.0
is needed.

1. Find the ID usages in `input/` and note the runtime they were found on (comments, `RELOCATION_ID(se, ae)`
   arguments: first is SE 1.5.97, second is AE; AE IDs are mostly shared between 1.6.x and 1.7.x but
   not guaranteed - verify).
2. Normalise the source: `python scripts/idport.py resolve <old> <ID[+/-off]>`. This yields the containing
   function and its own ID + offset (a negative/odd offset usually means the ID named the *next* function).
3. Port: `python scripts/idport.py port <old> <ID[+/-off]> <new>`. Do it for each hooked address **and**
   for each called/hijacked function ID (`port <old> <calleeID> <new>`, offset 0).
4. Verify by reading both printed disassemblies. Do not trust a single method blindly; look at
   candidate scores/ambiguity warnings. If it fails, use `addr` / `resolve` on the new runtime, or
   open the Ghidra project, and reason manually (callers via `call rel32` scans, strings, unique constants).
5. Check what the hook *needs*, beyond the address. Typical traps found so far:
   - the patched instruction length (a `call rel32` is 5 bytes: resume at `hook + 5`, not an arbitrary number);
   - registers that are live at the hook site on that runtime (callee-saved ones like `r14` can hold `this`);
     prefer volatile registers (`rax`, `r11`) in trampolines and keep the stack 16-byte aligned with 0x20 shadow space;
   - results consumed right after the hooked call (`test al, al`) must survive the hook;
   - struct member offsets differing per runtime (e.g. `[rbx + 0xf0]` vs `[r14 + 0xf8]`).
6. Update the code with `RELOCATION_ID(se, ae)` / `#ifndef ENABLE_SKYRIM_AE` as the project already does.
   Cross-check against the ID table: `python scripts/idport.py resolve <new> <newID+off>` must show the
   instruction you expect.

Notes on `idport.py` internals worth knowing when debugging it:
- Functions come from `.pdata`; MSVC sometimes splits a prologue into two entries (the second is
  `UNW_FLAG_CHAININFO`) - they must be merged. Leaf functions have no `.pdata` entry, so their starts are
  taken from the ID table.
- Strategies: exact masked signature -> loose -> prefix -> callee anchors -> fuzzy. Fuzzy is weak when
  the compiler output changed; callee anchors are the robust one for big functions.
- The fuzzy index is cached per runtime in `.idport_index.pkl` (git-ignored); delete it if you change the tool.

## Environment notes

- Windows + PowerShell; Python 3.10+ with `capstone`, `pefile` (installed by `python run.py setup`).
- Do not commit executables, Ghidra projects, caches or anything under `tools/`.
- Keep scratch scripts out of the repo (use the session folder) unless they are generally reusable, in which
  case put them under `scripts/` and document them in `README.md`.
