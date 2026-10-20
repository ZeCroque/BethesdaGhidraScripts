# Bethesda Ghidra Scripts

Automatically imports CommonLib type definitions, vtable layouts, function
signatures, and address-library symbols into Ghidra for Bethesda game binaries.

## Quick start

1. Clone the repo:

```bash
git clone https://github.com/ZeCroque/BethesdaGhidraScripts.git
cd BethesdaGhidraScripts
```

2. Run the interactive status/menu:

```bash
python run.py
```

This opens an interactive menu:

```
============================================================
  Bethesda Ghidra Scripts
============================================================

  Tools:
    Ghidra      : 12.1.4
    Clang       : clang version 23.1.3
    Steamless   : OK
    Python pkgs : OK

  Runtime databases:
    x.x.x.x:
      skyrim/se: SkyrimSE.exe
      Ghidra project : OK
      Import state   : current
    x.x.x.x:
      skyrim/ae: SkyrimSE.exe
      Ghidra project : OK
      Import state   : current

----------------------------------------
  1) Install prerequisites
  2) Update CommonLib submodules to latest
  3) Generate import scripts
  4) Add runtime executable and import
  5) Run headless Ghidra import (select runtime)
  6) Open a runtime Ghidra project
  7) Full rebuild (select runtime; blank for all)
  8) Clean a runtime Ghidra project
  9) Run headless Ghidra analysis on an imported executable
  q) Quit
----------------------------------------
```

The status panel at the top shows what's installed and detected. Menu options:

| Option | What it does |
|--------|-------------|
| **1** | Installs Python packages (`pdbparse`, `pyghidra`), downloads Ghidra, LLVM/Clang, and Steamless if missing. Safe to run multiple times -- skips anything already installed. |
| **2** | Runs `git submodule update --init --recursive --remote` to pull the latest CommonLib and AddressLibraryDatabase commits. Run this when upstream CommonLib has new types or fixes. |
| **3** | Parses CommonLib headers with clang and generates shared import scripts under `ghidrascripts/`. Generate them once before importing runtimes; rerun only when the generated scripts need updating. |
| **4** | Prompts for a runtime name, game, variant, and executable path; copies the executable and runs the headless import using the existing shared scripts. |
| **5** | Imports one selected runtime into its own Ghidra project. Steam DRM is stripped automatically via Steamless. |
| **6** | Opens the selected runtime's Ghidra project. |
| **7** | Regenerates scripts and imports one runtime, or all runtimes when left blank. |
| **8** | Deletes only the selected runtime's Ghidra project and import state. |
| **9** | Runs Ghidra's headless auto-analysis on an executable already imported into a runtime project, saving the analyzed program in that project. |

**First-time setup:** run **1**, then **2**, generate the import scripts with
**3**, and then add each runtime with **4** (or the `add` command). Each
addition is imported immediately without regenerating scripts. Use **6** to
open the selected runtime project. Use **9** or the `analyze` command to run
headless auto-analysis and save the result in that runtime's project.

### Non-interactive mode

For CI or scripting, pass a subcommand instead of using the menu:

```bash
python run.py setup
python run.py status
python run.py build                 # rebuild every runtime
python run.py build 1.6.1170.0      # rebuild one runtime
python run.py add 1.7.104.0 skyrim ae "D:\Games\SkyrimSE.exe"
python run.py all 1.6.1170.0       # setup, rebuild, and open one project
python run.py analyze 1.6.1170.0 skyrim ae  # headless analysis, saved to project
```

`analyze` runs Ghidra's `analyzeHeadless` against the selected program already
in the runtime's project. It does not import a new executable or apply the
CommonLib import script; run the headless import first. Auto-analysis is enabled
and can take a long time. Close any Ghidra window using that project before
starting it.

### How it works

Shared dependencies and generated import scripts are stored once. Each runtime
has its own executable directory, import state file, and Ghidra project at
`runtimes/<runtime>/ghidraprojects/BethesdaGhidraScripts/`.

The address library for each executable is selected automatically based on
the detected PE version. For Skyrim AE, all versions from 1.6.317 to 1.6.1179
are supported via the AddressLibraryDatabase.

### Requirements

- **Python 3.10+** (64-bit)
- **Git**

Clang, Ghidra, Steamless, and Python packages are all fetched automatically on
first run.

---

## Supported games

| Game         | Folder           | Address library  | CommonLib                 |
|--------------|------------------|------------------|---------------------------|
| Skyrim SE    | `runtimes/<runtime>/exes/skyrim/se` | `1-5-97-0` | `alandtse/CommonLibNG` |
| Skyrim AE    | `runtimes/<runtime>/exes/skyrim/ae` | auto-detected | `alandtse/CommonLibNG` |
| Fallout 4 AE | `runtimes/<runtime>/exes/f4/ae` | `1-11-191-0` | `libxse/commonlibf4` |

Address-library selection is detected from each executable. Runtime databases
are imported and tracked independently.

---

## What gets imported

Each binary receives:

- All enums, structs, and classes from CommonLib headers with exact field
  offsets and sizes (parsed via clang `-ast-dump` and `-fdump-record-layouts`)
- Primary and secondary vtable structs for multi-inheritance hierarchies
- Virtual function names from vtable address walks
- Function signatures built from CommonLib type descriptors
- Address-library symbols (function labels, RTTI, vtable pointers)
- Fallback symbols from PDB (`SkyrimSE.pdb`) and IDA scripts where available
- `Source:` plate comments on named functions showing which symbol table
  provided the name

### Accuracy

Every emitted struct field and signature parameter uses the **exact** type from
the source. Anything that can't be pinned to an exact type is left as `void *`
rather than guessed. In practice ~99.75% of struct fields are fully typed.

Skyrim AE's `PlayerCharacter` intentionally has fewer named components than SE:
CommonLibNG represents its runtime-dependent data block as opaque padding on
AE, while retaining the asserted AE size. The headless verification uses a
variant-specific component threshold for this type.

| | F4 AE | Skyrim AE | Skyrim SE |
| --- | --- | --- | --- |
| Struct fields | 24,216 | 34,243 | 34,231 |
| Fully typed | 99.76% | 99.75% | 99.75% |
| Vtable structs | 1,292 | 2,023 | 2,024 |

---

## Advanced usage

### Running pipeline scripts directly

The `run.py` menu is the recommended interface. If you need to run individual
pipeline steps (e.g. regenerating only one game, or importing a single target):

```bash
# Generate import scripts only (requires clang)
python scripts/commonlibsse/parse_commonlib_types.py   # Skyrim SE + AE
python scripts/commonlibf4/parse_commonlib_types.py    # Fallout 4 AE

# Run headless Ghidra import (requires generated scripts + Ghidra)
python scripts/run_headless.py                # all targets
python scripts/run_headless.py --runtime 1.6.1170.0
```

### Symbol priority

Symbols are applied in priority order. Higher-priority sources take precedence:

1. `RELOCATION_ID(SE, AE)` / `REL::ID` macros (CommonLib)
2. `Offsets_RTTI.h`, `Offsets_NiRTTI.h`, `Offsets_VTABLE.h` labels
3. `RE::Offset::` namespace IDs (Skyrim)
4. CommonLibSSE `src/*.cpp` cross-references (Skyrim only)
5. AE rename DB (`skyrimae.rename`) -- Skyrim AE only
6. PDB public symbols (`SkyrimSE.pdb`) -- Skyrim
7. IDA names (`IDAImportNames_1.11.191.0.py`) -- Fallout 4 AE

### Porting Address Library IDs between runtimes

CommonLib code such as `REL::ID(36540).address() + 0x62D` only works on the
runtime the ID was found for. When a new executable shifts too much, use
`scripts/idport.py` (needs `capstone` and `pefile`, installed by `python run.py setup`)
to translate it using the executables in `runtimes/` and the `.bin` files in
`addresslibrary/sse`:

```bash
# What is this ID (+/- offset) really? Prints the canonical REL::ID form + disassembly
python scripts/idport.py resolve 1.5.97.0 36541-0x63
# Same, from a raw RVA (image base is stripped if present)
python scripts/idport.py addr 1.5.97.0 0x5e869d
# Port it to another runtime
python scripts/idport.py port 1.5.97.0 36540+0x62D 1.7.104.0
```

`SPEC` is `ID`, `ID+OFFSET` or `ID-OFFSET`. The offset is applied to the address
the ID resolves to, then normalised to the containing function and *its* ID, so
oddities like `REL::ID(36541).address() - 0x63` come out as `REL::ID(36540) + 0x62D`.

`port` tries, in order: exact function signature (relative operands masked), loose
signature, prefix signature, **callee anchors** (small callees are ported by
signature, then the new function calling the most of them wins) and finally a weak
fuzzy mnemonic similarity (`--no-fuzzy` to skip; its index is cached in
`runtimes/<runtime>/.idport_index.pkl`). The hooked instruction is then mapped across
by aligning both instruction streams, and both disassemblies are printed.
**Always compare them by eye** - and re-check things a port cannot see: register
allocation, what the hooked instruction's neighbours consume (flags, `al`), and
struct offsets that changed between runtimes. Run `port` again on the hooked callee
(`port 1.5.97.0 38357 1.7.104.0`) to translate the IDs of called functions.

### Project layout

```
.
├── run.py                           Interactive launcher / menu
├── extern/                          CommonLib submodules (auto-updated)
├── addresslibrary/                  Address library .bin files
├── extras/                          Fallback symbol sources (PDB, IDA)
├── runtimes/                        Independent runtime databases
│   ├── 1.5.97.0/
│   │   ├── exes/                    Executable(s) for this runtime
│   │   ├── ghidraprojects/          Analyzed Ghidra project
│   │   └── .last_run_state          Import state for this runtime
│   └── 1.6.1170.0/
├── scripts/                         Pipeline source code
│   ├── run_headless.py              Headless Ghidra runner
│   ├── idport.py                    Address Library ID porting between runtimes
│   ├── core/                        Shared: clang parser, script emitter
│   ├── commonlibsse/                Skyrim SE/AE pipeline
│   └── commonlibf4/                 Fallout 4 AE pipeline
├── ghidrascripts/                   Generated import scripts (output)
└── tools/                           Ghidra, Steamless, LLVM (auto-downloaded)
```

---
