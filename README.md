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
  q) Quit
----------------------------------------
```

The status panel at the top shows what's installed and detected. Menu options:

| Option | What it does |
|--------|-------------|
| **1** | Installs Python packages (`pdbparse`, `pyghidra`), downloads Ghidra, LLVM/Clang, and Steamless if missing. Safe to run multiple times -- skips anything already installed. |
| **2** | Runs `git submodule update --init --recursive --remote` to pull the latest CommonLib and AddressLibraryDatabase commits. Run this when upstream CommonLib has new types or fixes. |
| **3** | Parses CommonLib headers with clang and generates shared import scripts under `ghidrascripts/`. |
| **4** | Prompts for a runtime name, game, variant, and executable path; copies the executable, generates the needed script, and runs the headless import. |
| **5** | Imports one selected runtime into its own Ghidra project. Steam DRM is stripped automatically via Steamless. |
| **6** | Opens the selected runtime's Ghidra project. |
| **7** | Regenerates scripts and imports one runtime, or all runtimes when left blank. |
| **8** | Deletes only the selected runtime's Ghidra project and import state. |

**First-time setup:** run **1**, then **2**, then add each runtime (option **4**
or the `add` command). Each addition is imported immediately. Use **6** to open
the selected runtime project.

### Non-interactive mode

For CI or scripting, pass a subcommand instead of using the menu:

```bash
python run.py setup
python run.py status
python run.py build                 # rebuild every runtime
python run.py build 1.6.1170.0      # rebuild one runtime
python run.py add 1.7.104.0 skyrim ae "D:\Games\SkyrimSE.exe"
python run.py all 1.6.1170.0       # setup, rebuild, and open one project
```

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
│   ├── core/                        Shared: clang parser, script emitter
│   ├── commonlibsse/                Skyrim SE/AE pipeline
│   └── commonlibf4/                 Fallout 4 AE pipeline
├── ghidrascripts/                   Generated import scripts (output)
└── tools/                           Ghidra, Steamless, LLVM (auto-downloaded)
```

---
