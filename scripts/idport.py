#!/usr/bin/env python3
"""
Port Address Library IDs (as used by CommonLibSSE / CommonLibNG `REL::ID`)
between Skyrim runtimes by matching code in the executables.

Typical use: a mod hooks `REL::ID(36540).address() + 0x62D` on 1.5.97.0 and
needs the equivalent `REL::ID(...) + offset` on 1.7.104.0.

Usage:
  python scripts/idport.py resolve 1.5.97.0 36541-0x63
  python scripts/idport.py addr    1.5.97.0 0x5e869d
  python scripts/idport.py port    1.5.97.0 36540+0x62D 1.7.104.0
  python scripts/idport.py port    1.5.97.0 38357 1.7.104.0 --no-fuzzy

`SPEC` is `ID`, `ID+OFFSET` or `ID-OFFSET` (decimal or 0x hex). The offset is
relative to the address the ID resolves to, so it may be negative or point
past the end of the function the ID names; the tool normalises it to the
containing function and its own ID.

Runtimes are read from runtimes/<version>/exes/skyrim/*/ (an
`SkyrimSE.exe.unpacked.exe`, i.e. the Steamless output, is preferred over the
packed executable). ID tables come from addresslibrary/sse (then
extern/CommonLibSSE/tests/REL). Addresses are RVAs (image base excluded).

Matching strategy for `port` (first that yields candidates wins):
  1. exact: whole function bytes with relative branches / RIP-relative
     displacements masked out
  2. loose: same, with every displacement and immediate masked
  3. prefix: loose match of the first 32 instructions
  4. fuzzy: mnemonic 4-gram similarity against every function of the target
     executable (index cached in runtimes/<version>/.idport_index.pkl)
Candidates are ranked by instruction-sequence similarity, then the hook
instruction is mapped across by aligning both instruction sequences.
ALWAYS eyeball the printed disassembly of both sides before trusting a result.
"""
import argparse
import bisect
import difflib
import pickle
import re
import struct
import sys
import zlib
from array import array
from pathlib import Path

import capstone
import pefile

REPO_DIR = Path(__file__).resolve().parent.parent
RUNTIMES_DIR = REPO_DIR / "runtimes"
ADDRLIB_DIRS = [
    REPO_DIR / "addresslibrary" / "sse",
    REPO_DIR / "extern" / "CommonLibSSE" / "tests" / "REL",
]
INDEX_NAME = ".idport_index.pkl"
HEX_RE = re.compile(r"0x[0-9a-f]+")


# ---------------------------------------------------------------- address library
def find_library(version):
    tag = version.replace(".", "-")
    for directory in ADDRLIB_DIRS:
        for path in sorted(directory.glob("version*-%s.bin" % tag)):
            return path
    raise FileNotFoundError("no address library .bin for %s in %s" % (version, [str(d) for d in ADDRLIB_DIRS]))


def read_library(path):
    """Returns {id: rva} for format 1/2 (sparse, delta coded) and 5 (dense u32 table)."""
    d = path.read_bytes()
    fmt = struct.unpack_from("<i", d, 0)[0]
    if fmt == 5:
        n = (len(d) - 0x60) // 4
        offsets = struct.unpack_from("<%dI" % n, d, 0x60)
        return {i: o for i, o in enumerate(offsets) if o}

    p = 4 + 16
    name_len = struct.unpack_from("<i", d, p)[0]
    p += 4 + name_len
    ptr_size, count = struct.unpack_from("<ii", d, p)
    p += 8

    def read_delta(kind, prev, p):
        if kind == 0: return struct.unpack_from("<Q", d, p)[0], p + 8
        if kind == 1: return prev + 1, p
        if kind == 2: return prev + d[p], p + 1
        if kind == 3: return prev - d[p], p + 1
        if kind == 4: return prev + struct.unpack_from("<H", d, p)[0], p + 2
        if kind == 5: return prev - struct.unpack_from("<H", d, p)[0], p + 2
        if kind == 6: return struct.unpack_from("<H", d, p)[0], p + 2
        if kind == 7: return struct.unpack_from("<I", d, p)[0], p + 4
        raise ValueError("bad address library record type")

    out = {}
    prev_id = prev_off = 0
    for _ in range(count):
        t = d[p]
        p += 1
        lo, hi = t & 0xF, t >> 4
        i, p = read_delta(lo, prev_id, p)
        base = prev_off // ptr_size if hi & 8 else prev_off
        o, p = read_delta(hi & 7, base, p)
        if hi & 8:
            o *= ptr_size
        out[i] = o
        prev_id, prev_off = i, o
    return out


# ---------------------------------------------------------------- runtime image
class Runtime:
    def __init__(self, version):
        self.version = version
        self.exe = self._find_exe(version)
        self.data = self.exe.read_bytes()
        self.pe = pefile.PE(data=self.data, fast_load=True)
        self.text = next(s for s in self.pe.sections if s.Name.rstrip(b"\0") == b".text")
        self.ids = read_library(find_library(version))
        self._inv = None
        self._funcs = None
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    @staticmethod
    def _find_exe(version):
        root = RUNTIMES_DIR / version / "exes" / "skyrim"
        found = sorted(root.glob("*/SkyrimSE.exe.unpacked.exe")) + sorted(root.glob("*/SkyrimSE.exe"))
        if not found:
            raise FileNotFoundError("no SkyrimSE.exe under %s" % root)
        return found[0]

    def rva2off(self, rva):
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return rva - s.VirtualAddress + s.PointerToRawData
        raise ValueError("RVA %#x outside the image" % rva)

    def read(self, rva, n):
        o = self.rva2off(rva)
        return self.data[o:o + n]

    @property
    def inv(self):
        if self._inv is None:
            self._inv = {}
            for i, o in self.ids.items():
                self._inv.setdefault(o, []).append(i)
        return self._inv

    @property
    def functions(self):
        """Sorted [(begin, end)] from .pdata (contiguous chained fragments merged) plus ID-table leaves."""
        if self._funcs is None:
            sec = next(s for s in self.pe.sections if s.Name.rstrip(b"\0") == b".pdata")
            raw = self.data[sec.PointerToRawData:sec.PointerToRawData + sec.Misc_VirtualSize]
            lo = self.text.VirtualAddress
            hi = lo + self.text.Misc_VirtualSize
            entries = []
            for i in range(0, len(raw) - 11, 12):
                b, e, u = struct.unpack_from("<III", raw, i)
                if lo <= b < hi and e > b:
                    try:
                        chained = bool(self.read(u & ~1, 1)[0] >> 3 & 4)
                    except ValueError:
                        chained = False
                    entries.append((b, e, chained))
            funcs = []
            for b, e, chained in sorted(entries):
                # MSVC splits some prologues in two entries, the second one chained to the first
                if chained and funcs and funcs[-1][1] == b:
                    funcs[-1] = (funcs[-1][0], e)
                elif not chained:
                    funcs.append((b, e))
            pstarts = [f[0] for f in funcs]

            # Leaf functions have no unwind info: take their starts from the ID table instead
            leaves = []
            for o in sorted(set(self.ids.values())):
                if lo <= o < hi:
                    k = bisect.bisect_right(pstarts, o) - 1
                    if not (k >= 0 and funcs[k][0] <= o < funcs[k][1]) and (not leaves or leaves[-1] != o):
                        leaves.append(o)
            starts = sorted(set(pstarts) | set(leaves))
            base = self.text.PointerToRawData - lo
            for o in leaves:
                k = bisect.bisect_right(starts, o)
                end = starts[k] if k < len(starts) else hi
                while end > o and self.data[base + end - 1] == 0xCC:
                    end -= 1
                if end > o:
                    funcs.append((o, end))
            self._funcs = sorted(funcs)
            self._starts = [f[0] for f in self._funcs]
        return self._funcs

    def function_at(self, rva):
        funcs = self.functions
        k = bisect.bisect_right(self._starts, rva) - 1
        if k >= 0 and funcs[k][0] <= rva < funcs[k][1]:
            return funcs[k]
        return None

    def decode(self, begin, end):
        """[(rva, size, mnemonic, op_str)] for a function."""
        return list(self.md.disasm_lite(self.read(begin, end - begin), begin))

    def ids_of(self, rva):
        return self.inv.get(rva, [])


def spec_ids(ids):
    return "/".join(str(i) for i in ids) if ids else "none"


# ---------------------------------------------------------------- signatures
def norm_key(ins):
    return ins[2] + " " + HEX_RE.sub("#", ins[3])


def masked_regex(rt, begin, end, strict, max_insns=None):
    """Regex matching the function's bytes with version-dependent operands wildcarded."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    parts = []
    for n, ins in enumerate(md.disasm(rt.read(begin, end - begin), begin)):
        if max_insns and n >= max_insns:
            break
        raw = bytearray(ins.bytes)
        mask = bytearray(len(raw))
        rip = "rip" in ins.op_str
        branch = ins.mnemonic[0] == "j" or ins.mnemonic == "call"
        if ins.disp_size and (not strict or rip):
            mask[ins.disp_offset:ins.disp_offset + ins.disp_size] = b"\1" * ins.disp_size
        if ins.imm_size and (not strict or branch):
            mask[ins.imm_offset:ins.imm_offset + ins.imm_size] = b"\1" * ins.imm_size
        for b, m in zip(raw, mask):
            parts.append(b"." if m else re.escape(bytes([b])))
    return re.compile(b"".join(parts), re.DOTALL)


def regex_candidates(rt, rx, limit=40):
    starts = {b for b, _ in rt.functions}
    lo = rt.text.PointerToRawData
    hi = lo + rt.text.SizeOfRawData
    out = []
    for m in rx.finditer(rt.data, lo, hi):
        rva = m.start() - lo + rt.text.VirtualAddress
        if rva in starts:
            out.append(rva)
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------- callee anchors
def callee_anchors(old, new, old_insns, max_size=0x600):
    """
    Ports each (small enough) callee of the old function by unique signature, then
    finds the functions of the new runtime that call the most of those ports.
    Returns ({old callee rva: new callee rva}, [(anchors matched, function begin)]).
    """
    anchors = {}
    for t in sorted({call_target(i) for i in old_insns if i[2] == "call"} - {None}):
        fn = old.function_at(t)
        if not fn or fn[0] != t or fn[1] - fn[0] > max_size:
            continue
        for strict in (True, False):
            found = regex_candidates(new, masked_regex(old, fn[0], fn[1], strict), 2)
            if found:
                if len(found) == 1:
                    anchors[t] = found[0]
                break
    if not anchors:
        return anchors, []

    reverse = {}
    for o, n in anchors.items():
        reverse.setdefault(n, set()).add(o)
    lo = new.text.PointerToRawData
    blob = new.data[lo:lo + new.text.SizeOfRawData]
    tva = new.text.VirtualAddress
    hits = {}
    for m in re.finditer(b"\xe8", blob):
        i = m.start()
        if i + 5 > len(blob):
            break
        target = tva + i + 5 + struct.unpack_from("<i", blob, i + 1)[0]
        if target in reverse:
            fn = new.function_at(tva + i)
            if fn:
                hits.setdefault(fn[0], set()).update(reverse[target])
    ranked = sorted(((len(v), b) for b, v in hits.items()), reverse=True)
    need = 1 if len(anchors) == 1 else 2
    return anchors, [(c, b) for c, b in ranked if c >= need][:8]


# ---------------------------------------------------------------- fuzzy index
def shingles(mnemonics, table):
    ms = [table.setdefault(m, len(table)) for m in mnemonics]
    return {(ms[i] << 30) | (ms[i + 1] << 20) | (ms[i + 2] << 10) | ms[i + 3] for i in range(len(ms) - 3)}


def load_index(rt):
    cache = RUNTIMES_DIR / rt.version / INDEX_NAME
    stamp = (rt.exe.name, rt.exe.stat().st_size, rt.exe.stat().st_mtime_ns)
    if cache.exists():
        try:
            with cache.open("rb") as f:
                saved = pickle.load(f)
            if saved["stamp"] == stamp:
                return saved
        except Exception:
            pass
    print("  building fuzzy index for %s (one-off, cached)..." % rt.version, file=sys.stderr)
    table = {}
    entries = []
    for b, e in rt.functions:
        mn = [i[2] for i in rt.md.disasm_lite(rt.read(b, e - b), b)]
        if len(mn) >= 5:
            entries.append((b, e, len(mn), array("Q", sorted(shingles(mn, table)))))
    saved = {"stamp": stamp, "table": table, "entries": entries}
    with cache.open("wb") as f:
        pickle.dump(saved, f, protocol=pickle.HIGHEST_PROTOCOL)
    return saved


def fuzzy_candidates(old_insns, new_rt, top=8):
    idx = load_index(new_rt)
    s = shingles([i[2] for i in old_insns], idx["table"])
    if not s:
        return []
    scored = []
    for b, e, n, arr in idx["entries"]:
        if not 0.5 <= n / len(old_insns) <= 2.0:
            continue
        inter = len(s.intersection(arr))
        if inter:
            scored.append((inter / (len(s) + len(arr) - inter), b))
    scored.sort(reverse=True)
    return [b for _, b in scored[:top]]


# ---------------------------------------------------------------- comparison
def similarity(a_insns, b_insns):
    return difflib.SequenceMatcher(None, [norm_key(i) for i in a_insns], [norm_key(i) for i in b_insns], autojunk=False).ratio()


def align(old_insns, new_insns, old_idx, anchors=None):
    """Maps an instruction index of the old function onto the new one. Returns (index, how) or (None, None)."""
    target = call_target(old_insns[old_idx]) if old_insns[old_idx][2] == "call" else None
    if anchors and target in anchors:
        same = [n for n, i in enumerate(new_insns) if i[2] == "call" and call_target(i) == anchors[target]]
        if len(same) == 1:
            return same[0], "unique call to the ported callee"
    for how, key in (("exact", norm_key), ("mnemonic only", lambda i: i[2])):
        sm = difflib.SequenceMatcher(None, [key(i) for i in old_insns], [key(i) for i in new_insns], autojunk=False)
        for a, b, n in sm.get_matching_blocks():
            if a <= old_idx < a + n:
                return b + old_idx - a, how
    return None, None


def call_target(ins):
    if ins[2] in ("call", "jmp") and ins[3].startswith("0x"):
        return int(ins[3], 16)
    return None


def show(rt, insns, idx, ctx, label):
    print("  %s" % label)
    for n in range(max(0, idx - ctx), min(len(insns), idx + ctx + 1)):
        a, size, m, o = insns[n]
        mark = ">>" if n == idx else "  "
        print("   %s %08x  %-22s %s %s" % (mark, a, rt.read(a, size).hex(" "), m, o))


# ---------------------------------------------------------------- commands
def parse_spec(spec):
    m = re.fullmatch(r"\s*(\d+)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*", spec)
    if not m:
        sys.exit("bad SPEC %r (expected ID, ID+OFFSET or ID-OFFSET)" % spec)
    off = int(m.group(3), 0) if m.group(3) else 0
    return int(m.group(1)), -off if m.group(2) == "-" else off


def describe(rt, rva):
    """Prints the canonical REL::ID form of an RVA and returns (function, insns, index)."""
    f = rt.function_at(rva)
    if not f:
        sys.exit("%#x is not inside a known function of %s" % (rva, rt.version))
    insns = rt.decode(*f)
    idx = next((n for n, i in enumerate(insns) if i[0] == rva), None)
    ids = rt.ids_of(f[0])
    print("  rva %#x  function %#x-%#x  IDs: %s  offset in function: %#x%s" % (
        rva, f[0], f[1], spec_ids(ids), rva - f[0], "" if idx is not None else "  (NOT an instruction boundary)"))
    for i in ids:
        print("    => REL::ID(%d).address() + %#x" % (i, rva - f[0]))
    return f, insns, idx


def cmd_resolve(args):
    rt = Runtime(args.version)
    ident, off = parse_spec(args.spec)
    if ident not in rt.ids:
        sys.exit("ID %d not in the %s address library" % (ident, rt.version))
    rva = rt.ids[ident] + off
    print("%s: ID %d = rva %#x, %+#x => rva %#x" % (rt.version, ident, rt.ids[ident], off, rva))
    f, insns, idx = describe(rt, rva)
    if idx is not None:
        show(rt, insns, idx, args.context, "context")


def cmd_addr(args):
    rt = Runtime(args.version)
    rva = int(args.rva, 0)
    if rva >= rt.pe.OPTIONAL_HEADER.ImageBase:
        rva -= rt.pe.OPTIONAL_HEADER.ImageBase
    print("%s:" % rt.version)
    f, insns, idx = describe(rt, rva)
    if idx is not None:
        show(rt, insns, idx, args.context, "context")


def cmd_port(args):
    old = Runtime(args.old)
    new = Runtime(args.new)
    ident, off = parse_spec(args.spec)
    if ident not in old.ids:
        sys.exit("ID %d not in the %s address library" % (ident, old.version))
    rva = old.ids[ident] + off
    print("SOURCE %s: ID %d %+#x" % (old.version, ident, off))
    f, old_insns, old_idx = describe(old, rva)
    if old_idx is None:
        sys.exit("source address is not on an instruction boundary")

    anchors = {}
    scored, method = [], None
    for name, strict, limit in (("exact signature", True, None), ("loose signature", False, None),
                                ("loose signature of the first 32 instructions", False, 32)):
        found = regex_candidates(new, masked_regex(old, f[0], f[1], strict, limit))
        if found:
            scored, method = [(0, b) for b in found], name
            break
    if not scored:
        anchors, found = callee_anchors(old, new, old_insns)
        if found:
            scored = found
            method = "callee anchors (%d callees ported by signature; score = how many each candidate calls)" % len(anchors)
    if not scored and not args.no_fuzzy:
        scored, method = [(0, b) for b in fuzzy_candidates(old_insns, new)], "fuzzy mnemonic similarity (weak)"
    if not scored:
        sys.exit("no candidate found in %s" % new.version)

    ranked = []
    for score, b in scored:
        fn = new.function_at(b)
        ins = new.decode(*fn)
        ranked.append((score, similarity(old_insns, ins), fn, ins))
    ranked.sort(key=lambda r: (-r[0], -r[1]))
    print("\nMETHOD: %s, %d candidate(s)" % (method, len(scored)))
    for score, sim, fn, _ in ranked[:5]:
        print("  candidate function %#x  IDs: %s  anchors %d  similarity %.2f" % (fn[0], spec_ids(new.ids_of(fn[0])), score, sim))
    score, sim, fn, new_insns = ranked[0]
    unambiguous = len(ranked) == 1 or (score, sim) > (ranked[1][0], ranked[1][1] + 0.1) or score > ranked[1][0]

    hooked = call_target(old_insns[old_idx]) if old_insns[old_idx][2] == "call" else None
    if hooked is not None and hooked not in anchors:
        hf = old.function_at(hooked)
        if hf and hf[0] == hooked:
            found = regex_candidates(new, masked_regex(old, hf[0], hf[1], True), 2) or regex_candidates(new, masked_regex(old, hf[0], hf[1], False), 2)
            if len(found) == 1:
                anchors[hooked] = found[0]

    new_idx, how = align(old_insns, new_insns, old_idx, anchors)
    print("\nTARGET %s:" % new.version)
    if new_idx is None:
        print("  best function %#x IDs: %s, but the hook instruction could not be aligned" % (fn[0], spec_ids(new.ids_of(fn[0]))))
        return 1
    new_rva = new_insns[new_idx][0]
    ids = new.ids_of(fn[0])
    print("  rva %#x  function %#x  similarity %.2f  alignment: %s  %s" % (
        new_rva, fn[0], sim, how, "" if unambiguous else "AMBIGUOUS - check the other candidates"))
    for i in ids:
        print("    => REL::ID(%d).address() + %#x" % (i, new_rva - fn[0]))
    if not ids:
        print("    (function start has no ID in the address library; use the closest preceding ID + offset)")
    if ident in new.ids and new.function_at(new.ids[ident]) and new.function_at(new.ids[ident])[0] == fn[0]:
        print("  note: the same ID %d still names this function" % ident)

    old_t, new_t = call_target(old_insns[old_idx]), call_target(new_insns[new_idx])
    if old_t is not None and new_t is not None:
        print("  hooked call target: old ID %s (rva %#x) -> new ID %s (rva %#x)" % (
            spec_ids(old.ids_of(old_t)), old_t, spec_ids(new.ids_of(new_t)), new_t))

    print()
    show(old, old_insns, old_idx, args.context, "old (%s)" % old.version)
    show(new, new_insns, new_idx, args.context, "new (%s)" % new.version)
    return 0


def main():
    ap = argparse.ArgumentParser(description="Port Skyrim Address Library IDs between runtimes", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("resolve", help="ID[+/-offset] -> rva, canonical ID form, disassembly")
    p.add_argument("version")
    p.add_argument("spec")
    p.add_argument("--context", type=int, default=4)
    p.set_defaults(fn=cmd_resolve)

    p = sub.add_parser("addr", help="rva -> canonical REL::ID form")
    p.add_argument("version")
    p.add_argument("rva")
    p.add_argument("--context", type=int, default=4)
    p.set_defaults(fn=cmd_addr)

    p = sub.add_parser("port", help="port ID[+/-offset] from one runtime to another")
    p.add_argument("old")
    p.add_argument("spec")
    p.add_argument("new")
    p.add_argument("--context", type=int, default=5)
    p.add_argument("--no-fuzzy", action="store_true", help="skip the (slow on first run) similarity fallback")
    p.set_defaults(fn=cmd_port)

    args = ap.parse_args()
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
