#!/usr/bin/env python3
"""Desensamblador anotado: funciones desde .pdata, IAT resuelta, strings por referencia RIP"""
import pefile, struct, re, os, sys
from capstone import *
from capstone.x86 import X86_REG_RIP

OUT_DIR = os.environ.get("BLK_OUT") or "artifacts"
os.makedirs(OUT_DIR, exist_ok=True)

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
PATH = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")
pe = pefile.PE(PATH)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

BASE = pe.OPTIONAL_HEADER.ImageBase

# --- Mapa RVA->offset y datos de secciones
secs = []
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    secs.append((name, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Characteristics))

def rva2off(rva):
    for name, va, vs, raw, rs, ch in secs:
        if va <= rva < va + max(vs, rs):
            return raw + (rva - va)
    return None

def off2rva(off):
    for name, va, vs, raw, rs, ch in secs:
        if raw <= off < raw + rs:
            return va + (off - raw)
    return None

def read(rva, n):
    o = rva2off(rva)
    if o is None: return None
    return pe.__data__[o:o+n]

# --- IAT: RVA -> nombre de API
iat = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        for imp in entry.imports:
            if imp.address:  # IAT thunk RVA (pefile lo da como VA)
                rva = imp.address - BASE if imp.address > BASE else imp.address
                n = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
                iat[rva] = f"{dll}!{n}"

# --- Strings detectables en .rdata/.data (para anotar lea)
data_blob = pe.__data__
str_map = {}
ascii_re = re.compile(rb'[\x20-\x7e]{4,}')
for m in ascii_re.finditer(data_blob):
    rva = off2rva(m.start())
    if rva is not None:
        str_map[rva] = m.group().decode()

# --- Funciones desde .pdata (RUNTIME_FUNCTION)
funcs = []
pdata_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress
pdata_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size
n_entries = pdata_size // 12
for i in range(n_entries):
    o = rva2off(pdata_rva + i*12)
    beg, end, unw = struct.unpack('<III', data_blob[o:o+12])
    if beg and end and end > beg:
        funcs.append((beg, end))
funcs.sort()
print(f"[+] {len(funcs)} funciones detectadas vía .pdata")

# --- Desensamblar todo con anotaciones
out = open(os.path.join(OUT_DIR, 'disasm_annotated.txt'), 'w')

def annotate(insn):
    notes = []
    op = insn.op_str
    # call/jmp [rip+X] -> IAT
    if 'rip' in op and ('call' in insn.mnemonic or 'jmp' in insn.mnemonic):
        try:
            for opnd in insn.operands:
                if opnd.type == CS_OP_MEM and opnd.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + opnd.mem.disp
                    if target in iat:
                        notes.append(f"<< {iat[target]} >>")
        except Exception:
            pass
    # lea reg, [rip+X] -> string o sección
    if insn.mnemonic == 'lea' and 'rip' in op:
        try:
            for opnd in insn.operands:
                if opnd.type == CS_OP_MEM and opnd.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + opnd.mem.disp
                    if target in iat:
                        notes.append(f"<< IAT: {iat[target]} >>")
                    elif target in str_map:
                        s = str_map[target]
                        if len(s) >= 4 and not s.startswith('api-ms') and not s.startswith('ext-ms'):
                            notes.append(f'<< "{s[:60]}" >>')
                    else:
                        # apunta a datos: etiquetar sección
                        for name, va, vs, raw, rs, ch in secs:
                            if va <= target < va + max(vs, rs):
                                notes.append(f"<< .{name}+{target-va:#x} >>")
                                break
        except Exception:
            pass
    return f" ; {' '.join(notes)}" if notes else ""

total_calls = {}
for beg, end in funcs:
    off = rva2off(beg)
    if off is None: continue
    code = data_blob[off:off+(end-beg)]
    out.write(f"\n{'='*70}\n FUNC @ RVA {hex(beg)} - {hex(end)}  (size {end-beg})\n{'='*70}\n")
    for insn in md.disasm(code, beg):
        ann = annotate(insn)
        if '<<' in ann and ('!' in ann):
            api = ann.split('<< ')[1].split(' >>')[0]
            total_calls.setdefault(api, 0)
            total_calls[api] += 1
        out.write(f"  {insn.address:#010x}: {insn.mnemonic:<10s} {insn.op_str:<45s}{ann}\n")
out.close()
print(f"[+] Desensamblado guardado en {OUT_DIR}/disasm_annotated.txt")

# --- Resumen de llamadas a APIs interesantes
print("\n[+] APIs más llamadas (por función):")
for api, cnt in sorted(total_calls.items(), key=lambda x: -x[1])[:40]:
    print(f"    {cnt:4d}x {api}")
