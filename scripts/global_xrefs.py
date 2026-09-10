#!/usr/bin/env python3
"""Xrefs globales completas: quién lee/escribe cada variable del VM ctx (.data 0x26b00-0x26d00)"""
from capstone import *
from capstone.x86 import X86_REG_RIP
import pefile, struct, os, sys

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
PATH = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")
data = open(PATH, 'rb').read()
pe = pefile.PE(PATH)

secs = []
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    secs.append((name, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData))

def rva2off(rva):
    for name, va, vs, raw, rs in secs:
        if va <= rva < va + max(vs, rs):
            return raw + (rva - va)
    return None

# Funciones desde .pdata
funcs = []
pdata_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress
pdata_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size
for i in range(pdata_size // 12):
    o = rva2off(pdata_rva + i*12)
    beg, end, unw = struct.unpack('<III', data[o:o+12])
    if beg and end > beg:
        funcs.append((beg, end))
funcs.sort()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Escaneo de accesos a rango .data 0x26b00-0x26d00
WATCH_LO, WATCH_HI = 0x26b00, 0x26d00
xrefs = {}
for beg, end in funcs:
    off = rva2off(beg)
    if off is None: continue
    code = data[off:off+(end-beg)]
    for insn in md.disasm(code, beg):
        if insn.mnemonic in ('mov','movd','movups','movdqa','movzx','cmp','add','or','xor','inc','lea','movaps'):
            for opnd in insn.operands:
                if opnd.type == CS_OP_MEM and opnd.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + opnd.mem.disp
                    if WATCH_LO <= target < WATCH_HI:
                        # ¿lectura o escritura? opnd.access (capstone 5: insn.operands[i].access)
                        acc = ''
                        try:
                            acc = 'W' if (opnd.access & CS_AC_WRITE) else 'R'
                        except Exception:
                            acc = '?'
                        xrefs.setdefault(target, []).append((insn.address, acc, f"{insn.mnemonic} {insn.op_str}"))

print(f"{'RVA':10s} {'offset .data':12s} {'#refs':5s} accesos (func, R/W)")
for t in sorted(xrefs):
    refs = xrefs[t]
    ws = sum(1 for _,a,_ in refs if a=='W')
    rs = sum(1 for _,a,_ in refs if a=='R')
    print(f"{hex(t):10s} +{hex(t-0x26000):8s} {len(refs):5d} (R:{rs} W:{ws})")
    for addr, acc, txt in refs[:6]:
        print(f"      {hex(addr):8s} {acc} {txt}")
    if len(refs) > 6: print(f"      ... y {len(refs)-6} más")
