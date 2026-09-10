#!/usr/bin/env python3
"""Resuelve todos los accesos [rip+X] a RVAs absolutos y nombra globals"""
from capstone import *
import pefile, struct, os, sys

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
PATH = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")
data = open(PATH, 'rb').read()
pe = pefile.PE(PATH)
BASE = pe.OPTIONAL_HEADER.ImageBase

secs = []
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    secs.append((name, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData))

def rva2off(rva):
    for name, va, vs, raw, rs in secs:
        if va <= rva < va + max(vs, rs):
            return raw + (rva - va)
    return None

def secname(rva):
    for name, va, vs, raw, rs in secs:
        if va <= rva < va + max(vs, rs):
            return name
    return "?"

# IAT map
iat = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.address:
            rva = imp.address - BASE
            iat[rva] = f"{dll}!{imp.name.decode()}"

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
from capstone.x86 import X86_REG_RIP

def analyze(start, length):
    off = rva2off(start)
    code = data[off:off+length]
    print(f"\n### Función {hex(start)} (+{length} bytes) — globals y APIs:")
    prev = None
    for insn in md.disasm(code, start):
        line = f"  {insn.address:#010x}: {insn.mnemonic} {insn.op_str}"
        for opnd in insn.operands:
            if opnd.type == CS_OP_MEM and opnd.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + opnd.mem.disp
                if target in iat:
                    line += f"   ; [{iat[target]}]"
                else:
                    line += f"   ; [.{secname(target)}+{hex(target - dict((n, v) for n, v, _, _, _ in secs)[secname(target)])}] RVA={hex(target)}"
        print(line)

# funciones clave del núcleo BLK
analyze(0x1610, 0x40)     # hash
analyze(0x3b26, 0x3e0)    # VM dispatcher/inicio
