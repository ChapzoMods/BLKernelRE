#!/usr/bin/env python3
"""Extrae la tabla de handlers del VM (RVA 0x6bd8, 158 dwords) y agrupa opcodes"""
import struct
import pefile
import os, sys
from collections import defaultdict

OUT_DIR = os.environ.get("BLK_OUT") or "artifacts"
os.makedirs(OUT_DIR, exist_ok=True)

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
SAMPLE = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")

data = open(SAMPLE, 'rb').read()
pe = pefile.PE(SAMPLE)
secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
def rva2off(rva):
    for va, vs, raw, rs in secs:
        if va <= rva < va + max(vs, rs):
            return raw + (rva - va)
    return None

handlers = struct.unpack('<158I', data[rva2off(0x6bd8):rva2off(0x6bd8)+158*4])
print(f"{'opcode':8s} {'handler RVA':12s}")
groups = defaultdict(list)
for op, h in enumerate(handlers):
    groups[h].append(op)

print(f"\n{len(groups)} handlers únicos para 158 opcodes\n")
# tamaños por clase
classes = data[rva2off(0x1b7f0):rva2off(0x1b7f0)+0x9e]
CLASS_SIZE = {0: 1, 1: 2, 2: 3, 3: 6, 4: 0xa, 5: 6, 6: 7, 7: 5, 8: 5}

for h in sorted(groups):
    ops = groups[h]
    ops_s = ' '.join(f'{o:02x}' for o in ops)
    print(f"handler {hex(h):8s}: opcodes [{ops_s}]")

# guardar mapa opcode->handler
with open(os.path.join(OUT_DIR, 'vm_handler_map.txt'), 'w') as f:
    for op, h in enumerate(handlers):
        f.write(f"op {op:02x} class {classes[op]} size {CLASS_SIZE[classes[op]]:2d} handler {hex(h)}\n")
print(f"\n-> mapa en {OUT_DIR}/vm_handler_map.txt")
