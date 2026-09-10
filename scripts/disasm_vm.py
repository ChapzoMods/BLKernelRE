#!/usr/bin/env python3
"""Desensamblador del bytecode VM de BLKernel (.blkcode capa-1, plano)"""
import struct
import sys
import os

OUT_DIR = os.environ.get("BLK_OUT") or "artifacts"

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
SAMPLE = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")

BLK = open(os.path.join(OUT_DIR, 'blkcode_layer1.bin'), 'rb').read()
magic, code_size, data_size = struct.unpack('<QQQ', BLK[:0x18])
code = BLK[0x18:0x18+code_size]

# tabla de clases RVA 0x1b7f0 (158 opcodes, clase 0-8)
data = open(SAMPLE, 'rb').read()
import pefile
pe = pefile.PE(SAMPLE)
secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
def rva2off(rva):
    for va, vs, raw, rs in secs:
        if va <= rva < va + max(vs, rs):
            return raw + (rva - va)
classes = data[rva2off(0x1b7f0):rva2off(0x1b7f0)+0x9e]

# tamaño total de instrucción por clase (opcode + operandos)
CLASS_SIZE = {0: 1, 1: 2, 2: 3, 3: 6, 4: 0xa, 5: 6, 6: 7, 7: 5, 8: 5}

def disasm():
    pc = 0
    out = []
    while pc < len(code):
        op = code[pc]
        if op >= 0x9e:
            out.append(f"{pc:04x}: ?? {op:02x}  (INVÁLIDO >= 0x9e)")
            pc += 1
            continue
        c = classes[op]
        sz = CLASS_SIZE[c]
        ins = code[pc:pc+sz]
        if len(ins) < sz:
            out.append(f"{pc:04x}: {op:02x} (truncado)")
            break
        hexs = ' '.join(f'{b:02x}' for b in ins)
        # interpretación por clase
        ann = ''
        if c == 0:
            ann = f'op_{op:02x}'
        elif c == 1:
            ann = f'op_{op:02x} {ins[1]:02x}'
        elif c == 2:
            ann = f'op_{op:02x} {ins[1]:02x} {ins[2]:02x}'
        elif c in (3, 5):
            ann = f'op_{op:02x} {ins[1]:02x} {struct.unpack("<I", ins[2:6])[0]:#x}'
        elif c == 4:
            ann = f'op_{op:02x} {ins[1]:02x} {struct.unpack("<Q", ins[2:10])[0]:#x}'
        elif c == 6:
            ann = f'op_{op:02x} {ins[1]:02x} {struct.unpack("<I", ins[2:6])[0]:#x} {ins[6]:02x}'
        elif c in (7, 8):
            ann = f'op_{op:02x} {struct.unpack("<I", ins[1:5])[0]:#x}'
        out.append(f"{pc:04x}: {hexs:<30s} {ann}")
        pc += sz
    return out

lines = disasm()
print(f"Bytecode: {code_size} bytes, {len(lines)} instrucciones")
print(f"RAM data: {data_size} bytes")
print()
for l in lines[:120]:
    print(l)
print("...")
# guardar completo
open(os.path.join(OUT_DIR, 'blk_disasm.txt'), 'w').write('\n'.join(lines))
print(f"\n-> listado completo en {OUT_DIR}/blk_disasm.txt ({len(lines)} líneas)")

# estadística de opcodes
from collections import Counter
cnt = Counter()
pc = 0
while pc < len(code):
    op = code[pc]
    if op >= 0x9e:
        pc += 1; continue
    cnt[op] += 1
    pc += CLASS_SIZE[classes[op]]
print("\nTop 25 opcodes más frecuentes:", cnt.most_common(25))
