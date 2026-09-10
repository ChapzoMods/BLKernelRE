#!/usr/bin/env python3
"""Extrae funciones específicas del desensamblado anotado"""
import re, sys, os

OUT_DIR = os.environ.get("BLK_OUT") or "artifacts"

txt = open(os.path.join(OUT_DIR, 'disasm_annotated.txt')).read()
funcs = []
for f in re.split(r'={70}\n FUNC', txt):
    m = re.match(r' @ RVA (0x[0-9a-f]+) - (0x[0-9a-f]+)', f)
    if m:
        beg, end = int(m.group(1),16), int(m.group(2),16)
        funcs.append((beg, end, f))

def dump(rva, maxchars=16000):
    for beg, end, f in funcs:
        if beg <= rva < end:
            out = 'FUNC' + f
            print(out[:maxchars])
            return
    print(f"Func {hex(rva)} no encontrada")

targets = [int(x, 16) for x in sys.argv[1:]] if len(sys.argv) > 1 else [0x3740]
for t in targets:
    print("\n" + "#"*78)
    dump(t)
