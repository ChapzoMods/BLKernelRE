#!/usr/bin/env python3
"""Extracción de strings ASCII + UTF-16LE con contexto RVA"""
import re, sys, os

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
PATH = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")
data = open(PATH, 'rb').read()

# Mapeo de offsets raw -> RVA aproximado usando secciones conocidas
sections = [
    (".text",   0x400,  0x16600, 0x1000),
    (".rdata",  0x16a00, 0xda00,  0x18000),
    (".data",   0x24400, 0xc00,   0x26000),
    (".pdata",  0x25000, 0x1600,  0x28000),
    (".blkcode",0x26600, 0x2600,  0x2a000),
    (".fptable1",0x28c00, 0x200,  0x2d000),
    (".fptable2",0x28e00, 0x200,  0x2e000),
    (".rsrc",   0x29000, 0x400,   0x2f000),
    (".reloc",  0x29400, 0xa00,   0x30000),
]
def off_to_rva(off):
    for name, raw, rawsz, rva in sections:
        if raw <= off < raw + rawsz:
            return name, rva + (off - raw)
    return "?", 0

ASCII_RE = re.compile(rb'[\x20-\x7e]{5,}')
UTF16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')

print("="*78)
print("STRINGS ASCII (min 5 chars)")
print("="*78)
seen = set()
for m in ASCII_RE.finditer(data):
    s = m.group().decode()
    if s in seen: continue
    seen.add(s)
    sec, rva = off_to_rva(m.start())
    print(f"[{sec:9s} off={m.start():#08x} rva={rva:#08x}] {s}")

print()
print("="*78)
print("STRINGS UTF-16LE (min 4 chars)")
print("="*78)
seen = set()
for m in UTF16_RE.finditer(data):
    s = m.group().decode('utf-16-le')
    if s in seen: continue
    seen.add(s)
    sec, rva = off_to_rva(m.start())
    print(f"[{sec:9s} off={m.start():#08x} rva={rva:#08x}] {s}")
