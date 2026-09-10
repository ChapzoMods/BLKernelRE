#!/usr/bin/env python3
"""Análisis de recursos, .blkcode, .fptable y strings raros"""
import pefile, os, sys

OUT_DIR = os.environ.get("BLK_OUT") or "artifacts"
os.makedirs(OUT_DIR, exist_ok=True)

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
PATH = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")
pe = pefile.PE(PATH)

def hexdump(data, base=0, max_lines=40):
    for i in range(0, min(len(data), max_lines*16), 16):
        chunk = data[i:i+16]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"    {base+i:08x}  {hexs:<48s}  {asc}")

# Recursos
print("="*78)
print("RECURSOS (contenido)")
print("="*78)
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for e1 in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for e2 in e1.directory.entries:
            for e3 in e2.directory.entries:
                data = e3.data.struct
                blob = pe.get_data(data.OffsetToData, data.Size)
                rtype = pefile.RESOURCE_TYPE.get(e1.id, str(e1.id))
                print(f"\n[+] Tipo={rtype} Nombre={e2.id} Lang={e3.id} RVA={hex(data.OffsetToData)} Tamaño={data.Size}")
                hexdump(blob, data.OffsetToData, 60)
                # guardar
                fn = os.path.join(OUT_DIR, f"res_{rtype}_{e2.id}.bin")
                open(fn, 'wb').write(blob)
                print(f"    -> guardado en {fn}")

# blkcode
print("\n" + "="*78)
print("SECCIÓN .blkcode (primeros 64 líneas)")
print("="*78)
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    if name == '.blkcode':
        d = s.get_data()
        hexdump(d, s.VirtualAddress, 64)

# fptables
print("\n" + "="*78)
print("SECCIONES .fptable (completas)")
print("="*78)
n = 0
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    if name == '.fptable':
        n += 1
        d = s.get_data()
        print(f"\n[+] .fptable #{n} (RVA {hex(s.VirtualAddress)}, {len(d)} bytes, perm {'RW' if s.Characteristics & 0x80000000 else 'R'})")
        hexdump(d, s.VirtualAddress, 16)

# .data
print("\n" + "="*78)
print("SECCIÓN .data (primeras 48 líneas)")
print("="*78)
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    if name == '.data':
        d = s.get_data()
        hexdump(d, s.VirtualAddress, 48)

# Debug directory
print("\n" + "="*78)
print("DEBUG DIRECTORY (PDB path)")
print("="*78)
if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
    for d in pe.DIRECTORY_ENTRY_DEBUG:
        try:
            print(f"    Tipo={d.struct.Type} PDB: {d.entry.PdbFileName}")
        except Exception:
            print(f"    entry: {d.struct}")
