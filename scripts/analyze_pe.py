#!/usr/bin/env python3
"""Análisis estático completo de PE - BLKernel.exe"""
import pefile, math, hashlib, sys, os, datetime

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
PATH = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")
print(f"[*] Muestra: {PATH}")
pe = pefile.PE(PATH, fast_load=False)

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    e = 0.0
    for f in freq:
        if f:
            p = f/len(data)
            e -= p*math.log2(p)
    return e

print("="*78)
print("ANÁLISIS DE CABECERAS PE — BLKernel.exe")
print("="*78)

# --- DOS header ---
print(f"\n[+] DOS Header: magic={pe.DOS_HEADER.e_magic:#x}, e_lfanew={pe.DOS_HEADER.e_lfanew:#x}")

# --- Rich header (compilador) ---
try:
    rich = pe.parse_rich_header()
    if rich:
        print("\n[+] RICH HEADER (herramientas del compilador):")
        vals = rich.get('rich_values', []) if isinstance(rich, dict) else []
        for item in vals:
            print(f"    prodid={item.get('prodid')} build={item.get('build')} count={item.get('ct',1)}")
    else:
        print("\n[-] Sin Rich Header (no MSVC o eliminado)")
except Exception as ex:
    print(f"\n[-] Rich header error: {ex}")

# --- FILE header ---
fh = pe.FILE_HEADER
print(f"\n[+] FILE HEADER: Machine={hex(fh.Machine)} Characteristics={hex(fh.Characteristics)}")
print(f"    NumberOfSections={fh.NumberOfSections}, TimeDateStamp={fh.TimeDateStamp}", end="")
try:
    print(f" -> {datetime.datetime.utcfromtimestamp(fh.TimeDateStamp)} UTC")
except Exception:
    print()
print(f"    PointerToSymbolTable={fh.PointerToSymbolTable}, NumberOfSymbols={fh.NumberOfSymbols}")

# --- OPTIONAL header ---
oh = pe.OPTIONAL_HEADER
print(f"\n[+] OPTIONAL HEADER: Magic={hex(oh.Magic)} (20b=PE32+)")
print(f"    AddressOfEntryPoint={hex(oh.AddressOfEntryPoint)} (RVA)")
print(f"    ImageBase={hex(oh.ImageBase)}, SizeOfImage={hex(oh.SizeOfImage)}, SizeOfHeaders={hex(oh.SizeOfHeaders)}")
print(f"    Subsystem={oh.Subsystem} (3=console) DllCharacteristics={hex(oh.DllCharacteristics)}")
print(f"    Stack: reserve={hex(oh.SizeOfStackReserve)} commit={hex(oh.SizeOfStackCommit)}")
print(f"    Heap:  reserve={hex(oh.SizeOfHeapReserve)} commit={hex(oh.SizeOfHeapCommit)}")
print(f"    ASLR={'Sí' if oh.DllCharacteristics & 0x40 else 'NO'} | DEP/NX={'Sí' if oh.DllCharacteristics & 0x100 else 'NO'} | CFG={'Sí' if oh.DllCharacteristics & 0x4000 else 'NO'}")
print(f"    HighEntropyVA={'Sí' if oh.DllCharacteristics & 0x20 else 'NO'}")

# --- Data directories ---
print("\n[+] DATA DIRECTORIES:")
names = ['EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC','DEBUG','ARCHITECTURE','GLOBALPTR','TLS','LOAD_CONFIG','BOUND_IMPORT','IAT','DELAY_IMPORT','CLR','RESERVED']
for i, d in enumerate(oh.DATA_DIRECTORY):
    if d.VirtualAddress and d.Size:
        print(f"    [{i:2d}] {names[i] if i < len(names) else '?':14s} RVA={hex(d.VirtualAddress):>10s} Size={d.Size}")

# --- SECTIONS ---
print("\n[+] SECCIONES:")
print(f"    {'Name':10s} {'VirtAddr':>10s} {'VirtSize':>10s} {'RawPtr':>10s} {'RawSize':>10s} {'Entropy':>8s} Perms")
for s in pe.sections:
    data = s.get_data()
    e = entropy(data)
    name = s.Name.decode(errors='replace').rstrip('\x00')
    chars = []
    if s.Characteristics & 0x20000000: chars.append('EXEC')
    if s.Characteristics & 0x40000000: chars.append('READ')
    if s.Characteristics & 0x80000000: chars.append('WRITE')
    print(f"    {name:10s} {s.VirtualAddress:#10x} {s.Misc_VirtualSize:#10x} {s.PointerToRawData:#10x} {s.SizeOfRawData:#10x} {e:8.3f} {','.join(chars)}")

# --- IMPORTS ---
print("\n[+] IMPORTS:")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors='replace')
        print(f"\n  == {dll} ({len(entry.imports)} funciones) ==")
        for imp in entry.imports:
            n = imp.name.decode(errors='replace') if imp.name else f"ord_{imp.ordinal}"
            print(f"      {n}")
else:
    print("  (Sin tabla de imports visible — posible packing/resolve manual)")

# --- EXPORTS ---
print("\n[+] EXPORTS:")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print(f"    {exp.name} @ RVA {hex(exp.address)}")
else:
    print("    (Ninguno)")

# --- TLS ---
print("\n[+] TLS CALLBACKS:")
if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    print(f"    AddressOfCallBacks={hex(tls.AddressOfCallBacks)}")
else:
    print("    (Sin TLS)")

# --- RECURSOS ---
print("\n[+] RECURSOS:")
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    def walk(entries, prefix=""):
        for e in entries:
            if hasattr(e, 'directory'):
                walk(e.directory.entries, prefix + str(e.name) + "/")
            else:
                d = e.data.struct
                print(f"    {prefix} id={e.id} RVA={hex(d.OffsetToData)} size={d.Size}")
    walk(pe.DIRECTORY_ENTRY_RESOURCE.entries)
else:
    print("    (Ninguno)")

# --- FIRMA ---
print("\n[+] FIRMA DIGITAL (WIN_CERT):", "Sí" if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY and pe.DIRECTORY_ENTRY_SECURITY.Size else "NO — binario sin firmar")

# --- OVERLAY ---
last = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
fsz = os.path.getsize(PATH)
print(f"\n[+] OVERLAY: fin de secciones={last}, tamaño archivo={fsz}, overlay={fsz-last} bytes")

print("\n[+] HASH SHA256 por sección:")
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    data = s.get_data()
    print(f"    {name:10s} {hashlib.sha256(data).hexdigest()}")
