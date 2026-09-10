#!/usr/bin/env python3
"""Descifrador capa-1 de .blkcode — BLKernel.exe
key64 = 0x37941c22628688f0 (derivada de recurso RCDATA + .pdata + e_res)
state = bl_hash64(g_key32=0, key64)
buf[i] ^= splitmix_mix(i*GOLDEN ^ state ^ size)
"""
import struct
import os, sys

OUT_DIR = os.environ.get("BLK_OUT") or "artifacts"
os.makedirs(OUT_DIR, exist_ok=True)

# Muestra: variable BLK_SAMPLE, argumento o valor por defecto (repo raíz)
SAMPLE = os.environ.get("BLK_SAMPLE") or (sys.argv[1] if len(sys.argv) > 1 else "BLKernel/BLKernel.exe")

M64 = 0xFFFFFFFFFFFFFFFF
GOLDEN = 0x9e3779b97f4a7c15
C1 = 0xbf58476d1ce4e5b9
C2 = 0x94d049bb133111eb
LEC0DE = 0x5a17c0de5a17c0de

def splitmix_final(x):
    x &= M64
    y = ((x ^ (x >> 30)) * C1) & M64
    z = ((y ^ (y >> 27)) * C2) & M64
    return z ^ (z >> 31)

def bl_hash64(ecx, rdx):
    x = ((ecx & 0xFFFFFFFF) * GOLDEN) & M64
    x ^= rdx
    x ^= ((x ^ LEC0DE) >> 30) & M64
    x ^= LEC0DE
    x = (x * C1) & M64
    y = x ^ (x >> 27)
    y = (y * C2) & M64
    return y ^ (y >> 31)

# --- Datos extraídos del binario ---
data = open(SAMPLE, 'rb').read()
# .blkcode: raw 0x26600, tamaño 0x24c8 (RVA 0x2a000)
BLK = bytearray(data[0x26600:0x26600+0x24c8])
SIZE = len(BLK)

# key64 derivada:
#   bits 0-15:  recurso RCDATA id7 bytes[0:2] = 0x22,0x1c -> 0x1c22
#   bits 16-23: byte en RVA 0x28c00 (vía PointerToRawData de .fptable) = 0x94
#   bits 24-31: byte en image+0x28 = 0x37
#   bits 32-63: 0x628688f0
res16 = 0x22 | (0x1c << 8)
fptable_byte = 0xEB   # byte en RVA 0x2d000 (VirtualAddress de .fptable#1) = primer byte de .fptable#1
e_res = 0x37
key64 = (((e_res << 8 | fptable_byte) << 16) | res16) << 32 | 0x628688F0
print(f"[*] key64 derivada = {hex(key64)}")

g_key32 = None  # se calcula abajo: CRC32 raw del .text del archivo en disco

def crc32_raw(buf, init=0):
    """CRC32 con polinomio 0xEDB88320, sin init 0xFFFFFFFF ni flip final (como 0x1240)"""
    crc = init
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1))
    return crc & 0xFFFFFFFF

# g_key32 = CRC32(.text del archivo en disco) — calculado por 0x2e40 al arrancar
g_key32 = crc32_raw(data[0x400:0x400+0x16600])
print(f"[*] g_key32 = CRC32(.text disco) = {hex(g_key32)}")

state = bl_hash64(g_key32, key64)
print(f"[*] state (hash64) = {hex(state)}")

# --- Descifrar capa 1 ---
out = bytearray(SIZE)
nq = SIZE // 8
for i in range(nq):
    ks = splitmix_final(((i * GOLDEN) & M64) ^ state ^ SIZE)
    v = struct.unpack('<Q', BLK[i*8:i*8+8])[0]
    v ^= ks
    out[i*8:i*8+8] = struct.pack('<Q', v)
# resto < 8 bytes (0x24c8 % 8 = 0, exacto)

magic, f1, f2 = struct.unpack('<QQQ', out[:0x18])
print(f"\n[+] HEADER descifrado:")
print(f"    magic     = {hex(magic)}")
print(f"    field1    = {hex(f1)} ({f1})")
print(f"    field2    = {hex(f2)} ({f2})")
print(f"    checks: f1<=0x3fffff: {f1 <= 0x3fffff} | f2<=0x20000: {f2 <= 0x20000} | 0x18+f1+f2<=size: {0x18+f1+f2 <= SIZE}")
open(os.path.join(OUT_DIR, 'blkcode_layer1.bin'), 'wb').write(out)
print(f"    -> guardado en {OUT_DIR}/blkcode_layer1.bin")

# mostrar inicio de data1 y data2
print("\ndata1[0:64]:", out[0x18:0x18+64].hex())
if 0x18+f1 <= SIZE:
    print("data2[0:64]:", out[0x18+f1:0x18+f1+64].hex())
