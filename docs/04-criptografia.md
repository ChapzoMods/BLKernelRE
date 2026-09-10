# 04 — Criptografía: ruptura completa (paso a paso)

Este documento describe el esquema criptográfico de BLKernel tal como fue reconstruido desde
el desensamblado, y **cómo se rompió**. El exploit del descifrado está en
`scripts/decrypt_blkcode.py` y se reproduce con un solo comando.

## 1. Visión general

```
                      ┌──────────────────────────────────────────────┐
                      │  .blkcode (RVA 0x2A000, 0x24C8 bytes)        │
                      │  [ magic 8B | code_size 8B | data_size 8B    │
                      │    | bytecode code_size | data data_size ]   │
                      └──────────────────────────────────────────────┘
                                        │
              capa 1: stream cipher SplitMix64 (DETERMINISTA)
              estado = bl_hash64(g_key32, key64)
              keystream[i] = mix(i·GOLDEN ^ estado ^ tamaño)
                                        │
                                        ▼
              payload en claro (header + bytecode + RAM image)
                                        │
              capa 2: re-cifrado anti-dump (NO determinista, en memoria)
              keystream[i] = mix(i·GOLDEN ^ hash(PID^heap^rdtsc^...))
              (el intérprete descifra on-the-fly en cada fetch)
                                        ▼
              VM ejecuta el bytecode
```

## 2. Los tres ingredientes de la clave (capa 1)

### 2.1 `key64` — derivación en `0x1b60` (344 bytes)

La función hace tres cosas curiosas y las combina en un `u64`:

```c
uint64_t derive_key64(void) {
    // (a) Recurso RT_RCDATA id 7 (16 bytes): toma los dos primeros bytes
    //     22 1c → res16 = 0x1C22
    uint16_t res16 = res[0] | (res[1] << 8);          // = 0x1C22

    // (b) Parsea SUS PROPIAS cabeceras PE en memoria, recorre la tabla de
    //     secciones buscando el nombre ".fptable" (qword 0x656C62617470662E),
    //     y lee el PRIMER BYTE de esa sección (VirtualAddress 0x2D000)
    uint8_t fp_byte = *(uint8_t*)(image + 0x2D000);   // = 0xEB

    // (c) Byte del DOS header en image+0x28 (e_res[0], "reservado")
    uint8_t e_res   = *(uint8_t*)(image + 0x28);      // = 0x37

    return ((((uint64_t)e_res << 8 | fp_byte) << 16) | res16) << 32 | 0x628688F0;
    //     = 0x37EB1C22628688F0
}
```

La constante `0x628688F0` ocupa los 32 bits bajos. Todo el "secreto" de `key64` son
**bytes legibles del propio archivo**.

### 2.2 `g_key32` — el CRC32 del propio `.text` (¡leído del disco!)

`0x2e40` (llamada desde main vía `0x2e00` antes del descifrado):

```c
uint32_t g_key32(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);        // la ruta de ESTE exe
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    uint32_t sz = GetFileSize(h, NULL);
    uint8_t* buf = HeapAlloc(...); ReadFile(h, buf, sz, ...);   // ¡se lee a sí mismo!
    // localiza la sección ".text" del ARCHIVO (no de la imagen mapeada):
    //   [r8 + 40i + 0x18] == ".text"  (0x7865742E + 't')
    //   edx = SizeOfRawData, r9 = PointerToRawData
    return crc32_raw(buf + .text.PointerToRawData, .text.SizeOfRawData);
    //   = 0xC00DDD8F para esta muestra
}
```

`crc32_raw` (`0x1240`) es un CRC32 estándar (polinomio reflejado `0xEDB88320`) pero
**sin init `0xFFFFFFFF` ni XOR final** — init 0 y salida directa:

```c
uint32_t crc32_raw(const uint8_t* p, size_t n) {
    uint32_t crc = 0;
    while (n--) {
        crc ^= *p++;
        for (int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return crc;
}
```

> **Función dual**: además de ser parte de la clave, el CRC del `.text` actúa como candado
> anti-parcheo: si modificas un solo byte del `.text` en el archivo, `g_key32` cambia y el
> payload descifra a basura → el programa "se rompe solo". Es una protección de integridad
> implícita. (Su contrapartida — el CRC de la imagen mapeada, `.data+0xb3c` — se recalcula
> en `0x3080` y se re-verifica con `0x2dc0`.)

### 2.3 `bl_hash64` — el mezclador (`0x11e0`)

```c
uint64_t bl_hash64(uint32_t ecx, uint64_t key64) {
    uint64_t x = (uint64_t)ecx * 0x9E3779B97F4A7C15ULL ^ key64;
    x ^= (x ^ 0x5A17C0DE5A17C0DEULL) >> 30;
    x ^= 0x5A17C0DE5A17C0DEULL;
    x *= 0xBF58476D1CE4E5B9ULL;               // finalizer SplitMix64
    uint64_t y = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return y ^ (y >> 31);
}
```

*(La constante `0x5A17C0DE...` es un guiño leet: "5a17c0de" ≈ "SATI-CODE"/"code".)*

## 3. El cifrador de flujo (`0x1390`)

```c
void stream_crypt(uint64_t state, uint8_t* buf, size_t size) {
    for (size_t i = 0; i < size / 8; i++) {
        uint64_t ks = splitmix_final(i * 0x9E3779B97F4A7C15ULL ^ state ^ size);
        ((uint64_t*)buf)[i] ^= ks;
    }
}
```

Donde `splitmix_final` (la misma de SplitMix64):

```c
uint64_t splitmix_final(uint64_t x) {
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
```

Observaciones:
- El **tamaño** del buffer participa en el keystream (`^ size`).
- La versión nativa tiene un camino SIMD (SSE4.1, `vpsrlvq`/`pshufb`, 4 qwords por iteración,
  gated por `__isa_available >= 5`) y un camino escalar — funcionalmente idénticos.
- Es un **cifrado de flujo sin MAC ni IV por bloque**: mismo estado + mismo tamaño → mismo
  keystream. Clásico XOR-CTR caseiro.

## 4. El descifrado (reproducible)

```bash
$ python3 scripts/decrypt_blkcode.py
[*] key64 derivada = 0x37eb1c22628688f0
[*] g_key32 = CRC32(.text disco) = 0xc00ddd8f
[*] state (hash64) = 0x9eeea1b36def62f8

[+] HEADER descifrado:
    magic  = 0x770f89da30a70374
    field1 = 0xe9d  (3741 bytes de bytecode)
    field2 = 0x1610 (5648 bytes de imagen RAM)
    checks: f1<=0x3fffff ✓  f2<=0x20000 ✓  0x18+f1+f2<=size ✓
```

Todos los checks del header nativo (`0x37d2`–`0x3801`) se satisfacen — confirmación de que
la ruptura es exacta.

## 5. La capa 2 — "anti-dump" con keystream no determinista

Tras descifrar, `0x3740` NO deja el bytecode en claro en memoria. En su lugar:

```c
uint64_t seed = GetCurrentProcessId() ^ GetProcessHeap() ^ rdtsc_64()
                ^ data_size ^ magic;
ctx->seed = mix(seed);                       // VMCTX+0xe8
for (block = 0; block < ceil(code_size/8); block++)
    codebuf[block] = plaintext[block] ^ mix(block*GOLDEN ^ ctx->seed);
```

Como el seed incluye `rdtsc`, un dump de memoria no revela el bytecode. **PERO** el truco
es reversible por diseño: el propio intérprete necesita leer el bytecode, así que en cada
fetch recalcula el mismo keystream:

```c
// 0x4390 (fetch):
if ((pc >> 3) != ctx->last_block) {
    ctx->last_block = pc >> 3;
    ctx->keystream = bl_hash64((pc>>3) * GOLDEN ^ ctx->seed);
}
uint8_t opcode = code[pc] ^ (ctx->keystream >> ((pc & 7) * 8));
```

⇒ **Neutralización**: basta detenerse en el fetch (breakpoint en `0x4390`) o instrumentar
el intérprete para capturar el bytecode plano. En esta investigación ni siquiera hizo
falta: el bytecode plano es exactamente el resultado de la capa 1, que ya se obtiene
estáticamente. La capa 2 solo protege contra *dumping*, no contra *análisis*.

## 6. Cripto del bytecode (lógica de licencia)

El bytecode desensamblado (`artifacts/blk_disasm.txt`) contiene las constantes:

| Constante | Significado |
|---|---|
| `0x100000001B3` | FNV-1a 64 prime |
| `0xCBF29CE484222325` | FNV-1a 64 offset basis |
| `0x9E3779B97F4A7C15` | SplitMix64 golden ratio |
| `0x8E8A60EA32258A18` | constante custom (mezcla) |

Con `argv[2]` (usuario) y `argv[3]` (clave) en `ram+0x0` y `ram+0x100`, el programa VM
calcula FNV-1a sobre los inputs + fingerprint y lo mezcla con SplitMix64 para decidir
la validez de la licencia (la comparación contra `.fptable#1` es el binding HWID).

## 7. Análisis de seguridad del diseño criptográfico

| Problema | Consecuencia |
|---|---|
| La clave vive íntegramente en el binario (recurso + bytes del propio archivo) | Sin secretos reales → payload extraíble estáticamente |
| El "secreto" del CRC del `.text` se obtiene del propio archivo | Idem — cualquier copia del exe contiene su clave |
| Cifrado de flujo sin MAC | El payload no está autenticado: imposible distinguir un payload legítimo de uno falsificado |
| Keystream dependiente solo de (estado, tamaño) | keystream reutilizable para cualquier archivo del mismo tamaño con el mismo estado |
| Capa 2 con seed regenerable por el propio intérprete | Anti-dump cosmético — un tracer de un solo breakpoint lo anula |
| `bl_hash64`/SplitMix64 son PRF no criptográficas | Todas "rompibles" por diseño conocido (no hay secreto en el algoritmo) |
