# 03 — Arquitectura del binario

## 1. Cadena de arranque (reconstruida)

```
main (RVA 0x1090)
  │
  ├─ SetErrorMode(3)
  ├─ __security_init_cookie()
  │
  ├─ if (argc >= 2 && strcmp(argv[1], "--check") == 0):
  │      if (argc != 4) → ExitProcess(2)        # uso: BLKernel.exe --check <user> <key>
  │      g_checkMode (.data+0xb44) = 1
  │
  ├─ AddVectoredExceptionHandler(1, anti_tamper @ 0x1000)
  │      └─ en cada excepción: valida MZ/PE del módulo propio; si está alterado → ExitProcess(2)
  │
  ├─ 0x1cc0: resolver APIs nativas de ntdll (GetProcAddress)
  │      NtQueryInformationProcess   → .data+0xb50
  │      NtQuerySystemInformation    → .data+0xb58
  │      NtSetInformationThread      → .data+0xb60
  │      NtCreateThreadEx            (se resuelve de nuevo en 0x3d0b)
  │
  ├─ 0x2e00: INTEGRIDAD DISCO
  │      ├─ 0x2e40: GetModuleFileNameA → CreateFileA(GENERIC_READ, share ALL)
  │      │           → ReadFile(del propio exe) → localiza ".text" en disco
  │      │           → g_key32 (.data+0xb38) = CRC32_raw(.text del archivo)
  │      └─ 0x3080: CRC32_raw(.text de la imagen MAPEADA) → .data+0xb3c
  │
  ├─ 0x2940 → 0x2972: SUITE ANTI-VM/ANTI-DEBUG (VMware/VBox/KVM/Xen/QEMU/Parallels/
  │      Hyper-V/Wine, MAC, IsDebuggerPresent, CheckRemoteDebuggerPresent,
  │      NtQueryInformationProcess(ProcessDebugPort/Flags/Handle),
  │      NtSetInformationThread(ThreadHideFromDebugger), rdtsc timing)
  │      → si detecta algo: 0x1180(1) → salida silenciosa
  │
  ├─ 0x3170 → 0x31c6: PRIVILEGIOS + SONDEO
  │      ├─ OpenProcessToken + GetTokenInformation(TokenElevation)
  │      ├─ si elevado: g_isAdmin (.data+0xb40) = 1
  │      ├─ LookupPrivilegeValueA+AdjustTokenPrivileges(SeDebugPrivilege)
  │      ├─ CreateToolhelp32Snapshot → Process32First/Next → buscar "winlogon.exe"
  │      │   └─ OpenProcess(0x1000, winlogon_pid) + CloseHandle  (probe de acceso)
  │      ├─ SeSystemEnvironmentPrivilege (para firmware UEFI)
  │      └─ NtQuerySystemInformation(0x89 SystemKernelDebuggerInformation)
  │          + NtQuerySystemInformation(0xB SystemModuleInformation) → anti-KD/anti-rootkit
  │
  ├─ 0x1e80(1): inicialización (thread/consola interna, 1402 bytes)
  ├─ 0x2400: inicialización de huella / segunda fase de entorno
  │
  └─ 0x3740: DESCIFRAR + MONTAR EL VM (el corazón)
         │
         (ver 04-criptografia.md y 05-maquina-virtual.md)
```

## 2. La función 0x3740 — montaje del payload

Firma efectiva: `boot_vm(payload=.blkcode, size=0x24c8, user=argv[2], key=argv[3])`

```
1.  key64 = 0x1b60()                      ← derivación de clave (ver 04)
2.  heap  = HeapAlloc(0x24c8); memcpy(heap, .blkcode, 0x24c8)
3.  state = bl_hash64(g_key32, key64)     ← g_key32 = CRC32(.text disco)
4.  0x1390(state, heap, 0x24c8)           ← descifrado capa 1 (SplitMix64 stream)
5.  valida header:  { magic(8) | code_size(8) | data_size(8) }
       code_size ≤ 0x3FFFFF, data_size ≤ 0x20000, 0x18+code+data ≤ 0x24c8
6.  VMCTX (.data+0xb80, 0x108 bytes) = {0}   ← contexto de la máquina virtual
7.  codebuf = HeapAlloc(code_size)           → VMCTX+0x00
    ram     = HeapAlloc(0x20000)             → VMCTX+0x10
    memcpy(ram, payload+0x18+code_size, data_size)   ← imagen RAM inicial
8.  seed = GetCurrentProcessId() ^ GetProcessHeap() ^ rdtsc()
          ^ data_size ^ magic
    VMCTX+0xe8 = bl_hash64_mix(seed)         ← semilla del keystream anti-dump
9.  loop (i = 0 .. ceil(code_size/8)):
       codebuf[i*8..] = payload.data1[i*8..] XOR keystream(i)
       keystream(i) = splitmix_final(i*GOLDEN ^ VMCTX.seed)
       ⚠ el bytecode queda CIFRADO EN MEMORIA (anti-dump); el fetch lo descifra on-the-fly
10. VM init (0x3b26):
       ctx.flags = 2 · pc = 0 · sp_base = 0x10000
       0x1650(): genera S-box 256B (identity + shuffle BLK_SEED) en .data+0x19a0
       copia S-box → ram+0x300 ; tabla secundaria (.data+0x18a0) → ram+0x400
       si checkMode: strcpy(ram+0x000, argv[2])  (≤63 bytes)
                      strcpy(ram+0x100, argv[3])  (≤63 bytes)
11. GetProcAddress(ntdll, "NtCreateThreadEx")
    NtCreateThreadEx(&t, 0x1FFFFF, NULL, GetCurrentProcess(),
                     start=0x7280, NULL, 4, ...)   ← hilo del VM
    0x7280: NtSetInformationThread(ThreadHideFromDebugger) → 0x4390(VMCTX)  ← INTÉRPRETE
```

## 3. Estructura del VMCTX (`.data+0xb80`, 0x108 bytes)

| Offset | Campo | Uso |
|---|---|---|
| +0x00 | `code` | puntero al bytecode (cifrado en memoria) |
| +0x08 | `code_size` | tamaño del bytecode |
| +0x10 | `ram` | puntero a RAM (0x20000) |
| +0x18 | `ram_size` | 0x20000 |
| +0x20 | `regs[16]` | 16 registros de 64 bits |
| +0xA0 | `reg_map[16]` | tabla de remap registro virtual → físico |
| +0xB0 | `flags` | bit0 = ZF, bit1 = SF |
| +0xB8 | `pc` | contador de programa (byte offset) |
| +0xC8 | `trace_hash` | cadena de hash de instrucciones ejecutadas (anti-tamper de trazado) |
| +0xD0 | `icount` | presupuesto de instrucciones (límite 0x0BEBC200 = 200 000 000) |
| +0xE8 | `seed` | semilla del keystream anti-dump |
| +0xF0 | `last_block` | último bloque de 8 bytes descifrado |
| +0xF8 | `keystream` | keystream del bloque actual |

## 4. Fingerprint HWID (función 0x2972, 710 bytes)

Orígenes de datos identificados (llenan `.fptable#2` RW — RVA 0x2E000):

| Fuente | API | Valor |
|---|---|---|
| Usuario | `GetUserNameA` | nombre de cuenta |
| Red | `GetAdaptersInfo` ×2 | dirección(es) MAC |
| Memoria | `GlobalMemoryStatusEx` | RAM total |
| CPU/SO | `GetSystemInfo` | arquitectura, nº procesadores, page size |
| Firmware | `GetFirmwareEnvironmentVariableA` | variables UEFI (requiere `SeSystemEnvironmentPrivilege`) |
| Proceso | `GetCurrentProcessId`, heap handle | ruido anti-tracing |

`.fptable#1` (R, 64 bytes) contiene el **hash esperado** del fingerprint: el payload está
vinculado a la máquina concreta (binding HWID). La comparación y la lógica de decisión viven
en el **bytecode del VM** (no en código nativo) — por eso el `--check user key` pasa
`argv[2]`/`argv[3]` a la RAM del VM en `ram+0x0` y `ram+0x100`.

## 5. Layout de la RAM del VM (0x20000 bytes)

| Offset | Contenido | Origen |
|---|---|---|
| +0x000 | `user` (string C, ≤64 B) | `argv[2]` (modo --check) |
| +0x100 | `key` (string C, ≤64 B) | `argv[3]` |
| +0x300 | S-box (256 B) | generada en runtime con `BLK_SEED` |
| +0x400 | tabla secundaria (256 B) | `.data+0x18a0` runtime |
| +0x500 | imagen de datos | `data2` del payload (5 648 B) |
| +0x10000 | pila del VM | `sp_base` |

## 6. Inventario de funciones nativas clave

| RVA | Tamaño | Rol |
|---|---|---|
| 0x1000 | 141 | VEH handler anti-tamper (valida PE propio) |
| 0x1090 | 230 | **main** |
| 0x1180 | — | `die_silently(1)` |
| 0x11e0 | 60 | `bl_hash64(u32, u64)` — SplitMix64 + constante 0x5A17C0DE |
| 0x1240 | 177 | `crc32_raw(buf, len)` — polinomio 0xEDB88320 sin init/flip final |
| 0x1390 | 429 | `stream_cipher(state, buf, size)` — SplitMix64 (SIMD SSE4 + scalar) |
| 0x1600 | 16 | `ExitProcess(2)` |
| 0x1610 | 58 | `splitmix_final(x)` |
| 0x1650 | 447 | generador de tablas S (BLK_SEED) |
| 0x1b60 | 344 | `derive_key64()` — recurso RCDATA + .fptable + e_res + 0x628688F0 |
| 0x1cc0 | 433 | resolver APIs nativas ntdll |
| 0x2d90 | 43 | `is_disk_intact()` — re-CRC disco vs .data+0xb38 |
| 0x2dc0 | 43 | `is_memory_intact()` — re-CRC imagen vs .data+0xb3c |
| 0x2e40 | 565 | `crc32_of_file_text()` — se abre y lee a sí mismo del disco |
| 0x3080 | 225 | `crc32_of_mapped_text()` |
| 0x31c6 | 513 | elevación + SeDebugPrivilege + probe winlogon + anti-KD |
| 0x3740 | 1928* | boot del VM (0x3740–0x3EC9, 3 bloques .pdata) |
| 0x3ed0/0x4050 | — | fetch de operandes imm32/imm64 con descifrado on-the-fly |
| 0x4320 | — | fetch de byte de opcode con descifrado on-the-fly |
| 0x4390 | ~2900 | **intérprete del VM** (0x4390–0x6B19 + handlers 0x6280–0x6B18) |
| 0x6b19 | — | `dispatch_next` (NOP) |
| 0x6b23 | — | `dispatch_no_advance` (saltos) |
| 0x6b4a | — | error/halt del VM |
| 0x7280 | 130 | thread proc del VM: hide-from-debugger + interprete |
