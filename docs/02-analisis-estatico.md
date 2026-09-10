# 02 — Análisis estático

## 1. Cabeceras PE

```
DOS Header   : magic=0x5A4D ("MZ"), e_lfanew=0x110
FILE Header  : Machine=0x8664 (AMD64), NumberOfSections=9, Characteristics=0x22
TimeDateStamp: 1789005595 → 2026-09-10 01:59:55 UTC
Optional     : Magic=0x20B (PE32+), EntryPoint RVA=0x7A90, ImageBase=0x140000000
               SizeOfImage=0x31000, Subsystem=3 (console)
DllCharacteristics=0xC160 → ASLR | DEP/NX | CFG | HighEntropyVA  (SEH no aplica en x64)
```

El `EntryPoint` (0x7A90) apunta al arranque estándar del CRT de MSVC (`__scrt_common_main_seh`),
que eventualmente invoca `main` (RVA **0x1090**). No hay TLS callbacks ni hijacking del entry point.

## 2. Secciones — la anomalía "BLK"

| # | Nombre | RVA | VSize | RawSize | Entropía | Perms | Observación |
|---|--------|-----|-------|---------|----------|-------|-------------|
| 1 | `.text` | 0x1000 | 0x165B0 | 0x16600 | 6.434 | R+X | código (440 funciones vía `.pdata`) |
| 2 | `.rdata` | 0x18000 | 0xD9D2 | 0xDA00 | 5.022 | R | constantes + IAT + strings |
| 3 | `.data` | 0x26000 | 0x1AB8 | 0xC00 | 1.927 | R+W | ⚠ VSize > RawSize → BSS runtime (tablas S-box) |
| 4 | `.pdata` | 0x28000 | 0x14A0 | 0x1600 | 4.954 | R | 440 RUNTIME_FUNCTIONs |
| 5 | **`.blkcode`** | 0x2A000 | 0x24C8 | 0x2600 | **7.914** | R | ⚠ payload cifrado (entropía ≈ cifrado) |
| 6 | **`.fptable`** | 0x2D000 | 0x40 | 0x200 | 1.270 | R | ⚠ 64 bytes de material de verificación |
| 7 | **`.fptable`** | 0x2E000 | 0x100 | 0x200 | 0.000 | R+W | ⚠ tabla RW — se rellena en runtime (fingerprint) |
| 8 | `.rsrc` | 0x2F000 | 0x3E0 | 0x400 | 5.236 | R | manifest + RCDATA id 7 |
| 9 | `.reloc` | 0x30000 | 0x91C | 0xA00 | 5.199 | R | reubicaciones |

**Secciones duplicadas con el mismo nombre** (`.fptable` ×2) es deliberado: el código localiza
la tabla *"esperada"* iterando la tabla de secciones y buscando el nombre (ver `0x1b60`), por lo
que duplicar el nombre forma parte del esquema de derivación de clave.

No hay overlay (fin de secciones == tamaño de archivo, 171 520).

## 3. Imports — el perfil conductual

Total: 4 DLLs, 114 funciones. Agrupadas por intención:

### Anti-debugging / anti-tracing
```
KERNEL32!  IsDebuggerPresent, CheckRemoteDebuggerPresent, OutputDebugStringA,
           QueryPerformanceCounter, QueryPerformanceFrequency, GetTickCount64,
           AddVectoredExceptionHandler, RtlCaptureContext, RtlVirtualUnwind, RaiseException
ntdll!*    NtQueryInformationProcess, NtQuerySystemInformation, NtSetInformationThread,
           NtCreateThreadEx        (* resueltas en runtime con GetProcAddress)
```

### Fingerprint de hardware (HWID)
```
ADVAPI32!  GetUserNameA, OpenProcessToken, GetTokenInformation
IPHLPAPI!  GetAdaptersInfo              → dirección MAC
KERNEL32!  GlobalMemoryStatusEx, GetSystemInfo, GetFirmwareEnvironmentVariableA
```

### Enumeración de procesos / ventanas (detección de análisis)
```
KERNEL32!  CreateToolhelp32Snapshot, Process32First/Next, QueryFullProcessImageNameA
USER32!    EnumWindows, GetWindowTextA  → ventanas de analizadores
```

### Capacidad de manipulación de procesos
```
KERNEL32!  OpenProcess, GetThreadContext, VirtualProtect, CreateThread, TerminateProcess,
           GetCurrentProcess/Thread
ADVAPI32!  AdjustTokenPrivileges, LookupPrivilegeValueA   → SeDebugPrivilege & co.
```

### E/S y gestión
```
KERNEL32!  CreateFileA/W, ReadFile, WriteFile, GetFileSize, FindFirstFileExW, FindNextFileW,
           LoadLibraryExW, GetModuleHandleA/W, GetProcAddress, GetCommandLineA/W, ...
```

> **Nota**: no hay `WriteProcessMemory` ni `CreateRemoteThread` en la IAT — la inyección,
> si ocurre, se hace vía APIs nativas resueltas dinámicamente (`NtCreateThreadEx`) o desde
> el bytecode del VM.

## 4. Recursos

| Tipo | ID | Tamaño | Contenido |
|---|---|---|---|
| `RT_MANIFEST` | 1 | 814 | XML: `requireAdministrator`, nombre "BLKernel", v1.0.0.0, Win7-Win11 compatible |
| `RT_RCDATA` | **7** | **16** | `22 1c 3b 3c 0c 6e e8 48 d7 9a f7 ba 95 26 04 ea` — **entrada de la clave de descifrado** (se usan los bytes 0-1) |

El recurso RCDATA id 7 es la pieza "secreta" de la derivación de clave. Como cualquier recurso
embebido, es públicamente extraíble → no aporta seguridad real (ver vulnerabilidad BLK-0DAY-01).

## 5. Strings relevantes (con RVA)

```
.rdata 0x1a348  "ntdll.dll"                       → resolución dinámica de APIs nativas
.rdata 0x1a358  "NtQueryInformationProcess"
.rdata 0x1a378  "NtQuerySystemInformation"
.rdata 0x1a398  "NtSetInformationThread"
.rdata 0x1a3b0  "NtCreateThreadEx"
.rdata 0x1ad88  "VMwareVMware"                    → detección hypervisor (CPUID leaf 0x40000000)
.rdata 0x1ad98  "VBoxVBoxVBox"
.rdata 0x1ada8  "KVMKVMKVM"
.rdata 0x1adb8  "XenVMMXenVMM"
.rdata 0x1adc8  "TCGTCGTCGTCG"                    → QEMU/TCG
.rdata 0x1add8  "prl hyperv  "                    → Parallels / Hyper-V (parcialmente invertido)
.rdata 0x1adf8  "wine_get_version"                → detección Wine
.rdata 0x1b7a0  "winlogon.exe"                    → objetivo del probe de privilegios
.rdata 0x1b7b0  "SeDebugPrivilege"
.rdata 0x1b7c8  "SeSystemEnvironmentPrivilege"    → necesario para GetFirmwareEnvironmentVariable
.rdata 0x1ad88+ "--check"                         → modo de verificación de licencia
.text  0x1672   0x424C4B5F53454544 = "BLK_SEED"   → seed de la tabla S (invertida en memoria: "DEES_KLB")
.text  0x3b4c   0x0B1C0DE5A17C0DE                 → constante leet "b1c0de5a17c0de" (BICODE·5A17C0DE)
.text  0x3b56   0x5A17C0DE5A17C0DE                → "5a17c0de5a17c0de" (id. función hash)
.rdata 0x18f10  "--check"
```

## 6. Packer / ofuscación

- Entropía 7.914 en `.blkcode` → **payload cifrado** (no UPX/MPRESS — el cifrado es propio, ver `04-criptografia.md`).
- No hay packer comercial: el "packer" es el propio VM (virtualización de código).
- Ofuscación de constantes: strings relevantes invertidas o embebidas como `movabs` inmediatos.
- El `Rich header` existe pero sin bloques útiles (los product IDs fueron neutralizados).

## 7. Compilador y símbolos

- MSVC moderno (CRT con `__isa_available` init en 0x7280, api-sets, `LoadLibraryExW` shim).
- **Sin PDB**: el directorio DEBUG contiene un entry tipo repro (28 bytes) sin ruta de PDB utilizable.
- 440 funciones recuperables desde `.pdata` (esto permitió reconstruir el inventario completo).
