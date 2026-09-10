# 06 — Técnicas anti-análisis (catálogo y bypass)

BLKernel implementa **13+ técnicas** de resistencia al análisis. Todas fueron identificadas
estáticamente en esta investigación y todas tienen bypass documentado.

## Catálogo

### 1. `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` (KERNEL32)
- **Dónde**: suite `0x2972` (llamada desde `0x2940`).
- **Detecta**: PEB.BeingDebugged; depurador remoto attach-eado.
- **Bypass**: `BeingDebugger` en 0 con `plugin` ScyllaHide / patch de PEB, o `EBX=0` en el check.

### 2. `NtQueryInformationProcess` (resolución dinámica)
- **Dónde**: `0x1cc0` resuelve el puntero → `.data+0xb50`; consultas con `ProcessDebugPort`
  (clase 7), `ProcessDebugObjectHandle` (0x1E), `ProcessDebugFlags` (0x1F).
- **Bypass**: inline-hook de la función resuelta (un `mov eax,0; ret` en el slot) — como
  el binario cachea el puntero ANTES de usarlo, hookear ntdll no sirve de nada si se parchea
  la global `.data+0xb50`.

### 3. `NtSetInformationThread(ThreadHideFromDebugger)` (clase 0x11)
- **Dónde**: `0x7280` (arranque del hilo VM) y `0x7298`.
- **Efecto**: el hilo no recibe eventos de debug → breakpoints "no se disparan" en el VM.
- **Bypass**: attach después del arranque + restaurar, o hook de `NtSetInformationThread`
  que filtre la clase 0x11.

### 4. `NtQuerySystemInformation(0x89)` — detección de kernel debugger
- **Dónde**: `0x3350` (SystemKernelDebuggerInformation).
- **Detecta**: KD activo (boot con `/debug`).
- **Bypass**: no debuggear con KD, o falsificar la estructura devuelta `{KdEnabled, KdNotPresent}`.

### 5. `NtQuerySystemInformation(0xB)` — enumeración de módulos del kernel
- **Dónde**: `0x33A7`+ (SystemModuleInformation con HeapAlloc del tamaño requerido).
- **Detecta**: drivers de monitorización/sandbox (p. ej.Dbg, Sysmon driver).
- **Bypass**: renombrar el driver o filtrar el buffer devuelto.

### 6. Detección de hipervisores por CPUID (leaf `0x40000000`)
- **Dónde**: `0x29B0`–`0x2C38`; firmas: `VMwareVMware`, `VBoxVBoxVBox`, `KVMKVMKVM`,
  `XenVMMXenVMM`, `TCGTCGTCGTCG` (QEMU), `prl hyperv` (Parallels/Hyper-V).
- **Bypass**: hypervisor-level spoofing (CPUID masking en KVM/VMware config) o NOP del check.

### 7. Detección de Wine
- **Dónde**: `0x2BEF` — `GetProcAddress(ntdll, "wine_get_version")`.
- **Bypass**: ocultar el export (patch de la tabla de exports de ntdll en memoria).

### 8. `EnumWindows` + `GetWindowTextA` — enumeración de ventanas de analizadores
- **Dónde**: imports USER32 (ventanas de x64dbg/IDA/ProcMon).
- **Bypass**: renombrar ventanas o ejecutar headless.

### 9. VEH anti-tamper de cabeceras (`AddVectoredExceptionHandler(1, 0x1000)`)
- **Qué hace**: en cada excepción (¡los breakpoints software lanzan `INT3`!) valida MZ/PE
  del módulo. Un `INT3` en `.text` no altera el header, pero si el handler detecta headers
  parcheados → `ExitProcess(2)`.
- **Nota**: es también un truco anti-INT3 sutil: el VEH corre ANTES que el depurador
  reciba el evento y puede "tragar" excepciones.
- **Bypass**: breakpoints de hardware (DR0-DR3) o patch del handler.

### 10. Auto-CRC32 del `.text` (disco) como CLAVE de descifrado
- **Dónde**: `0x2e40` (disco) + `0x3080` (memoria); comparadores `0x2d90`/`0x2dc0`.
- **Efecto**: cualquier parche de 1 byte del `.text` (p.ej. para NOPear un check) cambia
  `g_key32` → el payload descifra a basura → el programa muere. **Parchear es autodestructivo.**
- **Bypass** (2 opciones):
  - (a) Parchear en MEMORIA y recalcular/actualizar `.data+0xb38` y `.data+0xb3c` con el
    nuevo CRC tras cada parcheo (la clave se deriva del ARCHIVO, el check de memoria es
    una global más — ambas son escribibles).
  - (b) No parchear nada: instrumentar externamente (ver #13).

### 11. Re-cifrado anti-dump del bytecode (capa 2)
- **Dónde**: `0x38C1`–`0x3ADA`; seed = `PID ^ heap ^ rdtsc ^ data_size ^ magic`.
- **Efecto**: un dump de memoria del heap muestra bytecode cifrado con keystream aleatorio.
- **Bypass**: el bytecode plano está en el ARCHIVO (capa 1, descifrable estáticamente —
  `scripts/decrypt_blkcode.py`); o tracer de un breakpoint en `0x4390` (fetch).

### 12. Hilo VM oculto + presupuesto de 200M instrucciones
- **Dónde**: `NtCreateThreadEx(..., 0x7280, ...)` + límite `0x0BEBC200` en `ctx+0xD0`.
- **Efecto**: (a) el hilo principal termina y el VM sigue; (b) loops ofuscados "infinitos"
  matan el presupuesto → halt silencioso anti-emulación.
- **Bypass**: instrumentar el contador (`ctx+0xD0`) o emular el bytecode por software.

### 13. VM de registros + remap + trace-hash
- **Dónde**: intérprete `0x4390`; cadenas de hash en cada instrucción (`ctx+0xC8`,
  opcodes `0x03`–`0x05`).
- **Efecto**: no existe código x86 de la lógica de licencia; además, alterar el flujo
  (saltarse instrucciones con breakpoints) cambia el hash de traza final.
- **Bypass**: no hay que alterar el flujo — con el bytecode plano + el desensamblador
  (`scripts/disasm_vm.py`) la lógica se lee estáticamente.

## Resumen de estrategia de análisis (lo que funcionó)

1. **Puro análisis estático de la imagen** — el binario nunca se ejecutó en esta investigación.
2. Recuperar las 440 funciones de `.pdata` y desensamblar con capstone + resolución de IAT.
3. Leer `main` (0x1090) → cadena de inicialización → localizar `0x3740`.
4. Replicar la derivación de clave (todos los ingredientes son bytes del propio archivo).
5. Descifrar capa 1 en Python → bytecode plano → desensamblar con las tablas del propio binario.
6. La capa 2 (anti-dump) queda irrelevante: el plaintext de interés ya estaba en el archivo.

**Conclusión**: el esquema protege contra *ejecución y dumping*, no contra *lectura*.
Para un adversario con el binario en la mano, el coste de ruptura es O(horas), no O(meses):
la totalidad del "secreto" (recurso RCDATA, bytes de cabecera, CRC del propio texto) es
públicamente computable.
