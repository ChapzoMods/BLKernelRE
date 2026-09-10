# BLKernelRE — Ingeniería Inversa Completa de BLKernel.exe

> **Investigación de seguridad / RE de punta a punta** — el binario fue descifrado por completo,
> incluyendo su máquina virtual custom, su esquema criptográfico y su payload embebido.
> Repo mantenido por **ChapzoMods**.

[![CI - Análisis Estático](https://github.com/ChapzoMods/BLKernelRE/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/ChapzoMods/BLKernelRE/actions/workflows/static-analysis.yml)
[![CI - Ghidra Headless](https://github.com/ChapzoMods/BLKernelRE/actions/workflows/ghidra-decompile.yml/badge.svg)](https://github.com/ChapzoMods/BLKernelRE/actions/workflows/ghidra-decompile.yml)
[![CI - Análisis Dinámico](https://github.com/ChapzoMods/BLKernelRE/actions/workflows/dynamic-analysis.yml/badge.svg)](https://github.com/ChapzoMods/BLKernelRE/actions/workflows/dynamic-analysis.yml)

---

## 📌 Resumen ejecutivo

**BLKernel.exe** es un **loader/protector de payload basado en virtualización** (esquema "BLK").
Todo el código sensible no existe como código x86: vive cifrado en la sección `.blkcode` y se
ejecuta dentro de una **máquina virtual de registros custom** (158 opcodes) cuyo bytecode se
**re-cifra en memoria con un keystream no determinista en cada ejecución** (anti-dump).
La carga está protegida además con una batería de 13+ técnicas anti-análisis y un candado
de integridad basado en **auto-CRC32** del propio `.text` leído desde el disco.

**Resultado de esta investigación: la protección está completamente rota.** La clave de
descifrado es 100 % derivable del propio binario (sin secretos externos), por lo que el
payload se extrajo estáticamente, se desensambló su bytecode (816 instrucciones VM) y se
documentó toda la arquitectura. Como consecuencia se identificaron **vulnerabilidades 0-day**
(documentadas en `docs/07-vulnerabilidades.md`), siendo la más grave el
**hijacking total del payload**: cualquiera que conozca la clave (pública tras este RE)
puede sustituir el payload cifrado y BLKernel lo ejecutará **con privilegios de administrador**.

### Identificación de la muestra

| Campo | Valor |
|---|---|
| Nombre | `BLKernel.exe` |
| Tipo | PE32+ (x86-64), consola, GUI=None |
| Tamaño | 171 520 bytes (167 KB) |
| MD5 | `2c92a70abc6179cc7a4b1eb24be028f0` |
| SHA-1 | `c42c91bdb56adc83e03c5df50740974e390ec5a5` |
| SHA-256 | `7b0136c6402a3bf6c04268e2f31d98fb83ebddf4fafd6ef92785202f9898d89c` |
| Compilador | MSVC (Rich header presente, CRT moderno) |
| TimeDateStamp | 2026-09-10 01:59:55 UTC |
| Firma digital | ❌ Ausente |
| Manifest | `requireAdministrator` (auto-elevación UAC) |
| Mitigaciones | ASLR ✔ · DEP/NX ✔ · CFG ✔ · HighEntropyVA ✔ · SEH NO (x64) |
| Secciones | 9 (incluye 3 custom: `.blkcode`, `.fptable` ×2) |

### 🔓 Lo que se rompió en esta investigación

| # | Componente | Estado |
|---|---|---|
| 1 | Capa 1 de cifrado de `.blkcode` (SplitMix64 stream cipher) | **Rota** — clave replicada en Python (`scripts/decrypt_blkcode.py`) |
| 2 | Derivación de clave (recurso RCDATA + `.fptable` + `e_res` + CRC32 de `.text`) | **Totalmente reconstruida** |
| 3 | Formato del payload (`magic` + `code_size` + `data_size`) | **Extraído**: 3 741 bytes de bytecode + 5 648 bytes de imagen RAM |
| 4 | VM de registros (158 opcodes, dispatch de 2 niveles, remap de registros) | **Documentada** (`docs/05-maquina-virtual.md`) |
| 5 | Bytecode VM | **Desensamblado** — 816 instrucciones (`artifacts/blk_disasm.txt`) |
| 6 | Cifrado anti-dump de opcodes (keystream por bloque `hash(i*GOLDEN ^ seed)`) | **Explicado y neutralizado** (el bytecode plano capa-1 es directamente legible) |
| 7 | Batería anti-análisis (13+ técnicas) | **Catalogada con bypass** (`docs/06-anti-analisis.md`) |
| 8 | Fingerprint HWID (username, MAC, RAM, CPU, firmware UEFI) | **Mapeado** (`docs/03-arquitectura.md`) |
| 9 | Modo licencia `--check <user> <key>` (FNV-1a + SplitMix64) | **Identificado** en el bytecode |

---

## 📁 Estructura del repositorio

```
BLKernelRE/
├── README.md                      ← este archivo
├── docs/
│   ├── 01-resumen-ejecutivo.md    ← hallazgos de alto nivel
│   ├── 02-analisis-estatico.md    ← PE, secciones, imports, recursos, strings
│   ├── 03-arquitectura.md         ← cadena de arranque + fingerprint HWID + winlogon probe
│   ├── 04-criptografia.md         ← ★ ruptura completa del cifrado (paso a paso)
│   ├── 05-maquina-virtual.md      ← arquitectura VM, tabla de opcodes, fetch cifrado
│   ├── 06-anti-analisis.md        ← 13+ técnicas y cómo bypassearlas
│   ├── 07-vulnerabilidades.md     ← ★ vulnerabilidades 0-day encontradas
│   └── 08-analisis-dinamico.md    ← resultados de GitHub Actions
├── scripts/                       ← herramientas de análisis (Python, reproducibles)
│   ├── analyze_pe.py              ← dump completo de cabeceras/imports/recursos
│   ├── extract_strings.py         ← strings ASCII+UTF16 con contexto RVA
│   ├── analyze_sections.py        ← hexdump de recursos, .blkcode, .fptable, .data
│   ├── disasm_all.py              ← desensamblado anotado (IAT + strings)
│   ├── extract_func.py            ← vuelca funciones concretas del desensamblado por RVA
│   ├── xref_resolve.py            ← resolvedor de referencias RIP-relativas
│   ├── global_xrefs.py            ← mapa de variables globales del VM ctx
│   ├── vm_handlers.py             ← extracción de la tabla de handlers del VM
│   ├── decrypt_blkcode.py         ← ★ descifrador del payload (rompe la capa 1)
│   ├── disasm_vm.py               ← desensamblador del bytecode VM
│   └── ghidra_dump_decompiled.py  ← post-script Ghidra: decompilación C batch
├── artifacts/
│   ├── blkcode_layer1.bin         ← payload descifrado (header + bytecode + RAM)
│   ├── blk_disasm.txt             ← bytecode VM desensamblado (816 instrucciones)
│   ├── vm_handler_map.txt         ← mapa opcode → handler RVA
│   ├── res_RT_RCDATA_7.bin        ← recurso de clave (16 bytes)
│   └── res_RT_MANIFEST_1.bin      ← manifest (requireAdministrator) auto-extraído
├── sample/
│   └── BLKernel.exe.zip           ← muestra original (password: "infected")
└── .github/workflows/
    ├── static-analysis.yml        ← CI: re-ejecuta todo el pipeline estático
    ├── ghidra-decompile.yml       ← CI: Ghidra headless → decompilación C de todo el binario
    └── dynamic-analysis.yml       ← CI: ejecución controlada en Windows runner + monitoreo
```

---

## ⚡ Reproducir el análisis localmente

```bash
# 1. Desempaquetar la muestra (password: infected)
7z x sample/BLKernel.exe.zip -oBLKernel/

# 2. Pipeline estático completo (salidas → artifacts/)
python3 scripts/analyze_pe.py
python3 scripts/extract_strings.py > artifacts/strings_out.txt
python3 scripts/analyze_sections.py
python3 scripts/disasm_all.py
python3 scripts/xref_resolve.py
python3 scripts/global_xrefs.py

# 3. Romper el cifrado del payload (★)
python3 scripts/decrypt_blkcode.py
#    → artifacts/blkcode_layer1.bin  (bytecode VM en claro)

# 4. Desensamblar el bytecode de la VM
python3 scripts/vm_handlers.py     # → artifacts/vm_handler_map.txt
python3 scripts/disasm_vm.py
#    → artifacts/blk_disasm.txt
```

Requisitos: `python3`, `pip install pefile capstone`.

Convención de rutas: los scripts aceptan la ruta de la muestra como **primer argumento**
o vía la variable `BLK_SAMPLE` (por defecto `BLKernel/BLKernel.exe`); escriben sus
salidas en `artifacts/` (configurable con `BLK_OUT`).

El mismo pipeline (y más) se ejecuta automáticamente en **GitHub Actions** — ver pestaña
*Actions*. Los resultados de la ejecución dinámica en Windows quedan como *artifacts* descargables.

---

## 🔎 Hallazgos de vulnerabilidad (resumen)

| ID | Severidad | Título |
|---|---|---|
| **BLK-0DAY-01** | 🔴 Crítica | Hijacking total del payload: clave de descifrado estática y extraíble del propio binario → ejecución de código arbitrario con privilegios admin |
| **BLK-0DAY-02** | 🔴 Alta | TOCTOU en la auto-verificación de integridad (se lee del disco tras estar mapeado; `FILE_SHARE_WRITE\|DELETE`) |
| **BLK-0DAY-03** | 🟠 Alta | El payload no tiene autenticación criptográfica (sin MAC/firma) — integridad = solo "clave correcta" |
| **BLK-0DAY-04** | 🟠 Media | Binario sin firma digital + `requireAdministrator` → sustitución/supply-chain trivial |
| **BLK-0DAY-05** | 🟡 Media | Detección de VM/debugger enumerable y bypasseable (13 vectores documentados) |
| **BLK-0DAY-06** | 🟡 Baja | Semilla "no determinista" reutilizable: el keystream anti-dump se regenera con un tracer simple |

Detalle, evidencia y pasos de reproducción: [`docs/07-vulnerabilidades.md`](docs/07-vulnerabilidades.md).

---

## ⚖️ Uso responsable

Esta investigación se publica con fines **defensivos y educativos** (interés legítimo del
propietario de la muestra). El material incluye herramientas para comprender el binario,
no para atacar sistemas de terceros. Si eres el autor del software protegido con este
esquema: las vulnerabilidades documentadas permiten construir mitigaciones concretas
(firmar el payload, usar HMAC con clave externa, verificar el binario con WinVerifyTrust
antes de derivar claves, etc.).

## 📄 Licencia

Análisis y scripts: **MIT**. La muestra pertenece a su autor original y se incluye
únicamente como objeto de estudio (comprimida con contraseña, convención de análisis de malware).
