# 01 — Resumen ejecutivo

## 1. Qué es BLKernel.exe

BLKernel.exe es un **loader/protector de payloads basado en virtualización** ("esquema BLK",
que su propio código llama internamente *BICODE* por la constante leet `0x5A17C0DE`). No
contiene su lógica sensible como código x86: esa lógica vive **cifrada** en la sección
custom `.blkcode` (entropía 7.914) y se ejecuta dentro de una **máquina virtual de
registros propia** con 158 opcodes, interpretada en un hilo dedicado oculto al depurador.

Su función observable es la validación de licencias con **binding por hardware (HWID)**:

```
BLKernel.exe --check <usuario> <clave>
```

El binario exige privilegios de administrador (`requireAdministrator`), calcula un
fingerprint del equipo (usuario, MAC, RAM, CPU, variables UEFI) y delega la decisión de
licencia al bytecode del VM. El manifiesto lo presenta como "BLKernel" v1.0.0.0, sin firma
digital, compilado con MSVC el 2026-09-10.

## 2. Metodología

La investigación fue **100 % estática**: el binario jamás se ejecutó. El flujo que se
siguió, y que este repositorio reproduce con herramientas propias, fue:

1. **Triage PE** — cabeceras, secciones anómalas (`.blkcode`, `.fptable` ×2), imports
   reveladores, recursos (RCDATA id 7 = material de clave) → `docs/02-analisis-estatico.md`
2. **Reconstrucción de la cadena de arranque** desde `main` (0x1090) → localización del
   montaje del VM (0x3740) → `docs/03-arquitectura.md`
3. **Ruptura del cifrado** — derivación de clave 100 % reproducible desde el propio
   archivo + replicación en Python del stream cipher SplitMix64 → `docs/04-criptografia.md`
4. **Extracción del payload** — 3 741 bytes de bytecode VM + 5 648 bytes de imagen RAM,
   con todos los checks del header nativo satisfechos.
5. **Documentación de la VM** — arquitectura, dispatch, ISA parcial y tabla completa de
   158 opcodes → handlers → `docs/05-maquina-virtual.md`
6. **Catálogo anti-análisis** — 13+ técnicas con su bypass → `docs/06-anti-analisis.md`

## 3. Resultados clave

| Hallazgo | Dato |
|---|---|
| Clave de descifrado (`key64`) | `0x37EB1C22628688F0` — derivada de bytes públicos del propio archivo |
| Clave secundaria (`g_key32`) | `0xC00DDD8F` — CRC32 "raw" del `.text` leído del disco |
| Magic del payload | `0x770F89DA30A70374` |
| Bytecode extraído | 3 741 bytes → **816 instrucciones** VM desensambladas |
| Imagen RAM inicial | 5 648 bytes (datos + constantes FNV-1a/SplitMix64) |
| ISA de la VM | 158 opcodes (0x00–0x9D), 155 handlers únicos, 9 clases de tamaño |
| Funciones nativas analizadas | 440 (recuperadas vía `.pdata`) |
| Técnicas anti-análisis | 13+ catalogadas, todas con bypass documentado |
| Fingerprint HWID | 6 fuentes de datos mapeadas (usuario, MAC, RAM, CPU, UEFI, PID/heap) |

La conclusión central: **la protección no contiene ningún secreto externo**. Todo el
material clave (recurso RCDATA, bytes de cabecera, primer byte de `.fptable`, CRC del
propio texto) es públicamente computable por cualquiera que posea una copia del binario.
Para un adversario con el archivo en la mano, el coste de ruptura es de horas, no de meses.

## 4. Vulnerabilidades 0-day

Como consecuencia de la ruptura se identificaron **seis vulnerabilidades**, encabezadas por
el **hijacking total del payload**: cualquiera puede sustituir el payload cifrado y
BLKernel lo ejecutará con privilegios de administrador (la clave es estática y extraíble,
y el payload carece de autenticación criptográfica).

| ID | Severidad | Título |
|---|---|---|
| BLK-0DAY-01 | 🔴 Crítica | Hijacking total del payload (clave estática + sin MAC) |
| BLK-0DAY-02 | 🔴 Alta | TOCTOU en la auto-verificación de integridad |
| BLK-0DAY-03 | 🟠 Alta | El payload no tiene autenticación criptográfica |
| BLK-0DAY-04 | 🟠 Media | Binario sin firma + `requireAdministrator` |
| BLK-0DAY-05 | 🟡 Media | Anti-análisis enumerable y bypasseable (13 vectores) |
| BLK-0DAY-06 | 🟡 Baja | Semilla anti-dump regenerable con un tracer simple |

Evidencia, prerrequisitos, CVSS y mitigaciones: **[`docs/07-vulnerabilidades.md`](07-vulnerabilidades.md)**.

## 5. Orden de lectura recomendado

1. Este documento (panorama).
2. `02-analisis-estatico.md` — qué se ve desde fuera.
3. `03-arquitectura.md` — cómo arranca y se protege.
4. `04-criptografia.md` — ★ cómo se rompe.
5. `05-maquina-virtual.md` — qué hay dentro del payload.
6. `06-anti-analisis.md` — por qué el análisis costó lo que costó (y cómo se evitó).
7. `07-vulnerabilidades.md` — ★ el impacto de todo lo anterior.
8. `08-analisis-dinamico.md` — detonación controlada en CI.

## 6. Limitaciones

- La **semántica del ISA es parcial**: la tabla completa de 158 opcodes está mapeada
  (handler por opcode), pero la interpretación semántica se documentó para el subconjunto
  que interviene en el flujo de licencia (~40 opcodes). El listado completo de
  instrucciones está disponible en `artifacts/blk_disasm.txt` para extenderla.
- No se ejecutó el binario en la fase estática; el análisis dinámico está diseñado como
  detonación controlada en CI (ver `08-analisis-dinamico.md`) y en VM aislada.
- Se analizó **una única muestra** (SHA-256
  `7b0136c6402a3bf6c04268e2f31d98fb83ebddf4fafd6ef92785202f9898d89c`); no se descartan
  variantes con cambios en offsets o constantes.
