# 08 — Análisis dinámico (detonación controlada en GitHub Actions)

La fase estática de esta investigación **nunca ejecutó el binario** (ver
`06-anti-analisis.md` §Resumen). El análisis dinámico se realiza como **detonación
controlada** en un runner efímero de GitHub Actions, opt-in manual, sin secretos y con
permisos vacíos. Este documento define el protocolo, las predicciones extraídas del
análisis estático y los resultados.

## 1. Diseño del entorno

| Propiedad | Valor | Motivo |
|---|---|---|
| Runner | `windows-latest` (VM efímera de Azure) | El objetivo es un PE x64 |
| Disparador | `workflow_dispatch` **manual** con confirmación explícita | Evitar detonaciones accidentales en cada push |
| Permisos del `GITHUB_TOKEN` | `{}` (ninguno) | Un payload hostil no puede leer ni persistir nada del repo |
| Secretos expuestos | Ninguno | Idem |
| Red | Salida de internet disponible en el runner (por diseño de GitHub) | El monitor la snapshot-ea antes/después |
| Timeout | 10 minutos de trabajo | Contención de coste y de efectos |
| Retención | Logs y artefactos de la ejecución únicamente | Reproducibilidad |

El flujo completo está en `.github/workflows/dynamic-analysis.yml`.

## 2. Predicciones del análisis estático (qué DEBERÍA observarse)

Estas son las hipótesis verificables que la detonación debe confirmar o refutar — el valor
científico de la fase dinámica:

| # | Predicción | Fundamento estático |
|---|---|---|
| P1 | **Muerte silenciosa inmediata** (sin salida, exit code 1/2): los runners de GitHub para Windows corren sobre **Hyper-V/Azure**, y la suite `0x2940` detecta hipervisores por CPUID leaf `0x40000000` (firmas `prl hyperv` / Hyper-V) → `0x1180(1)` | `03-arquitectura.md` §1; `06-anti-analisis.md` #6 |
| P2 | Si sobreviviera a P1 (anti-VM bypasseado): salida de uso (`argc` incorrecto) y exit `2` | `03-arquitectura.md` §1 (`main`) |
| P3 | Con `--check usuario clave` arbitrarios: la VM debería ejecutar y **fallar la validación** (el fingerprint del runner no coincide con `.fptable` #1) — salida controlada, sin crash | `04-criptografia.md` §6; `03-arquitectura.md` §4 |
| P4 | El CRC de la imagen mapeada del exe en el runner difiere del de la muestra original si el loader aplica reubicaciones (ASLR activo) → potencial desvío temprano | `03-arquitectura.md` §1 (0x3080) |
| P5 | Ningún proceso hijo persistente, ninguna persistencia, ningún artefacto en disco fuera de %TEMP% (la lógica es un validador de licencia, no un dropper — según el bytecode desensamblado) | `05-maquina-virtual.md` §6 |

> La predicción P1 es el resultado esperado más probable y, de confirmarse, constituye en
> sí misma una evidencia dinámica de la batería anti-VM: BLKernel **se niega a correr en
> nube** — dato útil para defensores (los sandbox de detonación en nube verán lo mismo).

## 3. Protocolo de detonación

```
T-1  snapshot A: lista de procesos, conexiones TCP (Get-NetTCPConnection),
      hash de BLKernel.exe, número de archivos de %TEMP% y del directorio de trabajo
T0   ejecutar:  .\BLKernel.exe                 (sin argumentos)
      luego:    .\BLKernel.exe --check tester AAAA-BBBB-CCCC-DDDD
      (timeout por comando: 60 s; captura de stdout/stderr y ExitCode)
T+1  snapshot B: idem A
diff  A vs B → informe (nuevos procesos, nuevas conexiones, archivos nuevos)
```

El runner ejecuta con la cuenta de servicio del agente (contexto elevado en Windows
runner), condición que además **ejercita el manifest `requireAdministrator`** (P2 de
BLK-0DAY-04).

## 4. Cómo ejecutarlo

1. Pestaña **Actions** → flujo **"Fase 3 — Análisis dinámico (detonación controlada)"**.
2. **Run workflow** → seleccionar rama `main`.
3. Parámetro `detonar`:
   - `false` (por defecto): solo prepara y verifica el entorno (sin ejecutar el binario).
   - `true`: ejecuta el protocolo completo de detonación de §3.
4. Al terminar, descargar el artefacto `informe-dinamico` con el diff de snapshots.

> ⚠️ La detonación ejecuta un binario desconocido en infraestructura de GitHub. El flujo
> está diseñado con `permissions: {}` y cero secretos precisamente para que un payload
> hostil no obtenga nada del repositorio. Úsalo solo si aceptas ese riesgo.

## 5. Resultados

> **PENDIENTE — primera ejecución.** Esta sección se completará con la tabla de resultados
> tras el primer `Run workflow` con `detonar=true`:

| Ejecución | Fecha | Comando | Exit code | Salida | Δ procesos | Δ red | Δ disco | P# confirmada |
|---|---|---|---|---|---|---|---|---|
| #1 | — | (sin args) | — | — | — | — | — | — |
| #2 | — | `--check tester …` | — | — | — | — | — | — |

Formato de informe que genera el workflow (los guiones bajos se sustituyen):

```
[PREDICCIÓN] P1 muerte silenciosa por detección de hipervisor: CONFIRMADA/REFUTADA
[EXIT] code=_
[STDOUT] _
[SNAPSHOT-DIFF] procesos: +_ / tcp: +_ / temp: +_
```

## 6. Alternativas de detonación local (sin GitHub)

- **VM dedicada**: Hyper-V/VMware con snapshot previo; usar breakpoints de hardware
  (DR0–DR3) para esquivar el VEH anti-INT3 (`06-anti-analisis.md` #9).
- **Wine sobre Linux**: detectable por `wine_get_version` (`06-anti-analisis.md` #7) —
  útil precisamente para validar esa técnica.
- **Emulación del bytecode**: dado que toda la lógica de licencia vive en la VM
  documentada, la vía más productiva no es detonar el exe sino **emular su bytecode**
  con un intérprete propio usando las tablas de este repositorio
  (`artifacts/vm_handler_map.txt` + `artifacts/blk_disasm.txt`) — sin riesgo alguno y con
  trazabilidad total (incluso es la forma natural de construir un generador de licencias
  de prueba para verificar la semántica del ISA).
