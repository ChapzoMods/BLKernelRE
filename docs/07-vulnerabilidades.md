# 07 — Vulnerabilidades 0-day

> **Divulgación responsable.** Este documento describe vulnerabilidades descubiertas
> durante la investigación con fines **defensivos** (ver `README.md` §Uso responsable).
> Los procedimientos se describen a nivel algorítmico para permitir la verificación y la
> remediación; no se distribuye un exploit armado listo para usar. Se recomienda a los
> afectados aplicar las mitigaciones de §9 antes de la divulgación pública.

## 0. Metodología de evaluación

- Severidad cualitativa (Crítica/Alta/Media/Baja) + vector **CVSS 3.1 estimado** (marcado
  con `≈`; los valores exactos dependen del entorno de despliegue).
- Mapeo **CWE** por vulnerabilidad.
- Dos escenarios de amenaza considerados:
  - **E-local**: el atacante tiene acceso de escritura al archivo en la máquina víctima.
  - **E-distribución**: el atacante redistribuye una copia modificada (supply-chain /
    ingeniería social) y la víctima la ejecuta voluntariamente.
- Contexto: BLKernel.exe se ejecuta **siempre con privilegios de administrador**
  (manifest `requireAdministrator`), lo que amplifica el impacto de todo lo que sigue.

---

## BLK-0DAY-01 — Hijacking total del payload 🔴 CRÍTICA

**Título**: Sustitución del payload cifrado por uno malicioso que se ejecuta con
privilegios de administrador, debido a que la clave de descifrado es estática y 100 %
derivable del propio binario.

**CWE**: CWE-321 (*Use of Hard-coded Cryptographic Key*), CWE-494 (*Download of Code
Without Integrity Check*)

**CVSS 3.1**:
- E-distribución: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` ≈ **9.6**
- E-local: `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` ≈ **8.8**

### Descripción

La confidencialidad del payload `.blkcode` descansa en una clave que **no contiene ningún
secreto externo**: todos sus ingredientes son bytes legibles del propio archivo (ver
`04-criptografia.md` §2). En consecuencia, un atacante puede **cifrar su propio payload**
con la misma clave y BLKernel lo montará y ejecutará sin ninguna objeción: el único
"control" es que el header descifrado tenga la magic correcta y tamaños dentro de rango.

### Raíz técnica — ingredientes de la clave (todos públicos)

| Ingrediente | Ubicación en el archivo | Valor (muestra analizada) |
|---|---|---|
| Recurso `RT_RCDATA` id 7, bytes 0–1 | `.rsrc` (16 bytes totales) | `0x1C22` |
| Primer byte de `.fptable` #1 | RVA 0x2D000 (file offset 0x28C00) | `0xEB` |
| Byte del DOS header `e_res[0]` | file offset 0x28 | `0x37` |
| Constante fija | inmediato en `0x1b60` | `0x628688F0` |
| **→ `key64`** | | **`0x37EB1C22628688F0`** |
| `g_key32` = CRC32 raw del `.text` **del archivo en disco** | file offset 0x400, 0x16600 bytes | `0xC00DDD8F` |

El punto decisivo: **`g_key32` hashea el `.text` del archivo, no el `.blkcode`**. Un
atacante que solo sustituya la sección `.blkcode` **no altera ningún ingrediente de la
clave** — la clave sigue siendo válida para su payload forjado.

### Cadena de explotación (nivel algorítmico)

1. **Derivar la clave** de una copia legítima (exactamente lo que hace
   `scripts/decrypt_blkcode.py`: key64, `crc32_raw(.text disco)`,
   `state = bl_hash64(g_key32, key64)` = `0x9EEEA1B36DEF62F8`).
2. **Construir un payload** con el formato esperado:
   `magic = 0x770F89DA30A70374`, `code_size ≤ 0x3FFFFF`, `data_size ≤ 0x20000`,
   `0x18 + code_size + data_size ≤ 0x24C8`, seguido de bytecode VM propio.
3. **Escribir bytecode VM** usando el ISA documentado (`05-maquina-virtual.md`). El opcode
   `0x02` (handler `0x469C`) ejecuta `call [rip+X]` — **invocación de APIs nativas desde el
   bytecode** — por lo que el payload forjado puede llamar directamente a APIs de Win32
   (p. ej. `CreateProcess`, `VirtualAlloc` + copia + salto) sin escribir un solo byte de
   código x86 en el binario.
4. **Cifrar** con el mismo stream cipher (la operación es simétrica):
   `cifrado[i] = claro[i] ^ splitmix_final(i*GOLDEN ^ state ^ 0x24C8)`.
5. **Sobrescribir** la sección en el file offset `0x26600` (respetando el tamaño raw
   `0x2600` con relleno). Redistribuir o sustituir localmente.

Al ejecutarse, el manifest `requireAdministrator` eleva los privilegios, la cadena de
auto-verificación pasa intacta (`.text` sin tocar) y la VM interpreta el bytecode del
atacante **en contexto administrativo**.

### Prerrequisitos

- E-distribución: que la víctima ejecute la copia modificada (ningún otro requisito).
- E-local: escritura sobre el exe (normalmente ya implica privilegios, por lo que el valor
  real de este vector es la **redistribución**).

### Impacto

Ejecución remota de código con privilegios de administrador, persistencia, robo de
credenciales, movimiento lateral — todo ello **con la apariencia de un producto legítimo**
y eludiendo la atribución: el código malicioso viaja cifrado dentro de un contenedor cuyo
mecanismo de "protección" fue diseñado justamente para ocultar payloads.

### Evidencia en este repo

- Derivación y descifrado reproducibles: `scripts/decrypt_blkcode.py` (salida con los
  checks del header nativo satisfechos).
- Formato del payload y bounds-checks: `04-criptografia.md` §4.
- Opcode de escape a nativo: `05-maquina-virtual.md` §5 (op `0x02`).
- Payload original extraído: `artifacts/blkcode_layer1.bin`.

### Mitigación

- Clave **externa** al binario (nunca derivable del propio archivo): p. ej. clave entregada
  por el servidor de licencias tras verificar el binario con `WinVerifyTrust`.
- Autenticar el payload con **HMAC-SHA256** (o firmarlo) con una clave que no viaje en el
  exe; verificar antes de ejecutar.
- Renunciar a `requireAdministrator` (§BLK-0DAY-04): un validador de licencia no necesita
  contexto elevado.

---

## BLK-0DAY-02 — TOCTOU en la auto-verificación de integridad 🔴 ALTA

**CWE**: CWE-367 (*Time-of-check Time-of-use Race Condition*)

**CVSS 3.1** (E-local): `AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` ≈ **4.7** — severidad
directa moderada, pero **habilita parcheo runtime indetectable** que amplifica 01/05.

### Descripción

La integridad se auto-verifica de tres formas (ver `03-arquitectura.md` §1):

1. `0x2e40`: abre **su propio exe en disco** con `FILE_SHARE_READ|FILE_SHARE_WRITE|
   FILE_SHARE_DELETE` y calcula `g_key32 = CRC32(.text del archivo)` → `.data+0xb38`.
2. `0x3080`: calcula el CRC de la **imagen mapeada en memoria** → `.data+0xb3c`.
3. `0x2d90` / `0x2dc0`: re-verifican disco-vs-`b38` y memoria-vs-`b3c` en puntos posteriores.

Tres defectos de diseño:

- **(a) La verificación es self-referencial**: los valores "esperados" (`b38`, `b3c`) viven
  en `.data`, una sección **escribible**. Un atacante que parchea la memoria recalcula y
  reescribe esos dos dwords y el checker vuelve a sonreír.
- **(b) Race TOCTOU real**: el archivo se mantiene compartido en escritura durante toda la
  ejecución. Entre la lectura de `0x2e40` y la re-verificación de `0x2d90` existe una
  ventana en la que un segundo proceso puede **sustituir el archivo en disco** (rename/
  reemplazo con los permisos del handle compartido): la clave se derivó de un archivo y se
  verifica contra otro — o viceversa, según el orden de las escrituras del atacante.
- **(c) El CRC no está autenticado**: incluso sin carrera, un CRC32 sin firmar no
  constituye evidencia de procedencia (colisiones dirigidas trivial con `crc32` elegido).

### Explotación (esbozo)

- Parchear el `.text` mapeado en memoria (NOP de un check), recalcular el CRC de la imagen
  parcheada y escribirlo en `.data+0xb3c`; opcionalmente parchear también `0x2dc0` para
  saltarse la comparación. El VEH anti-tamper (`0x1000`) solo inspecciona **cabeceras**
  MZ/PE, no el cuerpo del código (ver `06-anti-analisis.md` #9).
- Alternativamente, sustituir el archivo en disco durante la ventana (b) para que la
  re-verificación lea exactamente el contenido que el atacante quiere.

### Impacto

El "candado anti-parcheo" (que además **es parte de la clave de descifrado**, ver
`06-anti-analisis.md` #10) es bypasseable sin detonar la autodestrucción. Esto elimina la
única barrera que el esquema oponía a la instrumentación/debugging del binario en
ejecución, y permite entrega de contenido modificado "verificado".

### Mitigación

- Derivar la clave ANTES de mapear la imagen y desde un handle **sin share-write** (o de
  una copia snapshot bloqueada).
- Guardar los valores esperados en memoria de solo lectura firmada (o verificar contra un
  hash firmado embebido y firmado el binario).
- Usar `WinVerifyTrust` sobre el propio archivo: el Authenticode cubre el hash del archivo
  completo — cualquier sustitución queda detectada por el sistema, no por lógica propia.

---

## BLK-0DAY-03 — El payload no tiene autenticación criptográfica 🟠 ALTA

**CWE**: CWE-353 (*Missing Support for Integrity or Confidentiality Checks*),
CWE-345 (*Insufficient Verification of Data Authenticity*)

### Descripción

El payload viaja **cifrado pero no autenticado**: el stream cipher SplitMix64
(`04-criptografia.md` §3) es un XOR de keystream **sin MAC ni tag de autenticidad**. La
única validación que recibe el payload tras descifrar es estructural: magic reconocida y
tamaños dentro de rango. Eso confunde "descifra a algo auto-consistente" con "provino del
autor legítimo".

Dos consecuencias:

- **Forjabilidad total** (condición necesaria de BLK-0DAY-01): quien conoce la clave —
  tras este RE, todo el mundo — produce payloads válidos.
- **Maleabilidad clásica de XOR**: incluso sin conocer la clave, un bit volteado en el
  ciphertext se traduce en el mismo bit volteado en el bytecode en claro. Sin tag, el
  receptor no puede detectar la manipulación (solo el fallo estructural si rompe el
  formato).

### Impacto

Es el multiplicador que convierte la clave estática (01) en ejecución arbitraria, y la
maleabilidad permite "editar" payloads existentes (p. ej. invertir la rama de decisión de
la licencia en el bytecode) sin recomputar nada.

### Mitigación

- Sustituir el XOR casero por un **AEAD** (AES-256-GCM / ChaCha20-Poly1305) con clave no
  contenida en el binario: cifrado + integridad + autenticidad en una primitiva estándar.
- Si se mantiene el formato actual, añadir HMAC-SHA256 sobre `magic||code||data` con clave
  externa y verificarlo **antes** de mapear nada.

---

## BLK-0DAY-04 — Binario sin firma digital + `requireAdministrator` 🟠 MEDIA

**CWE**: CWE-494 (*Download of Code Without Integrity Check*)

**CVSS 3.1** (E-distribución, standalone): `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` ≈ **7.5**
— y actúa como **amplificador directo** de 01 (la cadena completa hereda su severidad).

### Descripción

Dos decisiones de empaquetado independientes y sumadas:

1. **Sin firma Authenticode** (`DIRECTORY_SECURITY` vacío): ni el sistema ni el usuario
   pueden distinguir una copia legítima de una sustituida; la única fricción es el aviso
   UAC de "editor desconocido", que el flujo normal de elevación enseña igualmente para el
   binario original.
2. **`requireAdministrator` en el manifest**: el proceso arranca **siempre** elevado. Un
   validador de licencias es un lector de strings + hashing; no existe justificación de
   privilegio. Cualquier explotación exitosa (incluida 01) **hereda el contexto
   administrativo sin esfuerzo adicional**.

### Impacto

- Supply-chain trivial: la sustitución del binario es indistinguible a nivel de sistema.
- Violación directa del principio de mínimo privilegio para todo el producto.
- Combinado con 01: RCE admin "out of the box".

### Mitigación

- Firmar el binario (y exigir verificación en la propia lógica: `WinVerifyTrust` del
  propio módulo antes de derivar claves o montar el VM).
- Quitar `requireAdministrator`; usar `asInvoker` y elevar solo si alguna operación
  concreta lo exige (y documentar cuál).

---

## BLK-0DAY-05 — Anti-análisis enumerable y bypasseable (13 vectores) 🟡 MEDIA

**CWE**: CWE-693 (*Protection Mechanism Failure*)

### Descripción

Las 13+ técnicas anti-análisis (catálogo completo en `06-anti-analisis.md`) se
descubren **estáticamente** con solo leer el binario: strings de firmas de hipervisores en
`.rdata` (`VMwareVMware`, `VBoxVBoxVBox`, …), imports evidentes
(`IsDebuggerPresent`, `EnumWindows`, `CreateToolhelp32Snapshot`), resolución dinámica de
`ntdll` visible en `.rdata:0x1A348+`, y constantes leet legibles. Todas tienen bypass
documentado en este mismo repositorio.

### Impacto

- **Falsa sensación de seguridad** para el autor: la protección real del payload (la
  clave) era el eslabón débil, y el resto era teatro costoso (13 checks que penalizan
  arranque y fiabilidad).
- Para el defensor: el perfil de imports/strings es una **huella YARA trivial** — la
  "protección" delata al binario más de lo que lo oculta.

### Mitigación

Aceptar que la ofuscación no es seguridad: reducir la batería a los controles que
aporten valor real y mover la garantía a criptografía autenticada (01/03) y firma (04).

---

## BLK-0DAY-06 — Semilla anti-dump regenerable con un tracer simple 🟡 BAJA

**CWE**: CWE-330 (*Use of Insufficiently Random Values*)

### Descripción

La capa 2 "anti-dump" re-cifra el bytecode en memoria con
`seed = PID ^ heap ^ rdtsc ^ data_size ^ magic` (`04-criptografia.md` §5). El diseño se
autoderrota: el propio intérprete (`0x4390`) recalcúa el keystream en cada fetch, así que
un **único breakpoint** en el fetch captura el bytecode en claro de todo el programa; y el
seed en sí es observable (materiales de entrada públicos o medibles con un tracer).

### Impacto

Nulo como vector de ataque (no otorga ejecución ni escritura); su único propósito era
impedir el volcado y se anula con instrumentación mínima. Relevancia: demuestra que el
esquema protege contra *ejecución y dumping*, no contra *análisis* (conclusión de
`06-anti-analisis.md`).

### Mitigación

Ninguna práctica: la protección anti-dump de interpretado siempre es recuperable por el
propio intérprete. Redirigir el esfuerzo a la autenticación del payload.

---

## 8. Matriz resumen

| ID | Severidad | CWE primario | Prerrequisito mínimo | Impacto final |
|---|---|---|---|---|
| 01 | 🔴 Crítica | CWE-321 | Copia del exe + víctima que ejecute la sustitución | RCE como administrador |
| 02 | 🔴 Alta | CWE-367 | E-local (escritura/debug) | Bypass del anti-tamper; parcheo indetectable |
| 03 | 🟠 Alta | CWE-353 | — (condición de 01) | Forja/maleabilidad de payloads |
| 04 | 🟠 Media | CWE-494 | Distribución de copia | Supply-chain; privilegio innecesario |
| 05 | 🟡 Media | CWE-693 | — | Falsa seguridad; huella detectable |
| 06 | 🟡 Baja | CWE-330 | Tracer local | Dump del bytecode |

## 9. Mitigaciones consolidadas (ordenadas por ROI)

| # | Mitigación | Vulnerabilidades que cierra |
|---|---|---|
| 1 | AEAD (AES-GCM/ChaCha20-Poly1305) con clave **externa** al binario | 01, 03 |
| 2 | HMAC-SHA256 sobre el payload verificado antes de montar el VM | 01, 03 |
| 3 | `WinVerifyTrust` del propio exe antes de derivar claves + firmar el binario | 01, 02, 04 |
| 4 | Eliminar `requireAdministrator` (→ `asInvoker`) | 01, 04 (impacto) |
| 5 | Derivar clave de un snapshot bloqueado sin `share-write` | 02 |
| 6 | Mover los valores de integridad esperados a memoria RO firmada | 02 |
| 7 | Poda de la batería anti-análisis a controles con valor real | 05 |

## 10. Cronología de divulgación

| Fecha | Evento |
|---|---|
| 2026-09-10 | Análisis completo y ruptura del cifrado (fase estática) |
| 2026-09-11 | Documentación de vulnerabilidades y publicación del método en este repositorio |
| — | Notificación al autor/proveedor del esquema *(pendiente: canal de contacto desconocido — la muestra no contiene datos del autor: sin PDB, sin manifest de contacto, sin strings de empresa)* |
| — | Fecha límite de remediación propuesta: **90 días** desde la notificación |
| — | Publicación de detalles amplificados (PoCs ejecutables) tras remediación o vencimiento del plazo |

> Si eres el autor del esquema BLK y quieres coordinar la divulgación, abre un issue en
> este repositorio. Las mitigaciones de §9 están pensadas para ser implementables en
> días, no meses.
