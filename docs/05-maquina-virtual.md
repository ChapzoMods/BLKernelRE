# 05 — La máquina virtual "BLK" (BICODE)

BLKernel no ejecuta su lógica sensible como código x86: la compila a **bytecode de una VM
de registros custom** y la interpreta en un hilo dedicado. Documentamos la arquitectura
completa y un subconjunto amplio del ISA.

## 1. Especificación resumida

| Propiedad | Valor |
|---|---|
| Tipo | VM de registros (load/store a RAM explícita) |
| Registros | 16 × 64 bits, con **remap virtual→físico** (tabla en `ctx+0xA0`) |
| RAM | 128 KB (`0x20000`) con zonas fijas (ver `03-arquitectura.md` §5) |
| PC | offset en bytes dentro del bytecode (`ctx+0xB8`) |
| Flags | `ZF` (bit 0), `SF` (bit 1) en `ctx+0xB0` |
| Bytecode | 3 741 bytes, 816 instrucciones |
| ISA | 158 opcodes (`0x00`–`0x9D`), 155 handlers únicos |
| Dispatch | 2 niveles: clase (tamaño) → handler (semántica) |
| Presupuesto | 200 000 000 instrucciones máximo (`ctx+0xD0`) — anti-loop-infinito |
| Ejecución | hilo dedicado creado con `NtCreateThreadEx` + `ThreadHideFromDebugger` |

## 2. Fetch y descifrado on-the-fly

Cada byte del bytecode se lee XOR-eado con el keystream de la capa 2 (por bloque de 8):

```c
uint8_t fetch8(VMCTX* ctx, uint64_t addr) {
    if ((addr >> 3) != ctx->last_block) {
        ctx->last_block = addr >> 3;
        ctx->keystream  = bl_hash64((addr >> 3) * GOLDEN, ctx->seed);
    }
    return ctx->code[addr] ^ (uint8_t)(ctx->keystream >> ((addr & 7) * 8));
}
```

El intérprete valida `opcode < 0x9E` y `pc + len(instr) <= code_size` antes de ejecutar.

## 3. Formato de instrucción

```
[ opcode (1 byte) ][ operandos... ]
```

El tamaño lo fija la **clase** del opcode (tabla en `.rdata` RVA `0x1B7F0`, 158 bytes):

| Clase | Tamaño total | Formato de operandos | Nº opcodes |
|---|---|---|---|
| 0 | 1 B | (sin operandos) | 16 |
| 1 | 2 B | `rD` (1 byte) | 30 |
| 2 | 3 B | `rD, rS` (2 bytes) | 29 |
| 3 | 6 B | `rD, imm32` | 20 |
| 4 | 10 B | `rD, imm64` | 2 |
| 5 | 6 B | `rD, imm32` (variante de decode) | 28 |
| 6 | 7 B | `rD, imm32, rX` | 8 |
| 7 | 5 B | `imm32` (rel32 para saltos) | 21 |
| 8 | 5 B | `imm32` (variante) | 4 |

Los índices de registro pasan por el remap: `físico = reg_map[virtual & 0xF]`.
Todos los índices se enmascaran con `& 0xF` — sin OOB en el banco de registros.

## 4. Dispatch (2 niveles)

```
0x4390:  opcode = fetch8(pc)
         clase  = tabla_clases[opcode]         (.rdata 0x1B7F0)
         handler_size = stubs[clase]           (0x4497..0x44C1)
         decode operandos (fetch8 inmediato/reg/imm vía 0x4320/0x3ED0/0x4050)
         pc += tamaño
         ctx->trace_hash = chain(trace_hash, opcode, pc)   ← anti-tamper de trazado
         handler = tabla_handlers[opcode]      (.text RVA 0x6BD8, 158 dwords)
         jmp handler
```

## 5. ISA — semántica reconstruida (parcial)

Formato: opcode hex · mnemónico propuesto · semántica.

### Transferencia

| Op | Mnemónico | Semántica | Handler |
|---|---|---|---|
| `0x0C` | `MOV rD, imm64` | `regs[map[rD]] = imm64` | 0x4992 |
| `0x0D` | `MOV rD, imm32` | `regs[map[rD]] = imm32` | 0x49A7 |
| `0x0E` | `MOV rD, rS` | `regs[map[rD]] = regs[map[rS]]` | 0x49BC |
| `0x1D` | `LEA/LOAD addr` | dirección desde reg+imm32 | 0x4C51 |

### Aritmética/lógica (con actualización de ZF/SF)

| Op | Mnemónico | Semántica | Handler |
|---|---|---|---|
| `0x31` | `ADD rD, rS` | `rD += rS` · flags | 0x5183 |
| `0x58` | `CMP rD, imm32` | `rD - imm32` · flags | 0x5D8C |
| `0x41` | `TEST rD, rS` | `rD & rS` · flags | 0x5714 |
| `0x49` | `SHR rD, rS` | `rD >>= rS & 0x3F` · flags | 0x5928 |
| `0x50` | `SHL/ROL rD, cnt` | desplazamiento · flags | 0x5B6D |
| `0x92` | `HASH rD` | `rD = splitmix_final(rD)` | 0x67E0 |
| `0x7E` | `ADD [addr], rS` | `mem32/64[rbp] += reg` (bounds-check vs `ram_size-8`) | 0x6311 |
| `0x7F` | `SUB [addr], rS` | idem resta | 0x6342 |
| `0x80` | `XOR [addr], rS` | idem XOR | 0x6373 |
| `0x81` | `AND [addr], rS` | idem AND | 0x63A4 |
| `0x82`–`0x8x` | (familia ALU mem) | OR/NOT/SHL/SHR/ROL/ROR mem,reg | 0x63D5… |

### Control de flujo

| Op | Mnemónico | Semántica | Handler |
|---|---|---|---|
| `0x00` | `NOP / next` | avanza (target del dispatch) | 0x6B19 |
| `0x67` | `JNZ rel32` | si `ZF==0`: `pc += rel32` | 0x62EB |
| `0x66` | `JZ rel32` | si `ZF==1`: `pc += rel32` | 0x62A6 |
| `0x6A/0x72` | `JMP/Jcc` | salto (rel32) | 0x5FD0 |
| `0x6B/0x75` | `JMP/Jcc` | salto (variante) | 0x5FDC |
| `0x6E`–`0x77` | familia saltos | condicionales por flags/signo | 0x6034… |

### Anti-tamper de trazado (exclusivo de esta VM)

| Op | Semántica | Handler |
|---|---|---|
| `0x02` | syscall-ish `call [rip+...]` | 0x469C |
| `0x03` | `trace ^= pc; ctx->trace_hash = trace` | 0x46A7 |
| `0x04` | `trace ^= pc ^ GOLDEN` | 0x46BA |
| `0x05` | `trace = pc*3 ^ trace` | 0x46D6 |

El intérprete encadena `ctx->trace_hash` con cada instrucción ejecutada
(`0x4652`–`0x4688`): el hash de ejecución se puede validar al final — si un debugger
alteró el flujo ( breakpoints que saltan instrucciones ), el hash final no coincide.
Es una **traza criptográfica de ejecución** integrada en el bytecode.

> El listado completo opcode→handler está en `artifacts/vm_handler_map.txt`; el bytecode
> desensamblado con estas semánticas, en `artifacts/blk_disasm.txt`.

## 6. Inicio del bytecode (primeras instrucciones)

```
0000: 0a 10 00 00 00        INIT 0x10           ; setup: 16 registros?
0005: 0e 01 00              MOV  r01, r00
0008: 0c 02 ffffffffffffffff MOV  r02, 0xFFFFFFFFFFFFFFFF
0012: 41 01 02              TEST r01, r02
0015: 0d 03 00000000        MOV  r03, 0
001b: 57 01 03              op_57 r01, r03      ; (LOAD/CALL vm-helper)
001e: 67 0e29               JNZ  +0x0E29        ; → 0x0E48
0023: 0e 01 00              MOV  r01, r00
0026: 4e 01 20 00 00 00     op_4E r01, 0x20
002c: 0d 03 00000004        MOV  r03, 4
...
019e: 0c 06 25 23 22 84 e4 9c f2 cb   MOV r06, 0xCBF29CE484222325   ; FNV offset basis!
01d5: 0c 02 00 01 00 00 00 01 00 00   MOV r02, 0x100000001B3        ; FNV prime!
...
0221: 0c 02 9e 37 79 b9 79 37 9c      MOV r02, 0x9E3779B97F4A7C15   ; GOLDEN
023c: 0c 04 18 8a 25 32 ea 60 8a 8e   MOV r04, 0x8E8A60EA32258A18  ; mezcla custom
```

El programa VM implementa el chequeo de licencia: hashing FNV-1a de usuario/clave,
mezclas SplitMix64, comparación con la tabla del fingerprint (binding HWID) y la
ramificación final que decide si la carga continúa.

## 7. Cómo desensamblar el bytecode tú mismo

```bash
python3 scripts/decrypt_blkcode.py    # capa 1 → artifacts/blkcode_layer1.bin
python3 scripts/disasm_vm.py          #       → artifacts/blk_disasm.txt (816 instr.)
python3 scripts/vm_handlers.py        #       → artifacts/vm_handler_map.txt
```

El desensamblador usa las tablas reales del binario (clases en `.rdata:0x1B7F0`,
handlers en `.text:0x6BD8`), por lo que las longitudes de instrucción son exactas.
