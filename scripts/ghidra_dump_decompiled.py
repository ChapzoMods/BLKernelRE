# Ghidra post-script (Jython 2) — BLKernelRE
# Vuelca la decompilación C de TODAS las funciones del programa importado.
#
# Uso (headless):
#   analyzeHeadless <proj_dir> BLKernelRE -import BLKernel/BLKernel.exe \
#       -scriptPath scripts -postScript ghidra_dump_decompiled.py artifacts/ghidra_decompiled.c \
#       -analysisTimeoutPerFile 900
#
# NOTA: sintaxis Python 2 (Jython) — sin f-strings.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0] if len(args) > 0 else 'ghidra_decompiled.c'

monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
f = open(out_path, 'w')

header = (
    '// Decompilacion Ghidra de BLKernel.exe\n'
    '// Generado por ghidra_dump_decompiled.py (post-script headless)\n'
    '// Nota: los nombres de funcion son sinteticos (binario sin simbolos);\n'
    '// para los RVAs clave ver docs/03-arquitectura.md (inventario de funciones).\n'
    '// La logica de licencia NO aparece aqui: vive en el bytecode de la VM\n'
    '// (ver docs/05-maquina-virtual.md y artifacts/blk_disasm.txt).\n\n'
)
f.write(header)

count = 0
failed = 0
for func in fm.getFunctions(True):
    res = ifc.decompileFunction(func, 60, monitor)
    if res.decompileCompleted():
        f.write('/' * 74 + '\n')
        f.write('// FUNC %s @ %s\n' % (func.getName(), func.getEntryPoint()))
        f.write('/' * 74 + '\n')
        f.write(res.getDecompiledFunction().getC())
        f.write('\n\n')
        count += 1
    else:
        failed += 1

f.close()
print('Descompiladas %d funciones (%d fallidas) -> %s' % (count, failed, out_path))
