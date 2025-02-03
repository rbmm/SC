createFuncS kernel32, VirtualProtect, 16
createFuncS kernel32, LoadLibraryW, 4

HMOD kernel32, <KERNEL32.dll>

createFuncS secur32, SeciAllocateAndSetCallFlags, 8

HMOD secur32, <Secur32.dll>

createFuncS ntdllp, RtlImageDirectoryEntryToData, 16
createFuncS ntdllp, RtlInitUnicodeString, 8
createFuncS ntdllp, LdrLoadDll, 16
createFuncS ntdllp, LdrGetProcedureAddress, 16

HMOD ntdllp, <>

