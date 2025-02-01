createFunc kernel32, VirtualProtect
createFunc kernel32, LoadLibraryW

HMOD kernel32, <KERNEL32.dll>

createFunc secur32, SeciAllocateAndSetCallFlags

HMOD secur32, <Secur32.dll>

createFunc ntdllp, RtlImageDirectoryEntryToData
createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, LdrGetProcedureAddress

HMOD ntdllp, <>

