createFuncS crypt32, CryptHashCertificate2, 28

HMOD crypt32, <CRYPT32.dll>

createFunc? cabinet, _CreateDecompressor@12, '#40'
createFunc? cabinet, _Decompress@24, '#43'
createFunc? cabinet, _CloseDecompressor@4, '#45'

HMOD cabinet, <Cabinet.dll>

createFuncS kernel32, VirtualAlloc, 16
createFuncS kernel32, GetLastError, 0
createFuncS kernel32, ExitProcess, 4
createFuncS kernel32, VirtualFree, 12

HMOD kernel32, <KERNEL32.dll>

createFuncS bcrypt, BCryptCloseAlgorithmProvider, 8
createFuncS bcrypt, BCryptGenerateSymmetricKey, 28
createFuncS bcrypt, BCryptOpenAlgorithmProvider, 16
createFuncS bcrypt, BCryptDecrypt, 40

HMOD bcrypt, <bcrypt.dll>

createFuncS ntdllp, RtlInitUnicodeString, 8
createFuncS ntdllp, LdrLoadDll, 16
createFuncS ntdllp, LdrGetProcedureAddress, 16
createFuncS ntdllp, RtlAllocateHeap, 12
createFuncS ntdllp, RtlFreeHeap, 12

HMOD ntdllp, <>

