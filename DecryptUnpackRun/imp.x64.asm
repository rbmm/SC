createFunc crypt32, CryptHashCertificate2

HMOD crypt32, <CRYPT32.dll>

createFunc? cabinet, CreateDecompressor, '#40'
createFunc? cabinet, Decompress, '#43'
createFunc? cabinet, CloseDecompressor, '#45'

HMOD cabinet, <Cabinet.dll>

createFunc kernel32, VirtualAlloc
createFunc kernel32, GetLastError
createFunc kernel32, ExitProcess
createFunc kernel32, VirtualFree

HMOD kernel32, <KERNEL32.dll>

createFunc bcrypt, BCryptCloseAlgorithmProvider
createFunc bcrypt, BCryptGenerateSymmetricKey
createFunc bcrypt, BCryptOpenAlgorithmProvider
createFunc bcrypt, BCryptDecrypt

HMOD bcrypt, <bcrypt.dll>

createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, LdrGetProcedureAddress
createFunc ntdllp, RtlAllocateHeap
createFunc ntdllp, RtlFreeHeap

HMOD ntdllp, <>

