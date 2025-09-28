createFunc crypt32, CryptHashCertificate2

HMOD crypt32, <CRYPT32.dll>

createFunc? cabinet, CloseDecompressor, '#45'
createFunc? cabinet, Decompress, '#43'
createFunc? cabinet, CreateDecompressor, '#40'

HMOD cabinet, <Cabinet.dll>

createFunc kernel32, ExitProcess
createFunc kernel32, GetLastError
createFunc kernel32, VirtualAlloc
createFunc kernel32, VirtualFree

HMOD kernel32, <KERNEL32.dll>

createFunc bcrypt, BCryptDecrypt
createFunc bcrypt, BCryptCloseAlgorithmProvider
createFunc bcrypt, BCryptGenerateSymmetricKey
createFunc bcrypt, BCryptOpenAlgorithmProvider

HMOD bcrypt, <bcrypt.dll>

createFunc ntdllp, RtlAllocateHeap
createFunc ntdllp, RtlUnicodeToUTF8N
createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, LdrGetProcedureAddress
createFunc ntdllp, RtlFreeHeap

HMOD ntdllp, <>

