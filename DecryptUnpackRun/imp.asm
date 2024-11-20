createFunc  crypt32, CryptHashCertificate2

HMOD crypt32, <CRYPT32.dll>

createFunc  cabinet, Decompress
createFunc  cabinet, CreateDecompressor
createFunc  cabinet, CloseDecompressor

HMOD cabinet, <Cabinet.dll>

createFunc  kernel32, VirtualAlloc
createFunc  kernel32, GetLastError
createFunc  kernel32, VirtualFree
createFunc  kernel32, ExitProcess

HMOD kernel32, <KERNEL32.dll>

createFunc  bcrypt, BCryptCloseAlgorithmProvider
createFunc  bcrypt, BCryptOpenAlgorithmProvider
createFunc  bcrypt, BCryptGenerateSymmetricKey
createFunc  bcrypt, BCryptDecrypt

HMOD bcrypt, <bcrypt.dll>

createFunc  ntdllp, LdrLoadDll
createFunc  ntdllp, LdrGetProcedureAddress
createFunc  ntdllp, RtlAllocateHeap
createFunc  ntdllp, RtlFreeHeap
createFunc  ntdllp, RtlInitUnicodeString

HMOD ntdllp, <>

