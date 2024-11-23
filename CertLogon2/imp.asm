createFunc  advapi32, ImpersonateLoggedOnUser

HMOD advapi32, <ADVAPI32.dll>

createFunc  crypt32, PFXImportCertStore
createFunc  crypt32, CertEnumCertificatesInStore
createFunc  crypt32, CertGetCertificateContextProperty
createFunc  crypt32, CertCloseStore
createFunc  crypt32, CertFreeCertificateContext
createFunc  crypt32, CryptDecodeObjectEx
createFunc  crypt32, CryptImportPublicKeyInfoEx2

HMOD crypt32, <CRYPT32.dll>

createFunc  kernel32, ExitProcess
createFunc  kernel32, LocalAlloc
createFunc  kernel32, GetCommandLineW
createFunc  kernel32, GetLastError
createFunc  kernel32, GetModuleHandleW
createFunc  kernel32, FormatMessageW
createFunc  kernel32, LocalFree

HMOD kernel32, <KERNEL32.dll>

createFunc  Secur32, LsaConnectUntrusted
createFunc  Secur32, LsaLogonUser
createFunc  Secur32, LsaFreeReturnBuffer
createFunc  Secur32, LsaDeregisterLogonProcess
createFunc  Secur32, LsaLookupAuthenticationPackage

HMOD Secur32, <Secur32.dll>

createFunc  user32, MessageBoxW

HMOD user32, <USER32.dll>

createFunc  ncrypt, NCryptSignHash
createFunc  ncrypt, NCryptDeleteKey
createFunc  ncrypt, BCryptDestroyKey
createFunc  ncrypt, BCryptVerifySignature
createFunc  ncrypt, NCryptOpenKey
createFunc  ncrypt, NCryptFreeObject
createFunc  ncrypt, NCryptExportKey
createFunc  ncrypt, NCryptImportKey
createFunc  ncrypt, NCryptSetProperty
createFunc  ncrypt, NCryptFinalizeKey
createFunc  ncrypt, NCryptGetProperty
createFunc  ncrypt, BCryptGenRandom
createFunc  ncrypt, NCryptOpenStorageProvider

HMOD ncrypt, <ncrypt.dll>

createFunc  ntdllp, NtSetInformationThread
createFunc  ntdllp, wcschr
createFunc  ntdllp, RtlDosPathNameToNtPathName_U_WithStatus
createFunc  ntdllp, _snwprintf
createFunc  ntdllp, RtlInitString
createFunc  ntdllp, NtClose
createFunc  ntdllp, NtReadFile
createFunc  ntdllp, NtQueryInformationFile
createFunc  ntdllp, RtlFreeUnicodeString
createFunc  ntdllp, NtOpenFile
createFunc  ntdllp, __chkstk
createFunc  ntdllp, RtlInitUnicodeString
createFunc  ntdllp, LdrLoadDll
createFunc  ntdllp, LdrGetProcedureAddress
createFunc  ntdllp, memset

HMOD ntdllp, <>

