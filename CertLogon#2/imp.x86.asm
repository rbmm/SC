createFuncS advapi32, ImpersonateLoggedOnUser, 4

HMOD advapi32, <ADVAPI32.dll>

createFuncS crypt32, CryptDecodeObjectEx, 32
createFuncS crypt32, CryptImportPublicKeyInfoEx2, 20
createFuncS crypt32, CertFreeCertificateContext, 4
createFuncS crypt32, CertGetCertificateContextProperty, 16
createFuncS crypt32, CertEnumCertificatesInStore, 8
createFuncS crypt32, PFXImportCertStore, 12
createFuncS crypt32, CertCloseStore, 8

HMOD crypt32, <CRYPT32.dll>

createFuncS kernel32, LocalAlloc, 8
createFuncS kernel32, LocalFree, 4
createFuncS kernel32, GetLastError, 0
createFuncS kernel32, GetModuleHandleW, 4
createFuncS kernel32, FormatMessageW, 28
createFuncS kernel32, GetCommandLineW, 0
createFuncS kernel32, ExitProcess, 4

HMOD kernel32, <KERNEL32.dll>

createFuncS Secur32, LsaConnectUntrusted, 4
createFuncS Secur32, LsaLookupAuthenticationPackage, 12
createFuncS Secur32, LsaLogonUser, 56
createFuncS Secur32, LsaDeregisterLogonProcess, 4
createFuncS Secur32, LsaFreeReturnBuffer, 4

HMOD Secur32, <Secur32.dll>

createFuncS user32, MessageBoxW, 16

HMOD user32, <USER32.dll>

createFuncS ncrypt, NCryptDeleteKey, 8
createFuncS ncrypt, BCryptDestroyKey, 4
createFuncS ncrypt, BCryptVerifySignature, 28
createFuncS ncrypt, NCryptOpenStorageProvider, 12
createFuncS ncrypt, NCryptOpenKey, 20
createFuncS ncrypt, NCryptFreeObject, 4
createFuncS ncrypt, NCryptExportKey, 32
createFuncS ncrypt, NCryptImportKey, 32
createFuncS ncrypt, NCryptSetProperty, 20
createFuncS ncrypt, NCryptFinalizeKey, 8
createFuncS ncrypt, NCryptGetProperty, 24
createFuncS ncrypt, BCryptGenRandom, 16
createFuncS ncrypt, NCryptSignHash, 32

HMOD ncrypt, <ncrypt.dll>

createFuncS ntdllp, RtlFreeUnicodeString, 4
createFuncS ntdllp, NtOpenFile, 24
createFuncS ntdllp, RtlDosPathNameToNtPathName_U_WithStatus, 16
createFuncS ntdllp, NtQueryInformationFile, 20
createFuncS ntdllp, NtReadFile, 36
createFuncS ntdllp, NtClose, 4
createFuncS ntdllp, RtlInitString, 8
createFuncC ntdllp, _snwprintf
createFuncC ntdllp, wcschr
createFuncS ntdllp, NtSetInformationThread, 16
createFuncS ntdllp, RtlInitUnicodeString, 8
createFuncS ntdllp, LdrLoadDll, 16
createFuncS ntdllp, LdrGetProcedureAddress, 16
createFuncC ntdllp, memset

HMOD ntdllp, <>

