createFunc  advapi32, ImpersonateLoggedOnUser
createFunc  advapi32, CredFree
createFunc  advapi32, LogonUserW
createFunc  advapi32, CredMarshalCredentialW

HMOD advapi32, <ADVAPI32.dll>

createFunc  crypt32, CryptHashCertificate2
createFunc  crypt32, PFXImportCertStore
createFunc  crypt32, CertOpenStore
createFunc  crypt32, CertGetCertificateContextProperty
createFunc  crypt32, CertAddCertificateContextToStore
createFunc  crypt32, CertEnumCertificatesInStore
createFunc  crypt32, CertFreeCertificateContext
createFunc  crypt32, CertCloseStore

HMOD crypt32, <CRYPT32.dll>

createFunc  kernel32, GetLastError
createFunc  kernel32, ExitProcess
createFunc  kernel32, GetCommandLineW
createFunc  kernel32, FormatMessageW
createFunc  kernel32, GetModuleHandleW
createFunc  kernel32, LocalFree
createFunc  kernel32, CreateFileW
createFunc  kernel32, LocalAlloc

HMOD kernel32, <KERNEL32.dll>

createFunc  user32, MessageBoxW

HMOD user32, <USER32.dll>

createFunc  ncrypt, NCryptOpenKey
createFunc  ncrypt, NCryptDeleteKey
createFunc  ncrypt, NCryptOpenStorageProvider
createFunc  ncrypt, NCryptFreeObject

HMOD ncrypt, <ncrypt.dll>

createFunc  ntdllp, NtClose
createFunc  ntdllp, NtReadFile
createFunc  ntdllp, NtQueryInformationFile
createFunc  ntdllp, wcschr
createFunc  ntdllp, RtlInitUnicodeString
createFunc  ntdllp, LdrLoadDll
createFunc  ntdllp, LdrGetProcedureAddress
createFunc  ntdllp, __chkstk

HMOD ntdllp, <>

