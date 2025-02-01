createFuncS advapi32, LogonUserW, 24
createFuncS advapi32, CredFree, 4
createFuncS advapi32, ImpersonateLoggedOnUser, 4
createFuncS advapi32, CredMarshalCredentialW, 12

HMOD advapi32, <ADVAPI32.dll>

createFuncS crypt32, CryptHashCertificate2, 28
createFuncS crypt32, PFXImportCertStore, 12
createFuncS crypt32, CertAddCertificateContextToStore, 16
createFuncS crypt32, CertGetCertificateContextProperty, 16
createFuncS crypt32, CertEnumCertificatesInStore, 8
createFuncS crypt32, CertOpenStore, 20
createFuncS crypt32, CertFreeCertificateContext, 4
createFuncS crypt32, CertCloseStore, 8

HMOD crypt32, <CRYPT32.dll>

createFuncS kernel32, GetLastError, 0
createFuncS kernel32, LocalAlloc, 8
createFuncS kernel32, GetCommandLineW, 0
createFuncS kernel32, FormatMessageW, 28
createFuncS kernel32, GetModuleHandleW, 4
createFuncS kernel32, LocalFree, 4
createFuncS kernel32, ExitProcess, 4

HMOD kernel32, <KERNEL32.dll>

createFuncS user32, MessageBoxW, 16

HMOD user32, <USER32.dll>

createFuncS ncrypt, NCryptDeleteKey, 8
createFuncS ncrypt, NCryptFreeObject, 4
createFuncS ncrypt, NCryptOpenKey, 20
createFuncS ncrypt, NCryptOpenStorageProvider, 12

HMOD ncrypt, <ncrypt.dll>

createFuncS ntdllp, NtClose, 4
createFuncS ntdllp, RtlFreeUnicodeString, 4
createFuncS ntdllp, NtQueryInformationFile, 20
createFuncC ntdllp, wcschr
createFuncS ntdllp, NtOpenFile, 24
createFuncS ntdllp, RtlDosPathNameToNtPathName_U_WithStatus, 16
createFuncS ntdllp, NtReadFile, 36
createFuncS ntdllp, RtlInitUnicodeString, 8
createFuncS ntdllp, LdrLoadDll, 16
createFuncS ntdllp, LdrGetProcedureAddress, 16

HMOD ntdllp, <>

