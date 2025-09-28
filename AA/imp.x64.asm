createFunc kernel32, ExitProcess

HMOD kernel32, <KERNEL32.dll>

createFunc ntdllp, LdrGetProcedureAddress
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, RtlInitUnicodeString

HMOD ntdllp, <>

createFunc ole32, CoCreateInstance
createFunc ole32, CoInitializeEx
createFunc ole32, CoUninitialize

HMOD ole32, <ole32.dll>

