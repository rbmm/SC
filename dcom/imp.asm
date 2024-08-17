createFunc  advapi32, OpenProcessToken
createFunc  advapi32, CreateProcessAsUserW
createFunc  advapi32, DuplicateToken
createFunc  advapi32, OpenThreadToken

HMOD advapi32, <ADVAPI32.dll>

createFunc  KERNEL32, DuplicateHandle
createFunc  KERNEL32, GetModuleHandleW
createFunc  KERNEL32, IsDebuggerPresent
createFunc  KERNEL32, ExpandEnvironmentStringsW
createFunc  KERNEL32, VirtualProtect
createFunc  KERNEL32, SetEvent
createFunc  KERNEL32, WaitForSingleObject
createFunc  KERNEL32, OpenProcess

HMOD KERNEL32, <KERNEL32.dll>

createFunc  ntdllp, NtSetInformationThread
createFunc  ntdllp, RtlInitUnicodeString
createFunc  ntdllp, RtlImageDirectoryEntryToData
createFunc  ntdllp, ZwSetInformationThread
createFunc  ntdllp, NtClose
createFunc  ntdllp, ZwQueryValueKey
createFunc  ntdllp, ZwOpenKey
createFunc  ntdllp, memset
createFunc  ntdllp, LdrLoadDll
createFunc  ntdllp, LdrGetProcedureAddress
createFunc  ntdllp, __chkstk
createFunc  ntdllp, strcmp

HMOD ntdllp, <>

