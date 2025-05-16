createFunc? cabinet, Decompress, '#43'
createFunc? cabinet, CreateDecompressor, '#40'
createFunc? cabinet, CloseDecompressor, '#45'

HMOD cabinet, <Cabinet.dll>

createFunc kernel32, LocalAlloc
createFunc kernel32, ExitProcess
createFunc kernel32, FreeLibrary
createFunc kernel32, FormatMessageW
createFunc kernel32, LocalFree
createFunc kernel32, GetLastError

HMOD kernel32, <KERNEL32.dll>

createFunc user32, MessageBoxW

HMOD user32, <USER32.dll>

createFunc ntdllp, RtlFreeHeap
createFunc ntdllp, RtlPushFrame
createFunc ntdllp, RtlPopFrame
createFunc ntdllp, RtlGetFrame
createFunc ntdllp, ZwProtectVirtualMemory
createFunc ntdllp, RtlEqualUnicodeString
createFunc ntdllp, RtlAddVectoredExceptionHandler
createFunc ntdllp, RtlAppendUnicodeStringToString
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, LdrUnloadDll
createFunc ntdllp, RtlRemoveVectoredExceptionHandler
createFunc ntdllp, LdrAddRefDll
createFunc ntdllp, RtlImageNtHeaderEx
createFunc ntdllp, LdrEnumerateLoadedModules
createFunc ntdllp, RtlAppendUnicodeToString
createFunc ntdllp, swprintf_s
createFunc ntdllp, memset
createFunc ntdllp, NtClose
createFunc ntdllp, NtCreateSection
createFunc ntdllp, LdrGetDllHandle
createFunc ntdllp, NtQueryDirectoryFile
createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, RtlAllocateHeap
createFunc ntdllp, RtlGetCurrentPeb
createFunc ntdllp, NtOpenFile
createFunc ntdllp, RtlFreeUnicodeString
createFunc ntdllp, RtlDosPathNameToNtPathName_U_WithStatus
createFunc ntdllp, ZwUnmapViewOfSection
createFunc ntdllp, ZwSetContextThread
createFunc ntdllp, ZwMapViewOfSection
createFunc ntdllp, LdrGetProcedureAddress
createFunc ntdllp, memcpy
createFunc ntdllp, strcmp

HMOD ntdllp, <>

