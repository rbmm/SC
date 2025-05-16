createFunc? cabinet, _Decompress@24, '#43'
createFunc? cabinet, _CreateDecompressor@12, '#40'
createFunc? cabinet, _CloseDecompressor@4, '#45'

HMOD cabinet, <Cabinet.dll>

createFuncS kernel32, LocalAlloc, 8
createFuncS kernel32, ExitProcess, 4
createFuncS kernel32, FreeLibrary, 4
createFuncS kernel32, FormatMessageW, 28
createFuncS kernel32, LocalFree, 4
createFuncS kernel32, GetLastError, 0

HMOD kernel32, <KERNEL32.dll>

createFuncS user32, MessageBoxW, 16

HMOD user32, <USER32.dll>

createFuncS ntdllp, RtlFreeHeap, 12
createFuncS ntdllp, RtlPushFrame, 4
createFuncS ntdllp, RtlPopFrame, 4
createFuncS ntdllp, RtlGetFrame, 0
createFuncS ntdllp, ZwProtectVirtualMemory, 20
createFuncS ntdllp, RtlEqualUnicodeString, 12
createFuncS ntdllp, RtlAddVectoredExceptionHandler, 8
createFuncS ntdllp, ZwSetContextThread, 8
createFuncS ntdllp, RtlAppendUnicodeStringToString, 8
createFuncS ntdllp, LdrUnloadDll, 4
createFuncS ntdllp, RtlRemoveVectoredExceptionHandler, 4
createFuncS ntdllp, LdrAddRefDll, 8
createFuncS ntdllp, RtlImageNtHeaderEx, 20
createFuncS ntdllp, LdrEnumerateLoadedModules, 12
createFuncS ntdllp, RtlWow64EnableFsRedirection, 4
createFuncS ntdllp, RtlAppendUnicodeToString, 8
createFuncC ntdllp, swprintf_s
createFuncC ntdllp, memcpy
createFuncS ntdllp, NtClose, 4
createFuncS ntdllp, NtCreateSection, 28
createFuncS ntdllp, LdrGetDllHandle, 16
createFuncS ntdllp, NtQueryDirectoryFile, 44
createFuncS ntdllp, RtlInitUnicodeString, 8
createFuncS ntdllp, RtlAllocateHeap, 12
createFuncS ntdllp, RtlGetCurrentPeb, 0
createFuncS ntdllp, NtOpenFile, 24
createFuncS ntdllp, RtlFreeUnicodeString, 4
createFuncS ntdllp, RtlDosPathNameToNtPathName_U_WithStatus, 16
createFuncS ntdllp, ZwUnmapViewOfSection, 8
createFuncS ntdllp, LdrLoadDll, 16
createFuncS ntdllp, ZwMapViewOfSection, 40
createFuncS ntdllp, LdrGetProcedureAddress, 16
createFuncC ntdllp, memset

HMOD ntdllp, <>

