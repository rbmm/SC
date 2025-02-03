#pragma once

NTSTATUS NTAPI InjectDLL(_In_ HANDLE hProcess, _In_ const void* pvData, _In_ ULONG cbData);
