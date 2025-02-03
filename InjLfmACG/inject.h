#pragma once

struct __declspec(novtable) IReadData
{
	virtual NTSTATUS NTAPI Read(_In_ PVOID buf, _In_ ULONG cb) = 0;
};

NTSTATUS NTAPI InjectACG(
	_In_ HANDLE hProcess,
	_In_ IReadData* pData,
	_In_ ULONG cbData,
	_Out_ PVOID* pImageBase,
	_Out_ PBOOL StatusFromRemote);

NTSTATUS NTAPI InjectACG(
	_In_ HANDLE hProcess,
	_In_ const void* pvData,
	_In_ ULONG cbData,
	_Out_ PVOID* pImageBase,
	_Out_ PBOOL StatusFromRemote);

NTSTATUS NTAPI RemoteUnloadDll(_In_ HANDLE hProcess, _In_ PVOID RemoteBase);