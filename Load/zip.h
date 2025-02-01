#pragma once

HRESULT Unzip(
	_In_ LPCVOID CompressedData,
	_In_ SIZE_T CompressedDataSize,
	_Out_ PVOID* pUncompressedBuffer,
	_Out_ SIZE_T* pUncompressedDataSize,
	_Out_ void** pbuf = 0,
	_In_opt_ ULONG cbBefore = 0,
	_In_opt_ ULONG cbAfter = 0);