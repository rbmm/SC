#include "stdafx.h"
#include <compressapi.h>
#include "zip.h"

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

HRESULT Unzip(
	_In_ LPCVOID CompressedData,
	_In_ SIZE_T CompressedDataSize,
	_Out_ PVOID* pUncompressedBuffer,
	_Out_ SIZE_T* pUncompressedDataSize,
	_Out_ void** pbuf /*= 0*/,
	_In_opt_ ULONG cbBefore /*= 0*/,
	_In_opt_ ULONG cbAfter /*= 0*/)
{
	if (!CompressedData)
	{
		if (pbuf && (cbBefore += cbAfter))
		{
			if (PVOID buf = LocalAlloc(LMEM_FIXED, cbBefore))
			{
				*pbuf = buf;

				return S_OK;
			}

			return STATUS_NO_MEMORY;
		}

		return STATUS_INVALID_PARAMETER_MIX;
	}

	ULONG dwError;
	COMPRESSOR_HANDLE DecompressorHandle;

	if (NOERROR == (dwError = BOOL_TO_ERROR(CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, 0, &DecompressorHandle))))
	{
		SIZE_T UncompressedBufferSize = 0;
		PVOID UncompressedBuffer = 0;
		PVOID buf = 0;

		while (ERROR_INSUFFICIENT_BUFFER == (dwError = BOOL_TO_ERROR(Decompress(
			DecompressorHandle, CompressedData, CompressedDataSize,
			UncompressedBuffer, UncompressedBufferSize, &UncompressedBufferSize))) && !buf)
		{
			if (!(buf = LocalAlloc(LMEM_FIXED, cbBefore + UncompressedBufferSize + cbAfter)))
			{
				dwError = ERROR_OUTOFMEMORY;
				break;
			}

			UncompressedBuffer = (PBYTE)buf + cbBefore;
		}

		if (NOERROR == dwError)
		{
			if (buf)
			{
				if (pbuf) *pbuf = buf;
				*pUncompressedDataSize = UncompressedBufferSize;
				*pUncompressedBuffer = UncompressedBuffer;
				buf = 0;
			}
			else
			{
				dwError = ERROR_INTERNAL_ERROR;
			}
		}

		if (buf)
		{
			LocalFree(buf);
		}

		CloseDecompressor(DecompressorHandle);
	}

	return HRESULT_FROM_WIN32(dwError);
}