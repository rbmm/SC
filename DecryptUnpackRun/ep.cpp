#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

#include <compressapi.h>

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

//## -> #
//#. -> *
//#: -> %

BOOL UnEscape(_Inout_ PWSTR str)
{
	PWSTR buf = str;
	WCHAR c;
	do
	{
		if ('#' == (c = *str++))
		{
			switch (c = *str++)
			{
			case '.':
				c = '*';
				break;
			case ':':
				c = '%';
				break;
			case '#':
				break;
			default:
				return FALSE;
			}
		}

		*buf++ = c;

	} while (c);

	return TRUE;
}

NTSTATUS CreateAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE secret, _In_ ULONG cb)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, _YW(BCRYPT_AES_ALGORITHM), 0, 0)))
	{
		status = BCryptGenerateSymmetricKey(hAlgorithm, phKey, 0, 0, secret, cb, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

HRESULT Unzip(_In_ LPCVOID CompressedData,
	_In_ ULONG CompressedDataSize,
	_Out_ PVOID* pUncompressedBuffer,
	_Out_ ULONG* pUncompressedDataSize)
{
	ULONG dwError;
	COMPRESSOR_HANDLE DecompressorHandle;

	if (NOERROR == (dwError = BOOL_TO_ERROR(CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, 0, &DecompressorHandle))))
	{
		SIZE_T UncompressedBufferSize = 0;
		PVOID UncompressedBuffer = 0;

		while (ERROR_INSUFFICIENT_BUFFER == (dwError = BOOL_TO_ERROR(Decompress(
			DecompressorHandle, CompressedData, CompressedDataSize,
			UncompressedBuffer, UncompressedBufferSize, &UncompressedBufferSize))) && !UncompressedBuffer)
		{
			if (!(UncompressedBuffer = VirtualAlloc(0, UncompressedBufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
			{
				dwError = ERROR_OUTOFMEMORY;
				break;
			}
		}

		if (NOERROR == dwError)
		{
			if (UncompressedBuffer)
			{
				*pUncompressedDataSize = (ULONG)UncompressedBufferSize;
				*pUncompressedBuffer = UncompressedBuffer, UncompressedBuffer = 0;
			}
			else
			{
				dwError = ERROR_INTERNAL_ERROR;
			}
		}

		if (UncompressedBuffer)
		{
			VirtualFree(UncompressedBuffer, 0, MEM_RELEASE);
		}

		CloseDecompressor(DecompressorHandle);
	}

	return HRESULT_FROM_WIN32(dwError);
}

void WINAPI ep(PEB* peb, PBYTE pbIn, ULONG cb)
{
	CPP_FUNCTION;

	PUNICODE_STRING CommandLine = &peb->ProcessParameters->CommandLine;
	if (ULONG cch = CommandLine->Length / sizeof(WCHAR))
	{
		PWSTR psz = CommandLine->Buffer, password = 0;

		do
		{
			if ('*' == *psz++)
			{
				if (password)
				{
					ULONG len = RtlPointerToOffset(password, psz);
					*--psz = 0;

					if (UnEscape(password))
					{
						RtlUnicodeToUTF8N((char*)password, len, &len, password, len);

						BCRYPT_KEY_HANDLE hKey;
						UCHAR secret[32];
						ULONG s = sizeof(secret);
						if (CryptHashCertificate2(_YW(BCRYPT_SHA256_ALGORITHM), 0, 0,
							(PBYTE)password, len, secret, &s))
						{
							*psz = '*';
							__movsw((PWORD)CommandLine->Buffer, (PWORD)psz, 1 + cch);
							CommandLine->Length = (USHORT)(cch*sizeof(WCHAR));

							if (0 <= CreateAesKey(&hKey, secret, s))
							{
								union {
									FARPROC fp;
									PVOID pv = 0;
								};

								s = 0;
								if (PBYTE pb = new BYTE[cb])
								{
									if (0 <= BCryptDecrypt(hKey, pbIn, cb, 0, 0, 0, pb, cb, &cb, BCRYPT_BLOCK_PADDING))
									{
										Unzip(pb, cb, &pv, &cb);
									}

									delete[] pb;

									if (pv)
									{
										fp();
										VirtualFree(pv, 0, MEM_RELEASE);
									}
								}
							}
						}

					}
					break;
				}
				else
				{
					password = psz;
				}
			}

		} while (--cch);
	}

	ExitProcess(0);
}
