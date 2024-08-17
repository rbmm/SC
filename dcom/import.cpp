#include "stdafx.h"

#include <delayimp.h>

struct __declspec(novtable) WalkImport
{
	union {
		PIMAGE_IMPORT_DESCRIPTOR piid;
		PCImgDelayDescr pdid;
		PVOID pv;
	};

	virtual USHORT DirectoryEntry() = 0;
	virtual ULONG Name(ULONG s) = 0;
	virtual ULONG Next() = 0;
	virtual ULONG rvaINT() = 0;
	virtual ULONG rvaIAT() = 0;

	PVOID Init(PVOID hmod, PULONG size)
	{
		return pv = RtlImageDirectoryEntryToData(hmod, TRUE, DirectoryEntry(), size);
	}
};

//#define _PRINT_CPP_NAMES_
#include "../scentry/asmfunc.h"

struct CImport : WalkImport
{
	virtual USHORT DirectoryEntry()
	{
		CPP_FUNCTION;
		return IMAGE_DIRECTORY_ENTRY_IMPORT;
	}

	virtual ULONG Name(ULONG s)
	{
		CPP_FUNCTION;
		return sizeof(IMAGE_IMPORT_DESCRIPTOR) > s ? 0 : piid->Name;
	}

	virtual ULONG Next()
	{
		CPP_FUNCTION;
		++piid;
		return sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	virtual ULONG rvaINT()
	{
		CPP_FUNCTION;
		return piid->OriginalFirstThunk;
	}

	virtual ULONG rvaIAT()
	{
		CPP_FUNCTION;
		return piid->FirstThunk;
	}
};

struct CDImport : WalkImport
{
	virtual USHORT DirectoryEntry()
	{
		CPP_FUNCTION;
		return IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT;
	}

	virtual ULONG Name(ULONG s)
	{
		CPP_FUNCTION;
		return sizeof(ImgDelayDescr) > s ? 0 : pdid->grAttrs & dlattrRva ? pdid->rvaDLLName : 0;
	}

	virtual ULONG Next()
	{
		CPP_FUNCTION;
		++pdid;
		return sizeof(ImgDelayDescr);
	}

	virtual ULONG rvaINT()
	{
		CPP_FUNCTION;
		return pdid->rvaINT;
	}

	virtual ULONG rvaIAT()
	{
		CPP_FUNCTION;
		return pdid->rvaIAT;
	}
};

CImport* InitVT(void** vt, CImport*)ASM_FUNCTION;
CDImport* InitVT(void** vt, CDImport*)ASM_FUNCTION;

void** FindApi(HMODULE hmod, PCSTR Name)
{
	ULONG s;

	UCHAR obj[sizeof(CDImport)];

	WalkImport* p = 0;
	void* vt[5];

	ULONG n = 2;

	do
	{
		switch (--n)
		{
		case 1:
			p = InitVT(vt, (CImport*)&obj);
			break;
		case 0:
			p = InitVT(vt, (CDImport*)&obj);
			break;
		}

		if (p->Init(hmod, &s))
		{
			while (p->Name(s))
			{
				if (DWORD OriginalFirstThunk = p->rvaINT())
				{
					if (DWORD FirstThunk = p->rvaIAT())
					{
						PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)RtlOffsetToPointer(hmod, FirstThunk);
						PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)RtlOffsetToPointer(hmod, OriginalFirstThunk);

						while (ULONG_PTR Ordinal = pINT->u1.Ordinal)
						{
							if (!IMAGE_SNAP_BY_ORDINAL(Ordinal))
							{
								PIMAGE_IMPORT_BY_NAME piibn = (PIMAGE_IMPORT_BY_NAME)RtlOffsetToPointer(hmod, Ordinal);
								if (!strcmp(piibn->Name, Name))
								{
									return (void**)&pIAT->u1.Function;
								}
							}
							pINT++, pIAT++;
						}
					}
				}
				s -= p->Next();
			}
		}
	} while (n);

	return 0;
}

#pragma code_seg(".text$nn")

// this is out shell code. for reference virtual functions
void yy()
{
	new CImport;
	new CDImport;
}
