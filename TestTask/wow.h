#pragma once

union FUNC
{
	PCSTR name;
	void* pfn;
};

NTSTATUS GetWowInfo(FUNC* pfn, ULONG n);