#pragma once

#include "../ScEntry/asmfunc.h"

#ifdef _X86_

void* __fastcall __Address(const void* )ASM_FUNCTION;

#define __UUIDOF(x) (*(const GUID*)__Address(& __uuidof(x)))

#undef IID_PPV_ARGS
#define IID_PPV_ARGS(p) __UUIDOF(**p), (void**)p

#define _Y(x) reinterpret_cast<decltype(x)>(__Address(x))

#define _YA(x) reinterpret_cast<PCSTR>(__Address(x))
#define _YW(x) reinterpret_cast<PCWSTR>(__Address(x))

#else

#define _Y(x) x
#define _YA(x) x
#define _YW(x) x
#define __UUIDOF(x) __uuidof(x)

#endif