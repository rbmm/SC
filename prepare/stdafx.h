#define DECLSPEC_DEPRECATED_DDK

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _NO_CRT_STDIO_INLINE
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES 0
#define _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
#define __EDG__
#define USE_ATL_THUNK2

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

#define DPAPI_IMP DECLSPEC_IMPORT
#define _CRTIMP DECLSPEC_IMPORT
#define _CRTIMP_ALT DECLSPEC_IMPORT


#define CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS
#define CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS

#pragma warning(disable : 4073 4074 4075 4097 4514 4005 4200 4201 4238 4307 4324 4392 4480 4530 4706 5040)
#include <stdlib.h>
//#include <wchar.h>
#include <stdio.h>
#include <string.h>

#include <WinSock2.h>
#include <intrin.h>
#include <windowsx.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winioctl.h>
#include <Commctrl.h>

//#include <atlbase.h>
//#include <atlwin.h>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

#ifndef PHNT_MODE
#define PHNT_MODE PHNT_MODE_USER
#endif

#ifndef PHNT_VERSION
#define PHNT_VERSION PHNT_WIN11_22H2
#endif

#define _NTLSA_

#if PHNT_MODE == PHNT_MODE_USER
#define SECURITY_WIN32
#endif

#pragma warning(disable : 4073 4074 4075 4097 4514 4005 4200 4201 4238 4307 4324 4471 4480 4530 4706 5040)

typedef GUID* PGUID;

#define PHNT_NO_INLINE_INIT_STRING
#include "phnt.h"

#pragma warning(default : 4392)
