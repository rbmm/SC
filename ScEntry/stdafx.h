#pragma code_seg(".text$mn$cpp")
#pragma const_seg(".text$mn$cpp$r")

#define DECLSPEC_IMPORT

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

#include "mini_yvals.h"

#define _makeachar(x) #@x
#define makeachar(x) _makeachar(x)
#define _makewchar(x) L## #@x
#define makewchar(x) _makewchar(x)
#define echo(x) x
#define label(x) echo(x)##__LINE__
#define showmacro(x) __pragma(message(__FILE__ _CRT_STRINGIZE((__LINE__): \nmacro\t)#x" expand to\n" _CRT_STRINGIZE(x)))

#define RTL_CONSTANT_STRINGA(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ), const_cast<PSTR>(s) }
#define RTL_CONSTANT_STRINGW_(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ), const_cast<PWSTR>(s) }
#define RTL_CONSTANT_STRINGW(s) RTL_CONSTANT_STRINGW_(echo(L)echo(s))

#define STATIC_UNICODE_STRING(name, str) \
static const WCHAR label(__)[] = echo(L)str;\
static const UNICODE_STRING name = RTL_CONSTANT_STRINGW_(label(__))

#define STATIC_ANSI_STRING(name, str) \
static const CHAR label(__)[] = str;\
static const ANSI_STRING name = RTL_CONSTANT_STRINGA(label(__))

#define STATIC_ASTRING(name, str) static const CHAR name[] = str
#define STATIC_WSTRING(name, str) static const WCHAR name[] = echo(L)str

#define STATIC_UNICODE_STRING_(name) STATIC_UNICODE_STRING(name, #name)
#define STATIC_WSTRING_(name) STATIC_WSTRING(name, #name)
#define STATIC_ANSI_STRING_(name) STATIC_ANSI_STRING(name, #name)
#define STATIC_ASTRING_(name) STATIC_ASTRING(name, #name)

#define STATIC_OBJECT_ATTRIBUTES(oa, name)\
	STATIC_UNICODE_STRING(label(m), name);\
	static OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(&label(m)), OBJ_CASE_INSENSITIVE }

#define STATIC_OBJECT_ATTRIBUTES_EX(oa, name, a, sd, sqs)\
	STATIC_UNICODE_STRING(label(m), name);\
	static OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(&label(m)), a, sd, sqs }


#define BEGIN_PRIVILEGES(name, n) static const union { TOKEN_PRIVILEGES name;\
struct { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[n];} label(_) = { n, {

#define LAA(se) {{se}, SE_PRIVILEGE_ENABLED }
#define LAA_D(se) {{se} }

#define END_PRIVILEGES }};};