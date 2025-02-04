write shell code framework

--------------------------------------

**Note !!** all projects from solution require [MSBuild](https://github.com/rbmm/MSBuild) and [pnth](https://github.com/rbmm/pnth)
it not direct included to this repo because was on [one level up](dummy/dummy.vcxproj#L19) :
```
<UserRootDir>$(SolutionDir)..\MSBuild\v4.0</UserRootDir>
 <AdditionalIncludeDirectories>$(SolutionDir)..\pnth</AdditionalIncludeDirectories>
```

i use it as common files in different solutions and for not make multiple copy, i place it at `$(SolutionDir)..`
so you need download it separate and place in parent directory of solution 

--------------------------------------

the idea is to write shellcode in c/c++ without using asm at all (unless some part of the project requires it, but this is not related to the shellcode itself)
and so that function calls and working with strings look like usual. so that there is no need to rewrite the usual code to convert it to shellcode

for comparison

[LibLfm](LibLfm/ep.cpp) - loads DLL from memory (static lib, not shellcode)
[ScLfm](ScLfm/ep.cpp) - same code converted to shellcode

find the differences

or [TestTask](TestTask) - builds in shellcode ( [TestTask.x64.exe](TestTask/TestTask.x64.exe) ) although it is not small code

1) **create a new project using the [NewScProj.exe](NewScProj.exe) utility **

```
NewScProj.exe *[path\]project-name*vcp
```
for example, the command
```
NewScProj.exe *dummy*vcp
```
created a [dummy](dummy) directory with several files

[stdafx.cpp](dummy/stdafx.cpp) / [stdafx.h](dummy/stdafx.h) - standard precompile files

[x64.asm](dummy/x64.asm) / [x86.asm](dummy/x86.asm) ( `$(PlatformTarget).asm` ) - contains shellcode entry point [`epASM()`](dummy/x64.asm#L7) which calls [`void ep()`](dummy/ep.cpp#L6) from c++ file

[ep.cpp](dummy/ep.cpp) - containing "user" entry point of shellcode - [`void ep()`](dummy/ep.cpp#L6)

[imp.x64.asm](dummy/imp.x64.asm) / [imp.x86.asm](dummy/imp.x86.asm) ( `imp.$(PlatformTarget).asm` ) - contains a list of imported functions for shellcode
Initially these files are empty. We do not need to edit them manually. They will be created automatically on post build event

2) **creating `imp.$(PlatformTarget).asm`**

even though we are creating shellcode - we can freely import any functions from any dll. add new libs to `Link > AdditionalDependencies` in vcxproj

`ntdllp.lib` and `ScEntry.lib` are necessary and should always be present in the list of libraries
other libs can be added/removed as needed

after our exe is built (a shellcode project is always an exe project) a post build will be automatically launched, which based on the map file (`/MAP` linker option is always must be on) and the exe import table, if it is not empty, generates `imp.$(PlatformTarget).asm` and returns an error

```
error MSB3073: The command "... ...:VCEnd" exited with code -1073741802.
```

after that we should press build again.
this time the exe import table should be empty. and if the exe does not contain relocs in the shellcode section (for x86 there is a special case here) the final shellcode will be built

that is, initially we need to do build 2 times always

after `imp.$(PlatformTarget).asm` is built, the following builds (after changing the code) will work as usual - that is, you will need to press build 1 time instead of 2. unless we add new imported functions. in this case we need to 3 time press buid:

first time will be error

```
1>Indicates that the directory trying to be deleted is not empty.
error MSB3073: :VCEnd" exited with code -1073741567.
```

second time error
```
1>{Still Busy}
1>The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.
1>0xc0000016 (-1073741802)
error MSB3073: :VCEnd" exited with code -1073741802.
```

and on 3-rd try

```
1>The operation completed successfully.
1>0x0 (0)
========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========
```

`imp.$(PlatformTarget).asm` creates a structure in the exe similar to delayimport. and it works completely similar to how delayimport works. finds the address of the function when it is first called. and saves it. subsequent calls use the saved address. all this happens transparently for the application. we call the api as usual. moreover - we do not need to use any special macros in the source code, any special form of syntax. the function is called exactly the same as in the case of ordinary (not shell) code. nothing needs to be changed.
if shellcode cannot find a function or a dll for it, it simply calls `__debugbreak()` any callbacks are not supported in this situation. not finding the function address is fatal (well, unless you install VEH and somehow handle such a situation in it)

someone may have a question - should we then use delayimport in our project instead of import ? no, it will not work. moreover, we should not contain delayimport at all

3) **CRT**

shellcode can't use standard c/c++ CRT. It must use special CRT - [ScEntry](ScEntry) project (static lib)
we must link our exe with `ScEntry.lib` and entry point of our project (`EntryPointSymbol`) - must be `?ScEntry@@YAXPEAU_PEB@@@Z` (for x86 `?ScEntry@@YGXPAU_PEB@@@Z` )

[`ScEntry(PEB*)`](ScEntry/prepare.cpp#L23) calls `epASM()` from our `$(PlatformTarget).asm` - so the name, `epASM`, cannot be changed.

here is a complete analogy with regular CRT. when the real entry point of the application `wmainCRTStartup` (`ScEntry`) calls `wmain` (`epASM`)

`epASM` in turn calls `ep` from our c++ code. we can change the name (or rather the signature) of our user entry point, if necessary.
if our shellcode does not accept any parameters and does not return anything, then `void ep()` is ok. and nothing needs to be changed.
otherwise, we need to edit `$(PlatformTarget).asm`

for example, in the project [ScLfm](ScLfm/ep.cpp#L464) the signature of the entry point

```
NTSTATUS NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_opt_ ULONG_PTR Size, _Out_opt_ void** ppv);
```

therefore we replace

```
; void ep()
extern ?ep@@YAXXZ : PROC

; void epASM()
?epASM@@YAXXZ proc
  jmp ?ep@@YAXXZ
?epASM@@YAXXZ endp
```
to

```
; long __cdecl LoadLibraryFromMem(void *,unsigned __int64,void **)
extern ?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z : PROC

; void epASM()
?epASM@@YAXXZ proc
	jmp ?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z
?epASM@@YAXXZ endp
```

the question may arise - how to get such a name as `?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z`
for this you can use macros - [`CPP_FUNCTION`](ScEntry/asmfunc.h#L13) and [`ASM_FUNCTION`](ScEntry/asmfunc.h#L12) from [asmfunc.h](ScEntry/asmfunc.h)

`CPP_FUNCTION` we place inside the function that we plan to call from asm code and we need to get its name.
`ASM_FUNCTION` we place after the declaration of the function that is implemented in the asm file - after `)` and before `;` - `)ASM_FUNCTION;`
if uncomment `#define _PRINT_CPP_NAMES_` during compilation (not linking !) we see names in the output window. we need comment `_PRINT_CPP_NAMES_` again before build (or we got error - multiple defined symbols)

of course you can use `EXTERN_C` names as an alternative. but this is not our method

there is a fundamental difference between the standard CRT and ScEntry - the standard CRT will be present in our final PE (exe/dll)
it will always be executed when the application starts (DLL loads).

in our case [`ScEntry(PEB*)`](ScEntry/prepare.cpp#L23) will not be present in the final shellcode (and therefore will not be executed)
it will be executed only at the stage of shellcode assembly (post build step) and debugging. its role is in the construction of the shellcode itself.

but the CRT part from the file [GetFuncAddr.cpp](ScEntry/GetFuncAddr.cpp) will be present - `GetFuncAddressEx`, `get_hmod`, `GetNtBase()` - used in runtime for import resolve and can be
[called](ScLfm/ep.cpp#L407) separate too

4) **post build step**

it always runs after successful exe build.
`ScEntry` loads prepare.dll (see prepare project) and calls
```
NTSTATUS NTAPI PrepareSC(PVOID Base, ULONG cb, PVOID ImageBase)
```
from [it](prepare/ep.cpp#L1095)

passing the shellcode start address (`epASM`), its size and exe base in memory

```
status = PrepareSC(epASM, RtlPointerToOffset(epASM, sc_end()), &__ImageBase);
```

this function will do all the work of creating shellcode from exe.
and then ScEntry will unload prepare.dll and if we are under debugger, will call epASM

```
if (peb->BeingDebugged)
{
	epASM();
}
```

and returns the result - `RAC(RtlExitUserProcess, status);`

a question may arise - why do we need a separate project/DLL - [prepare](prepare) ? Why not implement its functionality directly in [ScEntry](ScEntry) ?
because `ScEntry` cannot (unlike shellcode itself) import functions. Accordingly, writing code becomes extremely inconvenient and difficult.
I mentioned the main goal of the project at the very beginning - shellcode should not differ from regular code, at the source level. Now look at the implementation

```
void WINAPI ScEntry(PEB* peb)
```

compare `RAC(RtlExitUserProcess, status)` and `RtlExitUserProcess(status)`
`RAC(LdrGetProcedureAddress, hmod, 0, 1, &pv)` and `LdrGetProcedureAddress(hmod, 0, 1, &pv)`

that's why this project was created, so as not to write like this or similarly

a separate prepare.dll - not shellcode but a regular dll. it can import any functions and is not limited by anything

5) **PrepareSC / post build command line**
if we are under the debugger - PrepareSC simply makes memory for shellcode ERW - (`VirtualProtect(Base, cb, PAGE_EXECUTE_READWRITE, &cb)`) and exits.
otherwise the command line format for post build:

```
"$(TargetPath)" *map*imp*[bin]*[asm]*[exe]
```

```
$(TargetPath) - we run our own exe for post build, ScEntry loads prepare.dll and calls PrepareSC
map - path to map file - mandatory parameter := $(OutDir)$(ProjectName).map
imp - path to imp file - mandatory parameter := imp.$(PlatformTarget).asm
bin - name of file where to save shellcode in binary form - optional parameter, can be empty
asm - name of file where to save shellcode as asm code - i.e DQ sequense (and possible DD, DW, DB in the end)
exe - name of exe file where we insert shellcode. such exe will not contain any imports or relocs - the only section ".text" containing shellcode and nothing else
```

**exe** makes sense only if our shellcode does not accept direct parameters (`void ep()`) (but can of course use the process command line)
it is convenient for testing/demonstrating shellcode. usually `exe := $(ProjectName).$(PlatformTarget).exe`

`*` is used as a separator because it can't be in the file name

**asm** can have sub-parameters
if it starts with `?` (and doesn't contain more `?`) it means that we want to save the shellcode in a compressed form, using `CreateCompressor` + `Compress` from cabinet.dll
accordingly, when working with shellcode in realtime we need to first unpack it with `CreateDecompressor` + `Decompress`
if **asm** contains several `?` it means that we want to encrypt the compressed content with a password

asm = ?password?asm (based on the password, an AES256 key is created)

decrypt + unpack implementation in [DecryptUnpackRun](DecryptUnpackRun/ep.cpp#L61)

[DecryptUnpackRun](DecryptUnpackRun) is also shellcode with entry point signature
```
void WINAPI ep(PEB* peb, PBYTE pbIn, ULONG cb);
```
which takes encrypted shellcode pointer and its size (and peb of process)

`?` is chosen as sub delimiter because it again cannot be in file name
password can contain `?` characters (we are looking for the last `?` ) but cannot contain `*` (top delimiter) and `%`
you can use 3 esc sequense
```
## -> #
#. -> *
#: -> %
```

usage examples:

[ScLfm](ScLfm) project has this post build
```
"$(TargetPath)" *$(OutDir)$(ProjectName).map*imp.$(PlatformTarget).asm**$(ProjectName).$(PlatformTarget).asm
```

no bin and exe. `asm = $(ProjectName).$(PlatformTarget).asm`

[LibScLfm](LibScLfm) project ( static library, not shellcode ) includes it in its `$(PlatformTarget).asm`

```
shellcode SEGMENT READ WRITE EXECUTE ALIAS(".shlcode") 'CODE'

ALIGN 16
; long __cdecl LoadLibraryFromMem(void *,unsigned __int64,void **)

?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z PROC
LoadLibraryFromMem PROC
INCLUDE <../ScLfm/ScLfm.x64.asm>
LoadLibraryFromMem ENDP
?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z ENDP

shellcode ENDS

end
```

as a result we get a static lib that implements [`LoadLibraryFromMem`](LibScLfm/x64.asm#L8) and does not import anything.
for comparison [LibLfm](LibLfm) implements the same function [`LoadLibraryFromMem`](https://github.com/rbmm/SC/blob/main/LibLfm/ep.cpp#L459), but adds ntdll import to the project

in fact, there is practically no difference between [LibScLfm](LibScLfm) and [LibLfm](LibLfm). [LibScLfm](LibScLfm) was created exclusively to demonstrate embedding shellcode directly as code that will be executed in-place

the [Load](Load) project uses [LibScLfm.lib](Load/Load.vcxproj#L48) as static lib. but you can put [LibLfm](LibLfm) in this place - they are completely interchangeable. and if our goal is to load dll into own process only - better to use [LibLfm](LibLfm)

other usage [ScLfm.x64.asm](ScLfm/ScLfm.x64.asm) in project [InjLfm](InjLfm/x64.asm)

```
.const

public ?SC_begin@@3QBEB, ?SC_end@@3QBEB

?SC_begin@@3QBEB LABEL BYTE
INCLUDE <../ScLfm/ScLfm.x64.asm>
?SC_end@@3QBEB LABEL BYTE

end
```

here we include `ScLfm.x64.asm` not in `.code` but to the `.const` section

code will not be executed in-place. but will be used fror inject dll from memory to another process.

when we load dll from memory to current process, loader must not (but can) be a shellcode. but when we load dll from memory in **another** process, loader must be a shellcode

[ScLfm+ACG](ScLfm%2BACG) ( `NTSTATUS NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_opt_ ULONG_PTR Size, _In_ HANDLE hPipe)` )

```
"$(TargetPath)" *$(OutDir)$(ProjectName).map*imp.$(PlatformTarget).asm**?zip.$(ProjectName).$(PlatformTarget).asm
```

`zip.$(ProjectName).$(PlatformTarget).asm` - contains compressed, but not encrypted shellcode

the project [InjLfmACG](InjLfmACG/x64.asm) includes it
```
.const

public ?ACG_begin@@3QBEB, ?ACG_end@@3QBEB

?ACG_begin@@3QBEB LABEL BYTE
INCLUDE <../ScLfm+ACG/zip.ScLfm+ACG.x64.asm>
?ACG_end@@3QBEB LABEL BYTE

end
```
unpack it in [InjLfmACG/ep.cpp](InjLfmACG/ep.cpp#L9)

project [hello](hello)
```
"$(TargetPath)" *$(OutDir)$(ProjectName).map*imp.$(PlatformTarget).asm**?#.pass?word##?$(ProjectName).$(PlatformTarget).asm*$(ProjectName).$(PlatformTarget).exe
```

`?#.pass?word##?` means that the shellcode in `$(ProjectName).$(PlatformTarget).asm` is encrypted with `*pass?word#` (escaped to `#.pass?word##` ) password, after compression

we include it in [ESC](ESC) project - this is pure asm shellcode, which does not contain ScEntry CRT and post build - just build shell from generic
`<../DecryptUnpackRun/DecryptUnpackRun.$(PlatformTarget).asm>` and `<../hello/hello.$(PlatformTarget).asm>`
accepted command line is `*#.pass?word##*` - run `$(PlatformTarget)\[x64\]Release\esc.bat` - result must be the same as run direct `hello/hello.$(PlatformTarget).exe` (unencrypted shellcode)

`$(ProjectName).$(PlatformTarget).exe` - path to put shellcode, packed in exe

6) **code layout**

ml[64].exe ( MASM ) put code from `.code` or `_TEXT` segment to the ".text$mn" segment
I use

#pragma code_seg(".text$mn$cpp")
#pragma const_seg(".text$mn$cpp$r")

I also use compiler option `/cbstring` - when using it, the strings are placed in the same section as the code using them with the addition of `$s`
that is, if our code is in the ".text$mn$cpp" section, the strings will be in ".text$mn$cpp$s"

in [ScEntry\ep.cpp](ScEntry/prepare.cpp#L10) I use a special marker function

```
#pragma code_seg(".text$nm")

void* sc_end()
{
return sc_end;
}
```

placing it in ".text$nm" (dont confuse `mn` and `nm`) segment
and the CRT entry point - `ScEntry(PEB* peb)` - in `#pragma code_seg(".text$zz")`
```
/*---------------- begin of shellcode (epASM) ----------------*/
.text$mn                asm code from $(PlatformTarget).asm, always must begin with epASM()
.text$mn$cpp            c/c++ code from ep.cpp and any other src files
.text$mn$cpp$r          const data, can be __GUID_... when we use class/struct with __declspec(uuid("")) and __uuidof of this class
.text$mn$cpp$s          strings ( ??_C@_...)
/*---------------- end of shellcode (sc_end) ----------------*/
.text$nm                void* sc_end()
.text$zz                void WINAPI ScEntry(PEB* peb)
```

it is this structure that allows ScEntry to determine the boundaries of the shellcode and pass them to prepare
```
status = PrepareSC(epASM, RtlPointerToOffset(epASM, sc_end()), &__ImageBase);
```
ScEntry itself will not be included in the resulting shellcode

7)** x86 problems **
on x86, when we take the address of the global string object ("...") or function, a relocation occurs (`IMAGE_REL_BASED_HIGHLOW`) since the address is encoded in absolute form (in x64, rip-address is used - offset from the current rip). This causes problems, since we cannot use string constants directly (function addresses as parameters, `__uuidof()`). To solve this problem, I use the function

```
void* __fastcall __Address(const void* )ASM_FUNCTION;
```

it takes as input an address inside the shellcode (assuming it is loaded at preffered base ) and returns the actual address, taking into account the actual shellcode base

that is, we cannot call `MessageBoxW(.. L"text", L"caption" ..)` in x86, but must use `MessageBoxW(.. (PCWSTR)__Address(L"text"), (PCWSTR)__Address(L"caption") ..)`
to simplify the code, you can use several macros from [address.h](ScEntry/address.h)
```
#ifdef _X86_

void* __fastcall __Address(const void* )ASM_FUNCTION;

#define __uuidof(x) (*(const GUID*)__Address(&__uuidof(x)))

#define _Y(x) (*reinterpret_cast<decltype(x)*>(__Address(&x)))
#define _YA(x) reinterpret_cast<PCSTR>(__Address(x))
#define _YW(x) reinterpret_cast<PCWSTR>(__Address(x))

#else

#define __Address(x) x
#define _Y(x) x
#define _YA(x) x
#define _YW(x) x

#endif
```

that is, we can write like this: `MessageBoxW(.. _YW(L"text"), _YW(L"caption") ..)`
in the same way we can't write `EnumWindows( MyEnumWindowsProc, 0)` but we can `EnumWindows( _Y(MyEnumWindowsProc), 0)`

(macro _YA, _YW is identical in usage to the well-known macro _T("abc") )

even though I couldn't handle strings transparently as imports, I still think _YA("text") is the best solution out of the existing ones.
definitely better than writing something like `char msg[] = {'m', 's', 'g', 0 };` and writing `char msg[] = "some long string"` is not allowed at all, since the compiler may be smarter than us. place "some long string" in ".rdata" and copy it to the stack.

for x64, none of this is required. and if we don't need x86 code, we can write directly MessageBoxW(.. L"text", L"caption" ..), EnumWindows( MyEnumWindowsProc, 0) etc.
but we shouldn't forget that this is due to using `/cbstring` and `#pragma const_seg(".text$mn$cpp$r")` . although to be honest it would be enough to just `#pragma const_seg(".text$mn$cpp$r")`. then the strings would also be placed in ".text$mn$cpp$r". but I prefer to use `/cbstring` too and place the strings in a separate segment ".text$mn$cpp$s"

8) of course shellcode will have some limitations. for example we can't use classes with virtual functions, because vtable always generates relocations (it is possible of course to write some code to solve this problem too), and others.. in any case, to write this, a deep understanding is required - what and why we are doing. the ability to debug and solve problems

9) projects

[hello](hello)

this is just a demo project, shows how `imp.$(PlatformTarget).asm` is formed. especially for x86. I specifically chose some functions with __fastcall caling convention (extremely rare for winapi), __cdecl, __stdcall, exported only by the RtlDispatchAPC ordinal (in x64), cpp decorated.. using __uuidof and strings. shows general shellcode capabilities

[DownloadAndRun-x64](DownloadAndRun-x64) downloads "the.earth.li/~sgtatham/putty/latest/w[32\64]/putty.exe" and runs it from memory, without saving anything to disk. that is, it uses process hollowing. and all this from shellcode. both versions are launched - 32 and 64 at the same time

[DownloadAndRun-x86](DownloadAndRun-x86) - the same, but in the x86 version. launching 32 -> 64 presents great technical difficulties. in particular, entering 64 bit mode from a 32 bit process. why do we need a separate shellcode - [Exec-x64](Exec-x64) project

call x64:

```
; int __fastcall Exec64(void *,void *,void *)
?Exec64@@YIHPAX00@Z proc
  xchg edi,[esp+4]
  xchg esi,[esp+8]
  xchg ebp,[esp+12]
  jmp @2
  ALIGN 16
@3:
INCLUDE <../Exec-X64/Exec-x64.x64.asm>
@2:
  push 33h
  call @1
  ;++++++++ x64 +++++++++
  call @3
  retf
  ;-------- x64 ---------
@1:
  call fword ptr [esp]
  pop ecx
  pop ecx
  mov edi,[esp+4]
  mov esi,[esp+8]
  mov ebp,[esp+12]
  ret 12
?Exec64@@YIHPAX00@Z endp
```

although there is nothing new and unknown here, I strove for the highest quality and most beautiful implementation. since the meaning is only in it, and not in the final result

I wrote [TestTask](TestTask) not on my own initiative but as a .. I think it is clear from the name. however, the result of all this is also obvious. although the code is also written as high quality as possible. the project has only an x64 version

[CertLogon#1](CertLogon%231) and [CertLogon#2](CertLogon%232) implement 2 different ways of logging into Windows AD using a pfx file that contains a valid certificate with a key for logging in (you can use the [CRT-UT.exe](PfxLogon/CRT-UT.exe) utility to create it) there is no point in writing this in shellcode, of course. this is just another demonstration of the possibilities of writing a real application, in shellcode. besides these two solutions are of separate interest, especially #2

several of my personal, utility projects..
for example [ModKdc](ModKdc/ep.cpp)
I needed to change the value of one variable in "kdcsvc.dll" from lsass.exe. to be honest, it would have been easier to do. load "kdcsvc.dll" into your process. 99%+ of the time its address in my process would have matched the address in lsass.exe. after which just ZwWriteVirtualMemory. but 99% of the difficulty here was finding the RVA of this variable in kdcsvc - for this it was necessary to load kdcsvc.pdb from microsoft symbols server into memory and parse it

[Seci](Seci/ep.cpp) - intercepting calls to `SeciAllocateAndSetCallFlags` from "USERMGR.DLL"
as in the previous example, the shellcode will be called from APC and has a signature different from `void ep()`

10) **Load DLL from memory**

a number of projects are dedicated to this

[LibLfm](LibLfm) - static lib. not a shell code. simply the most high-quality and correct implementation of this.
designed to load DLLs exclusively into their own process.

[ScLfm](ScLfm) - the same project, but transformed into shellcode
if you compare the c++ files of the projects (both have actually 1 c++ file) you can see that the modifications are minimal. and even then, solely for the sake of x86 support. for x64 this would not be necessary (using _YA, _YW, _Y macros in several places)

the code (it is the same in both projects) needs to install ERW page protection, during the loading of DLL. in processes with ACG mitigation (PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::ProhibitDynamicCode) this will end with the error `STATUS_DYNAMIC_CODE_BLOCKED`

to solve this problem, an extended solution was written

[ScLfm+ACG](ScLfm%2BACG)

here we have a more complex code, but it also works in ACG processes
(the system usually has at least 1 such process (after opening the startmenu) `DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}` in which webplatstorageserver.dll lives (and the bug lives in it)).

in addition, [ScLfm+ACG](ScLfm%2BACG) has additional functionality compared to [ScLfm](ScLfm) - it can report the address to which the dll was loaded, or an error code if the download was unsuccessful

how to use these 2 shellcode?
for this we use 2 shell projects [InjLfm](InjLfm) for [ScLfm](ScLfm) and [InjLfmACG](InjLfmACG) for [ScLfm+ACG](ScLfm%2BACG)
these are static libs, not a shellcode. similar to the [LibLfm](LibLfm) project but intended for loading dll into any process, not just into its own like [LibLfm](LibLfm)
both of these projects include shellcode from [ScLfm](ScLfm) and [ScLfm+ACG](ScLfm%2BACG) respectively in the .const section
shellcode is written into the target process, together with the dll image, and does the job.

[InjLfm](InjLfm) contains raw shellcode and [InjLfmACG](InjLfmACG) compressed (although we win a little in shellcode size, we have additional size for unpacking code)

in fact, to use compressed shellcode or raw - there is no difference. you can use all 4 combinations here. I used 2 different options solely for demonstration and comparison of work in both cases

what is the fundamental difference between [InjLfm](InjLfm) and [InjLfmACG](InjLfmACG) ?

compare the interface signatures:

```
NTSTATUS NTAPI InjectDLL(_In_ HANDLE hProcess, _In_ const void* pvData, _In_ ULONG cbData);
```

and

```
NTSTATUS NTAPI InjectACG(
	_In_ HANDLE hProcess,
	_In_ const void* pvData,
	_In_ ULONG cbData,
	_Out_ PVOID* pImageBase,
	_Out_ PBOOL StatusFromRemote);

NTSTATUS NTAPI RemoteUnloadDll(_In_ HANDLE hProcess, _In_ PVOID RemoteBase);
```

InjectACG has 2 additional output parameters - pImageBase - the address at which the DLL was loaded (can be used for RemoteUnloadDll later) and StatusFromRemote. - that is, if an error occurred during the DLL loading, we can understand in which process it occurred - in the local one, at the shellcode injection stage, or already in the remote one, during the shellcode execution.

InjectDLL - writes the shellcode to the target process and runs it. and returns the status of this phase. but we do not know what happened next. was the DLL loaded. if yes, then at what address. if no, then what is the error code.

InjectACG - on the contrary, it reports all this information. and supports ACG mitigation. but on the other hand, there is a risk of freezing if the DLL loading process in the remote process freezes. even if it is not our fault. I encountered such a problem in webplatstorageserver which, due to an error during process termination, caused a deadlock in loader lock. the process did not exit and remained alive. loading a dll into such a process would hang even at the creation of the thread, since it could not enter the loader lock

finally, [LibScLfm](LibScLfm) which I have already mentioned several times. it also contains shellcode from [ScLfm](ScLfm) like [InjLfm](InjLfm). but in the `.code` section and not in `.data`
and is intended for in-place execution (and not copying it to executable memory first and run from it)
the project itself has no meaning (unlike the others) and is intended to demonstrate the difference with [LibLfm](LibLfm) and the way to include shellcode for in-place execution (that is, executing it directly from the body of the exe/dll where it is included, without copying it to separate memory)

well, about the names. yes, it is not my strong point, to come up with names

[Load](Load) UI project, not shellcode. used Lib[Sc]Lfm.lib and InjLfmACG.lib - used for testing/demo of DLL injection into your or another process.

[DLL](DLL) DLL for injection. Of course, you can inject any DLL. This DLL shows Messagebox, that is, it immediately shows successful loading (if the process can have UI). In addition, this DLL cannot be unloaded while it shows Messagebox, and as a result, it allows you to test re-loading of the DLL