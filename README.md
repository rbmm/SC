shellcode (x64/x86) example

else one example how write complex shellcode on c/c++

note on:

#define DECLSPEC_IMPORT

/cbstring ( for x64 only, in x86 need special string processing )

#pragma code_seg(".text$mn$cpp")

prepare.cpp ( util file, for build shell code from initial exe)

nobase64.inc / nobase32.inc  ( for implement import )

result: 

sc-x64.bin ( sc-x86.bin ) - pure shellcode as is 

sc-x64.asm ( sc-x86.asm) - shellcode converted to asm file for include in c/c++ project

sc-x64.exe( sc-x86.exe ) - shellcode wrapped to exe file (no import, relocs, dynamic base) for easy test

download 2 binary files (x86 and x64)

https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe

https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe

and exec it from memory, without save any data to disk

********************************

use x86 shellcode much more complex here compare x64: in case it wow code, for exec 64-bit exe from memory, need some native code in wow process
for this we need util project ( ExecX64 ) - 64bit code, which will be executed in wow process, after enter 64 gate.
also need use strings in asm code, ( for x64 we can use /cbstring)