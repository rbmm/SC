# SC
 shell code example

else one example how write complex shell code on c/c++

note on:


#define DECLSPEC_IMPORT

/cbstring

#pragma code_seg(".text$mn$cpp")

prepare.cpp ( util file, for build shell code from initial exe)

nobase64.inc ( for implement import )


result: 
sc.bin - pure shell code as is
sc.asm - described on asm for build
sc-x64.exe - sc.bin wrapped to exe file (no import, relocs, dynamic base) for easy test sc.bin

sc.bin - download 2 binary files (x86 and x64)

https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe
https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe

and exec it from memory (without save any data to disk
