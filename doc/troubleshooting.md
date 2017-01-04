# flare-qdb Troubleshooting Guide

Below are a few failure scenarios, reasons why they may occur, and resolutions
or work-arounds.

## qdb: Win32 Error kernel32.DebugBreakProcess failed: 5

This can occur when attempting to use a 64-bit Python interpreter or qdb script
entry point to debug a 32-bit binary. Example:

	C:\Users\username>flareqdb hello.exe -at hello+0x1000 "?('eax')"
	qdb: LoadLibrary C:\Python27_12_amd64\lib\site-packages\vtrace\platforms\windll\amd64\symsrv.dll: [Error 126] The specified module could not be found
	qdb: LoadLibrary C:\Python27_12_amd64\lib\site-packages\vtrace\platforms\windll\amd64\dbghelp.dll: [Error 126] The specified module could not be found
	qdb: Running: hello.exe
	qdb: Win32 Error kernel32.DebugBreakProcess failed: 5

In this example, the 64-bit version of the `flareqdb` Python script entry point
has been used to execute a 32-bit binary and has failed. The resolution is to
ensure that a 32-bit Python interpreter is installed, ensure that Vivisect and
flare-qdb have been installed under that Python installation, and to use the python
interpreter or `flareqdb` entry point (in the `Scripts` sub-directory of the
Python directory) for the correct architecture.

## qdb: CreateProcess failed!

This can occur when attempting to use a 32-bit Python interpreter or `flareqdb`
script entry point to debug a 64-bit binary.

	C:\Users\username>flareqdb hello64
	.exe -at hello+0x128c "kill()"
	qdb: CreateProcess failed!
	qdb: Debuggee terminated without returning an exit code

## qdb: Win32 Error kernel32.ReadProcessMemory 0xXXXXXXL failed: 299

This can occur when attempting to set a breakpoint on an invalid virtual
address. Reasons why a virtual address may not be correct include:

1. The binary was relocated and the virtual address you supplied has to be
   adjusted.
2. Address Space Layout Randomization (ASLR) has caused the image to be
   loaded at a different base address.
3. The platform you are running on is executing a program other than the one
   you expect. For instance, Linux loads `ld-linux.so` to interpret and load
   ELF binaries (see below for further discussion); meanwhile, Windows WOW64
   filesystem redirection and limited user access file virtualization (`luafv`)
   can cause the process that is loaded to be a different one than was
   intended/expected.

For (1) and (2) above, try querying on a module-relative Vivisect expression
such as `modulename+0xNNN` to see if this resolves the issue. To diagnose and
fix (3) above, test with other binaries to see if the behavior is consistent
with file virtualization; ensure that you are using a Python interpreter or
`flareqdb` entry point that will not be subject to WOW64 file redirection;
verify that the target file is not located in a place where WOW64 file
redirection or limited user access file virtualization may redirect your access
to point to another file.

## Exception: reading from invalid memory 0xXXXXXXL (0 returned)

This is a more detailed explanation of case (3) under the previous heading.

On Linux, the ELF binary format handler will first execute not the binary that
you specify on the command line, but instead the loader specified in the
`INTERP` program header of that binary, e.g.  `/lib64/ld-linux-x86-64.so.2`.
This means that when the process first starts, it will not contain a mapping to
the binary image that you executed from the command line, and attempting to
read from or write to a memory location in its text section may fault. Here is
an example with truncated error output:

	username@hostname:~/flare-qdb/test$ file ./hello
	./hello: ELF 64-bit LSB executable, x86-64, [...snip...]
	username@hostname:~/flare-qdb/test$ readelf -h ./hello | grep Entry
	  Entry point address:               0x400430
	username@hostname:~/flare-qdb/test$ flareqdb ./hello -at 0x400430 "print('Hello from qdb')"
	qdb: Running: ./hello
	Traceback (most recent call last):
	  File "/usr/local/bin/flareqdb", line 9, in <module>
		load_entry_point('flareqdb==1.0.0', 'console_scripts', 'flareqdb')()

	[...snip...]

	  File "/usr/local/lib/python2.7/dist-packages/vtrace/platforms/base.py", line 883, in trfunc
		raise ret
	Exception: reading from invalid memory 0x400430L (0 returned)
	Hello, world!

A work-around for this is to specify the program counter for your breakpoint as
a module-relative Vivisect expression, like `modulename+0xNNN`. For example:

	username@hostname:~/flare-qdb/test$ readelf -S ./hello | grep .text
	  [14] .text             PROGBITS         0000000000400430  00000430
	username@hostname:~/flare-qdb/test$ flareqdb ./hello -at hello+0x430 "print('Hello from qdb')"
	qdb: Adding delayed breakpoint for hello+0x430
	qdb: Running: ./hello
	Hello from qdb
	Hello, world!
	qdb: Debuggee returned 14
	username@hostname:~/flare-qdb/test$

`flareqdb` will initially fail to locate the program counter corresponding to
this expression (because the module is not loaded) and will set a delayed
breakpoint. When the module is later loaded by the program interpreter, the
Vivisect `vtrace.Trace` object will successfully resolve the expression to a
valid memory location and set the breakpoint.

## Also... the darwin port is not even REMOTELY working yet.  Solid progress though...

If you see this message, then you tried installing and using flare-qdb on OSX.
As denoted by the vtrace output you saw, your mileage on this terrain may vary.
