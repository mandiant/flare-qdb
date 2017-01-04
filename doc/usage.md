# flare-qdb Command Line Usage Guide

flare-qdb provides the script entry point `flareqdb` (the hyphen is omitted for
uniformity with the Python module of the same name).

Usage is as follows:

	usage: flareqdb-script.py [-h] [-q] [-at vexpr-pc pythontext]
						 [-at-if vexpr-pc vexpr-cond pythontext] [--help-builtins]
						 [cmdline]

	Query-oriented debugger

	positional arguments:
	  cmdline               program and arguments to run

	optional arguments:
	  -h, --help            show this help message and exit
	  -q                    suppress normal console output
	  -at vexpr-pc pythontext
							query
	  -at-if vexpr-pc vexpr-cond pythontext
							conditional query based on Vivisect expression truth
							value
	  --help-builtins       display flare-qdb builtin documentation

Vivisect expression evaluation can parse complex conditions such as:

	"not eax or (edx>3 and edx<5)"

## Command Line Examples

Usage is shown by way of example. Most examples omit the required program name
and cmdline argument or output for brevity. Functions used here are defined
either by flare-qdb or by standard Python libraries. For detailed documentation
of flare-qdb builtins, type `flareqdb --help-builtins` or see the [flare-qdb
Builtins Reference](qdb_builtins.txt).

* Setting a trace breakpoint using the `hit()` builtin:
	+ Is 402c72 ever executed?

	```
	-at 402c72 "hit()"
	```

	+ Something similar could also be done using normal Python:

	```
	-at 402c72 "print('Hit')"
	```

* Setting a counting breakpoint using the `count()` builtin:
	+ How many times (if any) is 402c72 executed?

	```
	-at 402c72 "count()"
	```

* Terminating when execution hits a certain instruction using the `kill()`
  builtin:
	+ When 402c72 is executed, bail

	```
	-at 402c72 "kill()"
	```

* Vivisect expression evaluation for registers using the `?()` builtin (which
  is a shorthand alias for the Vivisect expression evaluation builtin,
  `vex()`):
	+ At 402c72, what is eax?

	```
	-at 402c72 "?('eax')"
	```

* Semicolon-separated expression evaluation for registers and memory:
	+ At 402c72, what are eax, ebp-0x244, and poi(ebp-0x244)?

	```
	-at 402c72 "vex('eax'); vex('ebp-0x244'); vex('poi(ebp-0x244)')"
	```

* Vivisect expression evaluation for imported function addresses:
	+ When `MessageBoxA` is called, what is the ASCII string specified in the
	  second argument (`lpText`)?

	```
	-at kernel32.MessageBoxA "da('poi(esp+8)')"
	```

* Vivisect symbol resolution using the `getsym()` builtin (also callable
  through the alias `ln()`):

	```
	flareqdb ll.exe -at 0x401046 "getsym('poi(ebp-0xc)')"
	qdb: Running: ll.exe
	qdb[0x00401046]: Symbol for poi(ebp-0xc) = 0x7dd710ff = kernel32.SleepStub
	```

* Builtin functions similar to WinDbg's `du`, `da`, etc. commands, which accept
  Vivisect expressions:
	+ What values will this Unicode string take on during each loop iteration?

	```
	flareqdb "blah.exe asdfasdfasdfasdfasdfasdfasdf" -at 402bd3 
	"du('poi(ebp-0x218)')"

	qdb[0x402bd3]: poi(ebp-0x218): asdfasdfasdfasdfasdfasdfasdf
	qdb[0x402bd3]: poi(ebp-0x218): sdfasdfasdfasdfasdfasdfasdf
	qdb[0x402bd3]: poi(ebp-0x218): dfasdfasdfasdfasdfasdfasdf
	qdb[0x402bd3]: poi(ebp-0x218): fasdfasdfasdfasdfasdfasdf
	[...snip...]
	qdb[0x402bd3]: poi(ebp-0x218): fasdf
	qdb[0x402bd3]: poi(ebp-0x218): asdf
	qdb[0x402bd3]: poi(ebp-0x218): sdf
	qdb[0x402bd3]: poi(ebp-0x218): df
	```

* `flareqdb` accepts multiple queries. For example (hanging indents added for
  clarity):

	```
	flareqdb "blah.exe asdfasdfasdfasdf"
		-at 0x402C55 "vex('edx'); vex('poi(ebp-0x244)')"
		-at 0x402C5D "count()"

	qdb[0x402c55]: edx = 3b687c31
	qdb[0x402c55]: poi(ebp-0x244) = 8dede550
	qdb[0x402c5d]: hit
	[...snip...]
	qdb[0x402c5d]: hit
	qdb[0x402c55]: edx = 00000000
	qdb[0x402c55]: poi(ebp-0x244) = 00000000
	Hello, world!
	qdb: 0x402c5d hit 26 times
	```

* `flareqdb` supports local variables for stateful debugging:
	+ Each time the inner loop begins, print the base address that is
	  calculated once and only once:

	```
	flareqdb loader.exe -at 0x412345 "do_print = True;"
	-at 0x41234f "if do_print: r('eax'); do_print = False"

	qdb[0x41A495]: eax = 0x3f1008
	qdb[0x41A495]: eax = 0x3f1164
	qdb[0x41A495]: eax = 0x3f122c
	```

* `flareqdb` can disassemble thanks to Vivisect:

	```
	flareqdb hello.exe -at 0x401000 "uf()"
	qdb: Running: hello.exe
	qdb: [0x401000]: Disassembling at 0x401000
	qdb:   0x401000: push ebp
	qdb:   0x401001: mov ebp,esp
	qdb:   0x401003: push ecx
	qdb:   0x401004: mov dword [ebp - 4],0
	qdb:   0x40100b: push 0x0040c000
	qdb:   0x401010: call 0x00401022
	qdb:   0x401015: add esp,4
	qdb:   0x401018: mov dword [ebp - 4],eax
	qdb:   0x40101b: mov eax,dword [ebp - 4]
	qdb:   0x40101e: mov esp,ebp
	qdb:   0x401020: pop ebp
	qdb:   0x401021: ret
	Hello, world!
	```

* `flareqdb` can set analyst-defined breakpoints depending upon register and
  memory values and so on. Here is a simple example (hanging indents added for
  clarity):

	```
	flareqdb funcptrhello -at 0x40100b "bp('poi(ebp-4)+8','da(0x40c000)')"
	qdb: Running: callfptr.exe
	qdb: [0x40100b]: Setting breakpoint at poi(ebp-4)+8 to execute da(0x40c000)
	qdb: [poi(ebp-4)+8=0x401028]: 0x40c000: Hello function pointer world!
	Hello function pointer world!
	```
