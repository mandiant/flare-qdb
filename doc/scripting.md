# flare-qdb Scripting Guide

flare-qdb provides the `flareqdb` module (the hyphen is omitted). Module
`flareqdb` provides the `Qdb` class which can be used directly in Python
scripts.  There are two ways to script with flare-qdb. The first is by using
the `flareqdb` command line to import and execute script code. The second is by
writing and executing a custom script that imports and uses the `flareqdb`
module directly.

General information about scripting with the `Qdb` class is available in this
document.

Reference documentation of `Qdb` class methods for use in setting up a
debugging session can be found in the [flare-qdb Methods
Reference](qdb_methods.txt) which can be generated using the following command
line:

	python -c "import flareqdb; help(flareqdb.QdbMethodsMixin)"

Reference documentation for flare-qdb builtins that are also available as
instance methods can be found in the [flare-qdb Builtins
Reference](qdb_builtins.txt) which can be generated using the following command
line:

	python -c "import flareqdb; help(flareqdb.QdbBuiltinsMixin)"

## Scripting via the flareqdb Command Line

When flare-qdb queries outgrow the command line, it is possible to import
custom scripts and pass the instance of the `Qdb` class (named `q`) to the
script. A simple example:

    C:\Users\profile>REM May need to add . to Python path for modules
    C:\Users\profile>set PYTHONPATH=%PYTHONPATH%;%CD%

    C:\Users\profile>REM Implement module custom
    C:\Users\profile>echo def func(q): q.kill() > custom.py

    C:\Users\profile>REM When execution reaches 0x401000, import and call func
    C:\Users\profile>flareqdb hello.exe -at 0x401001 "import custom; custom.func(q)"
    qdb: Running: hello.exe
    qdb: [0x401001]: Killing debuggee
	qdb: Debuggee terminated without returning an exit code

## Scripting via the flareqdb Python Module

Analysts can also write Python scripts to import and use the `flareqdb` module
directly. Here is a simple template that can be used at the outset of a
reversing project. Starting with a list of queries is not essential, but makes
it easy to append and comment out queries during the reversing process.

```python
from flareqdb import Qdb

dbg = Qdb()

queries = [
    [0x401000, "kill();"],
]

dbg.add_queries(queries)
# Could also just use dbg.add_query(va, pythontext_or_callable)

dbg.run('mal.exe [arguments...]')
```

Script authors can supply Python text, callables, or mix and match when adding
queries. When using callables, it is necessary to define functions that conform
to the following specification:

```python
def callme(p, **kwargs):
	...
```

`p` is the dictionary of parameters (if any) passed in by the script author
during the call to `Qdb.run()`; these are provided as a dictionary so they can
be modified for stateful debugging and as output values. `kwargs` is a keyword
arguments dictionary containing copies of those same values plus the following
contextual items:

* `q` - This `Qdb` instance
* `qbp` - This breakpoint instance
* `trace` - The Vivisect Vtrace object for this `Qdb` instance
* `pc` - The current program counter
* `exprs` - Dictionary of virtual addresses that correspond to Vivisect
  expressions that were used to set breakpoints.

When evaluating Python text, `Qdb` provides locally available aliases to its
builtins (e.g.  `vex()` and `kill()`) to make for shorter command lines. When
executing a Python callable, `Qdb` does not support the builtin aliases.
Instead, script authors must either accept the `q` argument in their callable
or use globals, closures, classes, or another mechanism to be able to reference
the relevant `Qdb` instance. All `Qdb` methods can then be invoked using that
instance. For example:

```python
def print_rwx_park(p, q, trace, **kwargs):
	...
    q.detach()
```

## Scripting Examples

### Unpacking

Here is a more complex flare-qdb script to unpack malware and report the
locations of its unpacked code. This script uses callables and shows how output
parameters can be passed through `Qdb.run()`. It also uses the `park()`
method which suspends the process in an infinite loop and stores the old
program counter value so the analyst can attach with another debugger and
resume execution.

In this case, the packer's tailcall (where it transfers control into its
unpacked payload) is at address 0x41a738. The packer executes a `call edi`
instruction to transfer control to the original entry point (OEP). Once
execution reaches the instruction that is located 975 bytes ahead of the OEP,
the malware has unpacked six additional DLLs into heap memory allocated with
read/write/execute permissions.

This script creates a `Qdb` object, adds a single breakpoint at 0x41a738 to
execute `set_bps_before_tailcall()`, and runs the malware. When execution hits
0x41a738, `Qdb` calls `set_bps_before_tailcall()`.  This callback calls `q.bp()`
supplying the Vivisect expression `'edi-975'` and the callable
`print_rwx_park()` to set another breakpoint 975 bytes ahead of the OEP. When
execution reaches that point, `Qdb` calls `print_rwx_park()`. This callback
obtains the memory map from Vivisect via `trace.getMemoryMaps()`, stores it in
the parameters dictionary `p` under the key `'maps'`, and then parks and
detaches from the debuggee. After `Qdb.run()` terminates, the script iterates
through the memory map objects stored by `print_rwx_park()` and indicates the
base address and size of any regions having read/write/execute permission that
are not backed by a file. This is a common technique to detect injected code.

```python
from flareqdb import Qdb
from envi import memory as e_mem

def print_rwx_park(p, q, trace, **kwargs):
    print('All six packed PEs are loaded')
    p['maps'] = trace.getMemoryMaps()
    q.park()
    print('Detaching from pid ' + str(trace.pid))
    q.detach()

def set_bps_before_tailcall(p, q, **kwargs):
    q.bp('edi-975', print_rwx_park)

dbg = Qdb()
dbg.add_query(0x41a738, set_bps_before_tailcall)
params = {'maps': None}
dbg.run('static_sc_ldr.exe', params)

for (va, sz, p, filename) in params['maps']:
    if filename == u'' and p == e_mem.MM_RWX:
        print('\tRWX: ' + hex(va).rstrip('L') + ' L' + hex(sz).rstrip('L'))
```

It is not strictly necessary to pass parameters through `Qdb.run()`. The
following variation on the above example accomplishes the same end result by
implementing a class containing a state field that can be examined after the
bound callback routine has been called.

```python
from flareqdb import Qdb
from envi import memory as e_mem

class PrintRwxPark:
    def __init__(self): self.maps = None
    def callback(self, p, q, trace, **kwargs):
        print('All six packed PEs are loaded')
        self.maps = trace.getMemoryMaps()
        q.park()
        print('Detaching from pid ' + str(trace.pid))
        q.detach()

def set_bps_before_tailcall(p, q, **kwargs):
    q.bp('edi-975', handler.callback)

dbg = Qdb()
handler = PrintRwxPark()
dbg.add_query(0x41a738, set_bps_before_tailcall)
dbg.run('static_sc_ldr.exe')

for (va, sz, p, filename) in handler.maps:
    if filename == u'' and p == e_mem.MM_RWX:
        print('\tRWX: ' + hex(va).rstrip('L') + ' L' + hex(sz).rstrip('L'))
```

### String Decoding

Here is a flare-qdb script to decode the strings in a malware sample by running the
malware and manipulating the program counter and registers to decode each
string.

```python
from flareqdb import Qdb
import string

# This example code will execute the malware once per string it needs to
# decode, each time redirecting execution to the necessary locations and
# printing out the resulting string values. This malware sample uses constants
# that are found in a lookup table. We used Jay Smith's argtracker to collect
# all the locations where lookup arguments are pushed for this decoder and what
# their values are. We formatted this as a Python dictionary with key being the
# callsite and value being the list of values seen passed to the string decoder
# in the edx register. Some call sites to the decoder can be reached by
# multiple paths to allow the malware to conditionally decode one of many
# strings depending on conditions, hence the use of a list instead of a single
# value.

callsite_edx_lookup = {
    # va: [list, of, values, used],
    0x401012: [0x12345678],
    0x401313: [0x00001020, 0xf00df00d],
    0x401f00: [0x39a123b7],
    # ...
}

def decode(va, edx):
    # Prepare to run mal.exe
    dbg = Qdb()

    # After entry and stack initialization, move the program counter to an
    # arbitrarily chosen decoder call site and doctor up the arguments
    dbg.add_query(0x401010,
            "r('eip', 0x402054); r('edx', 'esp'); r('edx', " + hex(edx) + ");")

    # After the decoder call returns, print the result and terminate. The
    # "callsite" variable used here is provided in the Qdb.run() call,
    # subsequently.
    dbg.add_query(0x40205a,
            "print('Callsite: ' + hex(callsite)); da('esp'); kill();")

    # Run mal.exe, supplying the virtual address supplied in the arguments to
    # this Python callable but with the name "callsite"
    dbg.run('mal.exe', {'callsite': va})

# For each call site and group of values passed in via edx, iterate through the
# values and call decode.
for callsite, edx_array in callsite_edx_lookup.iteritems():
    for edx in edx_array:
        decode(callsite, edx)
```

### Overriding Function Output

It is also possible to hook and override API function output including return
values and output parameters. In the following example, the `vstruct`
definition of `OSVERSIONINFOEXW` is used to parse and modify the structure
returned by `kernel32.GetVersionExW`. This way of writing instrumentation is
closer to source code semantics, making the instrumentation easier to read and
maintain without referring to the program disassembly to understand or extend
what is being done. The example here and its output omit unnecessary
malware-specific details to focus on the technique at hand.

The script works by adding a query to execute `fix_GetVersionExW()` whenever
`kernel32.GetVersionExW` is called. The callback checks if the return address
corresponds to the desired call site. It then gets the first argument which is
the pointer to an `OSVERSIONINFOEXW` structure provided by the caller. Finally,
it calls the `retcallback()` method of the `Qdb` object to execute a callback
before the function returns. It passes a closure that will use the definition
of `OSVERSIONINFOEXW` provided by `vstruct.defs.win32` to modify the major and
minor version reported by the operating system. The `readstruct()` and
`writestruct()` convenience methods allow memory to be read and written as a
`vstruct` for this purpose.

NOTE: the `get_retaddr()` and `get_push_arg()` methods can only be executed
before a function's prolog has executed.

```python
from flareqdb import Qdb
from vstruct.defs.win32 import OSVERSIONINFOEXW

winvers = [
    (3,1, 'NT 3.1'), (3,5, 'NT 3.5'), (3,51, 'NT 3.51'), (4,0, 'NT 4.0'),
    (5,0, 'W2K'), (5,1, 'XP'), (5,2, 'WS03'), (6,0, 'Vista/WS08'),
    (6,1, 'W7/WS08R2'), (6,2, 'W8/WS12'), (6,3, 'W8.1/WS12R2'), (10,0, 'WX'),
]

ver = lambda maj, min: str(maj) + '.' + str(min)

lpVersionInfo = None

def fix_GetVersionExW(p, q, min, maj, **kwargs):
    global lpVersionInfo
    def GetVersionExW_ret_closure():
        osvi = q.readstruct(OSVERSIONINFOEXW, lpVersionInfo, 0x11c)
        cur = ver(osvi.dwMajorVersion, osvi.dwMinorVersion)
        print('GetVersionExW   ' + cur + ' => ' + ver(maj, min))
        osvi.dwMajorVersion, osvi.dwMinorVersion = maj, min
        q.writestruct(lpVersionInfo, osvi)

    if 0x4010a8 == q.get_retaddr():  # Only fix up calls from one location
        lpVersionInfo = q.get_push_arg(0)  # Get lpVersionInfo address
        q.retcallback(GetVersionExW_ret_closure) # Fix up maj,min @ ret

dbg = Qdb()
dbg.add_query('kernel32.GetVersionExW', fix_GetVersionExW)
dbg.add_query(0x401443, "print('\tRUNS on ' + os); kill()")
dbg.add_query(0x401eae, "print('\tBailed on ' + os); kill()")

for mj, mn, name in winvers:
    dbg.run('sample.exe', {'os': name, 'maj': mj, 'min': mn})
```

The output from this is as follows:

```
GetVersionExW   6.1 => 3.1
        Bailed on NT 3.1
GetVersionExW   6.1 => 3.5
        Bailed on NT 3.5
GetVersionExW   6.1 => 3.51
        Bailed on NT 3.51
GetVersionExW   6.1 => 4.0
        Bailed on NT 4.0
GetVersionExW   6.1 => 5.0
        Bailed on W2K
GetVersionExW   6.1 => 5.1
        RUNS on XP
GetVersionExW   6.1 => 5.2
        RUNS on WS03
GetVersionExW   6.1 => 6.0
        RUNS on Vista/WS08
GetVersionExW   6.1 => 6.1
        RUNS on W7/WS08R2
GetVersionExW   6.1 => 6.2
        Bailed on W8/WS12
GetVersionExW   6.1 => 6.3
        Bailed on W8.1/WS12R2
GetVersionExW   6.1 => 10.0
        Bailed on WX
```

Arbitrary structures can be represented as a `vstruct` and read/modified in
this way. Many common API structures are already defined for various platforms
within `vstruct.defs`. See the [vivisect](https://github.com/vivisect/vivisect)
project for more details.

### Exception Handling

`flareqdb` provides the `QdbBpException` class to encapsulate exceptions that
occur within breakpoints which would otherwise be swallowed by Vtrace. It
includes the following fields:

* `message` - qdb-specific exception description
* `detail` - Expression or callable name that caused the exception
* `error` - Value of `sys.exc_info()[1]` at the exception site
* `exception` - Original exception
* `backtrace` - Traceback list from `traceback.extract_tb(sys.exc_info()[2])`

An example follows:

```python
import traceback
from flareqdb import Qdb, QdbBpException

dbg = Qdb()
dbg.add_query(0x401000, 'asdf')
try:
    dbg.run('hello.exe')
except QdbBpException as e:
    print('str(): ' + str(e))
    print('Message: "' + e.message + '"')
    print('Detail: "' + e.detail + '"')
    print('Error: "' + e.error + '"')
    print('Exception type: ' + str(type(e.exception)))
    print('Backtrace:')
    for s in traceback.format_list(e.backtrace):
        print('\t' + s)
```

Output:

```
str(): Error evaluating expression "asdf": name 'asdf' is not defined
Message: "Error evaluating expression"
Detail: "asdf"
Error: "name 'asdf' is not defined"
Exception type: <type 'exceptions.NameError'>
Backtrace:
      File "C:\path\to\flareqdb\__init__.py", line 671, in dispatch_expr
    exec(expr, g, q._locals)

      File "<string>", line 1, in <module>
```

