# De-DOSfuscator

De-DOSfuscator is a Python script included with flare-qdb that instruments
`cmd.exe` to decode obfuscated batch scripts by executing them.

The name is a play on Daniel Bohannon's paper,
[DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and Detection Techniques](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html).

The tool lives at `flareqdb/scripts/deDOSfuscator.py` and is installed by
`setup.py` as a Python entry point. It can be invoked from the Python `scripts`
directory (which in some cases may be added to the Windows path).

Its usage follows:

```
C:\Users\myself>dedosfuscator.exe --help
usage: dedosfuscator-script.py [-h] [--logdir LOGDIR] [--getoff path_to_cmd]
                               [--useoff symbolic_offset] [--fDumpParse]
                               [--nerf] [--sympath SYMPATH]
                               [--getpdb path_to_cmd]
                               [--dbghelp path_to_dbghelp_dll]

DeDOSfuscator: de-obfuscate batch files by executing them. You can get the
needed symbol offsets by running this script on a network-connected machine
with the --getoff switch which expects the path to a copy of the version of
cmd.exe that you plan to use in your isolated malware analysis environment.
You can then pass the resulting symbolic offset as an argument to the --useoff
switch which will use it for hooking cmd.exe. Once DeDOSfuscator is running,
change to the directory where your malicious batch file is located (in your
isolated or safe analysis environment), and invoke the batch file. If you
can't remember whether you're running under the DeDOSfuscator, type REM
status.

optional arguments:
  -h, --help            show this help message and exit
  --logdir LOGDIR       Override logging directory. Default: %CD%
  --getoff path_to_cmd  Get symbolic offsets for specified copy of cmd.exe
  --useoff symbolic_offset
                        Use symbolic offsets
  --fDumpParse          Use cmd-native AST dumping via fDumpParse
  --nerf                Don't allow commands to execute. Mutually exclusive
                        with --fDumpParse. Warnings: (1) In many cases your
                        malicious batch file will not work with this switch
                        enabled. (2) No guarantee is implied or expressed that
                        this will protect your system -- especially if you
                        provide invalid/incorrect offsets! (3) You won't be
                        able to exit normally, so instead exit by hitting
                        Ctrl+C.
  --sympath SYMPATH     Override symbol path. Default: SRV*C:\Symbols*http://m
                        sdl.microsoft.com/download/symbols
  --getpdb path_to_cmd  Just get the PDB for the specified copy of cmd.exe
  --dbghelp path_to_dbghelp_dll
                        Override path to a copy of dbghelp.dll. Default:
                        %CD%\dbghelp.dll
```

For examples and further context, see the blog:
[Cmd and Conquer: De-DOSfuscation with flare-qdb](https://www.fireeye.com/blog/threat-research/2018/11/cmd-and-conquer-de-dosfuscation-with-flare-qdb.html)
