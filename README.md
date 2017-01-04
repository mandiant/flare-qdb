# FireEye Labs Query-Oriented Debugger

flare-qdb is a command-line and scriptable Python-based tool for evaluating and
manipulating native program state. It uses
[Vivisect](https://github.com/vivisect/vivisect) to set a breakpoint on each
queried instruction and executes Python code when hit.

flare-qdb frees the analyst to take a nonlinear approach to dynamic analysis
that accommodates the questions that arise in the course of normal debugging
and static analysis. flare-qdb answers these questions without requiring the
analyst to manually set up an interactive debugger session and navigate the
program counter to that code location.

Here are some examples of spot questions flare-qdb can answer:

* Does eax always equal this value at this point?
* What was eax equal to before this branch?
* What values will this string assume throughout this loop?
* At the *first* iteration of the inner loop, what base address is used?
* Is the program even going to hit this logic?
* Which code executes first?
* Does the number of loop iterations depend on the value of `argv[1]`?
* Can I alter the command-line arguments to avoid this condition?

flare-qdb can also be used to facilitate automated, repeatable manipulation of
program execution. Here are some examples of useful applications:

* Executing a string decoder with different arguments to quickly extract all
  the strings used by a malware sample.
* Overriding the arguments to `Sleep()` to permit rapid iterative testing of
  a custom command and control (C2) server.
* Telling a privilege escalation tool that its integrity level is 0x1000
  (`MANDATORY_LOW_RID`) in order to induce it to execute its exploit code.
* Repeatably automating the unpacking of a packer that jumps into one or more
  non-deterministic heap locations.

flare-qdb accepts multiple queries that take the form of a program counter or
Vivisect expression paired with some Python text to evaluate in the flare-qdb
scripting environment. Vivisect expressions can be used to specify simple
constant program counter values like `"0x401000"`, symbolic expressions like
`"kernel32.Sleep"`, and more. Vivisect expressions can also incorporate
register and memory state to articulate sophisticated conditions, such as `"not
eax or (( edx > 3) and (poi(ebp-8) < 5))"`.

The command line argument format for this is:

	-at <vexpr-pc> <pythontext>

flare-qdb also supports conditional evaluation based on the truth value of a
Vivisect expression:

	-at-if <vexpr-pc> <vexpr-conds> <pythontext>

flare-qdb provides several builtins for convenient debugging, which are
available both from the command line and as methods of its `Qdb` class.

flare-qdb has been tested primarily on Windows, but works on Linux.
Unfortunately, the Darwin port of Vivisect's `vtrace.Trace` class is
incomplete, so flare-qdb does not support OSX.

## Detailed Information

Information about installing flare-qdb is available in the [Installation
Guide](doc/installation.md).

Information about using flare-qdb on the command line is available in the
[Command Line Usage Guide](doc/usage.md).

Information about scripting with flare-qdb is available in the [Scripting
Guide](doc/scripting.md). `Qdb` class methods specific to scripting flare-qdb
can be found in the [Methods Reference](doc/qdb_methods.txt).

A full reference of flare-qdb's builtins (available both from the CLI and as
instance methods) is available in the [Builtins
Reference](doc/qdb_builtins.txt) or by typing `flareqdb --help-builtins` after
installing flare-qdb.

Troubleshooting information can be found in the [Troubleshooting
Guide](doc/troubleshooting.md).

Acknowledgements and thoughts about future functionality that may be useful can
be found in the [Notes](doc/notes.md).
