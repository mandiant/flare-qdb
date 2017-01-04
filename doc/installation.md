# flare-qdb Installation Guide

## External Dependencies

Requires Invisigoth's Vivisect Python module:
[vivisect](https://github.com/vivisect/vivisect)

Vivisect only works under Python 2.7.

Willi Ballenthin provides a convenient zipball which can be used with pip even
on systems not having git or svn. It usually tracks with the Vivisect master
branch, but this is not guaranteed. To use it, type:

	pip install https://github.com/williballenthin/vivisect/zipball/master

## Installing flare-qdb

To install flare-qdb, run:

	python setup.py install

## A Note About Processor Architecture

Note that the processor architecture of the Python interpreter that is used to
run `setup.py` is significant. If you plan to debug both x86 and amd64 binaries
on your analysis system, then you will need to install both a 32- and 64-bit
version of Python and run `setup.py install` under each. When debugging, you
will need to match the architecture of the Python interpreter or script entry
point (e.g. `flareqdb.exe`) to the architecture of the binary you wish to run.
This is because flare-qdb depends on Vivisect, whose trace capabilities vary
based on the processor architecture of the Python interpreter in which it is
run.

## Known Working and Non-Working Platforms

flare-qdb relies heavily on Vivisect. It has been successfully installed and
tested on the following platforms, with the majority of testing taking place on
Windows 7 amd64:

* Windows 7 amd64 with Python 2.7.12 32- and 64-bit
* Windows XP x86 with Python 2.7.12 32-bit
* Ubuntu 16.04 LTS GNU/Linux amd64 with Python 2.7.12 64-bit
* Ubuntu 14.04.1 LTS GNU/Linux amd64 with Python 2.7.6 64-bit

When running on OSX, Vivisect reports that its Darwin port is incomplete;
flare-qdb does not work on this platform.
