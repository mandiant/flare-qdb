# coding: utf-8
# Copyright (C) 2016 FireEye, Inc. All Rights Reserved.

"""Query-oriented debugger."""

from __future__ import print_function

import os
import re
import sys
import types
import ctypes
import string
import struct
import vtrace
import inspect
import logging
import argparse
import traceback
import itertools
from collections import defaultdict
from collections import namedtuple

__author__ = 'Michael Bailey'
__copyright__ = 'Copyright (C) 2016 FireEye'
__license__ = 'Apache License'
__version__ = '1.0.3'

logger = logging.getLogger(__name__)


ONE_MB = 1024 * 1024
UNPACK_FMTS = {
    1: 'B',
    2: 'H',
    4: 'I',
    8: 'Q',
}
_SPECIAL_ALIASES = [
    [r'\?', 'vex'],
]

StackTraceEntry = namedtuple('StackTraceEntry', 'nr bp ret pc pc_s')


class QdbBpException(Exception):
    """In-breakpoint exception class.

    vtrace breakpoints swallow exceptions within the notify() routine. Even
    though all malware analysis should take place in a safe environment, it
    is often inconvenient for faulty assumptions or code to result in malware
    being allowed to run free. Hence, qdb halts the debuggee if the user's
    query precipitates an exception, and this class is how the original
    exception information is stored and later delivered to the caller of
    Qdb.run().
    """

    def __init__(self, message, detail, err, ex, bt):
        super(QdbBpException, self).__init__(message)
        self.detail = detail  # Python expression OR callable name
        self.error = err
        self.exception = ex
        self.backtrace = bt

    def __str__(self):
        errstr = ': ' + str(self.error) if self.error else ''
        return self.message + ' "' + self.detail + '"' + errstr


class UnparkSpec:
    """Unparking specification enumeration.

    For details, see Qdb.unpark().
    """

    First, Any, All, Specific = range(4)


class StepType:
    """Step specification enumeration.

    For details, see Qdb.retcallback().
    """

    stepo, stepi = range(2)


class QdbMethodsMixin:
    """Instance methods most likely to be used in a script for setting up a
    qdb session rather than in a breakpoint context.

    These are not aliased as unbound methods in the namespace.
    """

    def attach(self, pid):
        """Attach to pid, add queries, and execute.

        Parameters
        ----------
        pid : int
            Process ID to attach to
        returns:
            True
        """
        if self._trace is not None:
            return False

        self._prepareTrace(lambda trace: trace.attach(pid))

        self._conout('Attached to PID ' + str(pid))

        return True

    def run(self, cmdline=None, parameters={}):
        """Apply permanent queries and execute cmdline.

        Parameters
        ----------
        cmdline : str
            Program and arguments to run. Can be None only if attach() has been
            called successfully.
        parameters : dict
            Optional parameters to pass to breakpoint callables/expressions.
        returns
            bool : True unless an unhandled exception occurred in a breakpoint
        """
        if not cmdline and not self._trace:
            raise ValueError('Cannot run unattached qdb without cmdline')

        if not self._trace:
            self._prepareTrace(lambda trace: trace.execute(cmdline))

        self._parameters = parameters
        self._add_queries_ephemeral()

        if cmdline:
            self._conout('Running: ' + str(cmdline))
        else:
            self._conout('Running: PID ' + str(self._trace.getPid()))

        self._bp_unknown_fail = False
        self._stored_exception = None

        # If initialization code was specified, give it first dibs
        if self._init_code:
            self._eval_exprs(self._init_code, self._exprs)

        # If kill() is called in init code, respect it
        if self._runnable:
            self._trace.run()

        if self._trace.exited:
            self._exitcode = self._trace.getMeta('ExitCode')

        if self._trace.attached and not self._trace.exited:
            self._trace.kill()

        self._trace.release()

        self._trace = None

        if self._stored_exception is not None:
            raise self._stored_exception

        return (not self._bp_unknown_fail)

    def clear_queries(self):
        """Remove all permanent queries.

        Does not remove ephemeral queries. For details, see add_query() and
        add_query_ephemeral().
        """
        self._queries = []
        self._exprs = {}
        self._exprs_delayed = {}

    def clear_counts(self):
        """Clear breakpoint hit counts that are maintained by the count()
        function.
        """
        self.counts = defaultdict(int)

    def setInitCode(self, code):
        """Set Python text to be executed upon program execution."""
        self._init_code = code

    def add_query(self, vexpr_pc, query, conds=None):
        """Add a single permanent query with an optional conditional
        expression.

        Permanent queries are tracked in a list, and that list is processed
        every time run() is invoked, which can be more than once. To add an
        ephemeral query (only for the current run of the binary), use the bp()
        method instead. To add a query to both a live run and future runs, you
        must invoke both bp() (for the current run) and add_query() (for future
        runs).

        Parameters
        ----------
        vexpr_pc : int or str
            * If an int, this is the program counter virtual address value upon
              which to evaluate :query:.
            * If a str, this is a Vivisect expression that will be evaluated
              when the `run()` is called to calculate the virtual address.
        query : str or callable
            * If a str, this is Python text that will be evaluated in module
              context.
            * If a callable, the function object will be deep copied and its
              `func_globals` attribute will be replaced with a copy of the
              original `func_globals`, augmented to include `context` and
              the contents of the `parameters` dictionary (if any) specified
              when callign `run()`.
        """
        self._queries.append([vexpr_pc, query, conds])

    def add_queries(self, queries):
        """Add multiple queries simultaneously.

        Each query must have two elements (a program counter and some Python to
        evaluate) or three elements (a conditional expression to also
        evaluate).

        Parameters
        ----------
        queries : list(list)
            List of queries
        """
        for query in queries:
            self.add_query(*query)

    def add_query_ephemeral(self, vexpr_pc, query, conds,
                            preserve_sym_name=True):
        """Add query for the current run only.

        If you wish to add a query to future runs as well as the current run,
        you must invoke add_query() (for future runs) as well as
        add_query_ephemeral() (for this run).

        Parameters
        vexpr_pc : vexpr (int or str)
            Vivisect expression or integer program counter value
        query : str or callable
            Python script text or a Python callable
        conds : vexpr (int or str)
            Vivisect expression or integer qualifying condition whose truth
            value will determine whether the query is executed or not each time
            the program counter hits this location.
        preserve_sym_name : bool
            Whether to preserve symbolic name from vexpr_pc
        """
        va = vexpr_pc
        try:
            va = int(vexpr_pc)
        except ValueError:
            va = self._vex(vexpr_pc)
            if str(vexpr_pc).lower() != phex(va).lower():
                vexpr_pc = (vexpr_pc + '=' +
                            phex(va))
            else:
                vexpr_pc = vexpr_pc

        if not preserve_sym_name:
            vexpr_pc = va

        self._exprs[va] = {}

        try:
            vexpr_pc = phex(vexpr_pc)
        except TypeError:
            pass

        self._exprs[va]['sym'] = vexpr_pc

        return self._trace.addBreakpoint(QdbBreak(self, va, query, conds))


class QdbBuiltinsMixin:
    """Instance methods that will serve as builtins for Python text evaluated
    within the qdb environment.

    The effect of this is that queries can call these instance methods without
    specifying any instance. This makes for shorter, simpler command line
    syntax.

    For example, an instance method that might otherwise require an instance as
    follows:

        q.kill()

    Can be called when evaluating Python text by typing simply:

        "kill()"

    This allows for syntactic convenience in the CLI and in scripts that
    specify queries in the form of Python text instead of as callables.

    This behavior is implemented by Qdb._setupBuiltins() which adds an unbound
    function to the locals namespace for every instance method that comes from
    QdbBuiltinsMixin.
    """

    def vex(self, vexpr):
        """Evaluate Vivisect expression in context of debuggee. Alias: ?().

        Examples:
            q.vex('poi(edi) + 4')
            "vex('eax * 2')"
            "?('eax * 2')"

        Parameters
        ----------
        vexpr : str or int
            Vivisect expression or integer literal. Vivisect expressions are
            evaluated against the debuggee's process address space and register
            file. Integer literals are returned as-is.
        returns:
            int : Result of Vivisect expression evaluation.
        """
        result = self._vex(vexpr)
        self._conout_pc(str(vexpr) + ' = ' + phex_dec(result))
        return result

    def get_pc(self):
        """Get the program counter of the currently selected thread within the
        debuggee.
        """
        return self._trace.getProgramCounter()

    def get_pcs(self):
        """Get dictionary of thread ID => program counter pairs.

        Returns:
            dict: tid => program counter
        """
        old_tid = self._trace.getCurrentThread()
        pcs = {}

        for tid in self._trace.getThreads():
            self._trace.selectThread(tid)
            pc = self._trace.getProgramCounter()
            pcs[tid] = pc

        self._trace.selectThread(old_tid)
        return pcs

    def k(self, depth=None):
        """WinDbg-style alias for stack backtrace.
        
        For details, see stacktrace().
        """
        return self.stacktrace(depth)

    def stacktrace(self, depth=None):
        """Obtain a stack backtrace.

        Currently only supported for x86 targets.

        Parameters
        ----------
        depth : int or NoneType
            Desired stack trace depth
        returns: list(StackTraceEntry)
            list of (frame number, ebp, ret, eip, and symbolic eip)
        """
        arch = self._trace.getMeta('Architecture')
        if arch not in self._stacktrace_impl:
            raise NotImplementedError('Stack trace is only available for %s' %
                                      ','.join(self._stacktrace_impl))

        archwidth = self._archWidth()

        self._conout_pc('Stack trace')
        if archwidth == 4:
            header = ' # Child-SP RetAddr  Call Site'
        elif archwidth == 8:
            # Header is ready but that's it; see above NotImplementedError ;-)
            header = ' # Child-SP          RetAddr           Call Site'
        else:
            raise ValueError('Unhandled architecture width %d' % (archwidth))
        self._conout(header)

        return self._stacktrace_impl[arch](archwidth, depth)

    def get_exitcode(self):
        """Get the exit code, valid only if the program has terminated."""
        return self._exitcode

    def get_pid(self):
        """Get the PID of the debuggee.

        Returns:
            int: PID.
        """
        return self._trace.getPid()

    def get_tid(self):
        """Get the TID of the currently selected thread.

        Returns:
            int: TID.
        """
        return self._trace.getCurrentThread()

    def bp(self, vexpr_pc, query):
        """Add a breakpoint to execute a query.

        Examples:
            q.bp(0x401000, process_main)
            q.bp(0x401000, "uf()")
            "bp(0x401000, 'uf()')"

        Parameters
        ----------
        vexpr_pc : str or int
            Vivisect expression or integer expressing the virtual address at
            which to break execution and execute the query.
        query : str or callable
            Python text or a Python callable to execute upon hitting this
            breakpoint.
        returns:
            int: Trace Breakpoint ID.
        """
        self._conout_pc('Setting breakpoint at ' + hex_or_str(vexpr_pc) +
                        ' to execute ' + str(query))
        return self.add_query_ephemeral(vexpr_pc, query, None)

    def get_retaddr(self):
        """Get return address.

        Assumes i386.
        Assumes the prolog has not yet been executed.
        """
        return self._vex('poi(esp)')

    def get_push_arg(self, argno):
        """Get argument from stack.

        Assumes i386.
        Assumes the prolog has not yet executed.

        Parameters
        ----------
        argno : int
            Number of the argument to get, zero-based.
        """
        esp = self._vex('esp')
        width = self._archWidth()
        off = esp + width * (1 + argno)
        data = self.readmem(off, 1, 4, None)
        dw = struct.unpack('@I', data)[0]

        return dw

    def retcallback(self, cb_ret=None, limit=16384, steptype=StepType.stepo):
        """
        Parameters
        ----------
        cb_ret : callable
            Callback to execute upon finding the final return instruction.
        limit : int
            Maximum number of instructions to execute before giving up. Zero
            means infinite.
        steptype : StepType enumeration member
            StepType.stepi: step into calls
            StepType.stepo: step over calls
        """
        if steptype not in [StepType.stepo, StepType.stepi]:
            raise ValueError('Invalid steptype specified')

        retcallback_stepx = None

        if steptype == StepType.stepo:
            retcallback_stepx = self._retcallback_stepo
        elif steptype == StepType.stepi:
            retcallback_stepx = self._retcallback_stepi

        return retcallback_stepx(cb_ret, limit)

    def gu(self, nframes=1, limit=16384, steptype=StepType.stepo):
        """Go up one frame.

        Executes stepwise until function return and executes the return.
        Optional nframes argument controls repetition of this operation.

        Parameters
        ----------
        nframes : int
            Number of times to go up.
        limit : int
            Maximum number of instructions to traverse searching for each
            function return.
        steptype : StepType enumeration member
            See retcallback() documentation for details.
        """

        for f in range(nframes):
            self.retcallback(None, limit)  # Until return
            self.stepi()  # And one more

    def stepi(self):
        self._trace.stepi()

    def stepo(self):
        op = self._trace.parseOpcode(self._trace.getProgramCounter())
        if op.isCall():
            next = op.va + op.size
            id = self._trace.addBreakByAddr(next)
            self._trace.setMode
            self._trace.setMode('RunForever', False)
            self._trace.run()
            self._trace.setMode('RunForever', True)
            self._trace.removeBreakpoint(id)
        else:
            self.stepi()

    def retwatch(self, limit=16384, steptype=StepType.stepo):
        """Step the program counter, ignoring breakpoints, until a return
        instruction is found, and then return the value stored in eax/rax.

        Parameters
        ----------
        limit : int
            Maximum number of instructions to execute before giving up. Zero
            means infinite.
        returns:
            Value in the return value register (rax/eax) at the ret
            instruction.
        """
        xax = self._archRetRegName()

        def retwatch_callback_closure():
            retval = self._vex(xax)
            self._conout_pc('Collecting return value ' + phex_dec(retval))
            return retval

        return self.retcallback(retwatch_callback_closure, limit, steptype)

    def retset(self, vexpr_val, limit=16384, steptype=StepType.stepo):
        """Step the program counter, ignoring breakpoints, until a return
        instruction is found, and then alter the value stored in eax/rax.

        Examples:
            "retset('eax-1')"

        Parameters
        ----------
        vexpr_val : str or int
            Vivisect expression expressing the value to set in the return
            address register (rax/eax) before returning.
        limit : int
            Maximum number of instructions to execute before giving up. Zero
            means infinite.
        returns:
            Value in the return value register (rax/eax) after the replacement
            instruction.
        """

        xax = self._archRetRegName()

        def retset_callback_closure():
            val = self._vex(vexpr_val)
            self._conout_pc('Setting return value <= ' + phex_dec(val))
            self._trace.setRegisterByName(xax, val)
            return self._vex(xax)

        return self.retcallback(retset_callback_closure, limit, steptype)

    def detach(self):
        """Detach from debuggee, leaving it running.

        Returns:
            int: PID.
        """
        pid = self._trace.getPid()
        self._conout_pc('Detaching from PID ' + str(pid))
        self._trace.detach()
        self._runnable = False

        # The trace object should neither be released nor set to None here.
        # This is called in a breakpoint context under Qdb.run(). Calling
        # Vtrace.detach() will already cause Vtrace.run() to terminate, which
        # will precipitate close-out processing in Qdb.run() that takes care of
        # calling Vtrace.release() and setting the trace object to None.

        return pid  # Useful if you subsequently want to use Qdb.attach()

    def kill(self):
        """Halt further execution from within a breakpoint context.

        Returns:
            bool: True.
        """
        self._conout_pc('Killing debuggee')
        self._halt()
        self._runnable = False
        return True

    def _forEachThreadOpenAndDo(self, cb):
        """Open all threads and execute a callback on each"""
        THREAD_ALL_ACCESS = 0x1fffff

        retval = True

        for tid, tinfo in self._trace.getThreads().items():
            ht = ctypes.windll.kernel32.OpenThread(THREAD_ALL_ACCESS, 0, tid)
            if ht:
                retval = retval and cb(tid, ht)
                ctypes.windll.kernel32.CloseHandle(ht)
            else:
                retval = False

        return retval

    def suspend(self):
        """Suspend all threads in the debuggee"""
        def cbSuspendThread(tid, ht):
            sc = ctypes.windll.kernel32.SuspendThread(ht)
            self._conout_pc('Suspended TID %s => suspend count %d' %
                            (phex(tid), sc))
            return (sc != -1)

        return self._forEachThreadOpenAndDo(cbSuspendThread)

    def resume(self):
        """Resume all threads in the debuggee"""
        def cbResumeThread(tid, ht):
            sc = ctypes.windll.kernel32.ResumeThread(ht)
            self._conout_pc('Resumed TID %s => suspend count %d' %
                            (phex(tid), sc))
            return (sc != -1)

        return self._forEachThreadOpenAndDo(cbResumeThread)


    def park(self, tid=None):
        """Place the debuggee in an infinite loop.

        Allocates memory, writes an infinite loop to that memory, writes the
        current value of the program counter after the loop, and finally
        updates the program counter to execute the infinite loop.

        This allows another debugger to attach to the process. The analyst can
        then manually or programmatically alter the program counter register to
        resume execution at the program counter value stored after the loop.

        This function does not detach from the process; the user must call
        detach() when ready.

        Examples:
            q.park()  # Park current thread
            q.park(some_tid)  # Park some other thread

            "park()"
            "park(some_tid)"

        Parameters
        ----------
        tid : int
            Thread ID to park. If not specified, qdb parks the current thread.
        returns:
            tuple: original PC, new PC, tid).
        """
        pc = self._trace.getProgramCounter()

        if tid:
            self._trace.selectThread(tid)

        len_rip_eip = 8  # Eight bytes for either eip or rip
        alloc_len = len(self._park_code_template) + len_rip_eip

        m = self._trace.allocateMemory(alloc_len)
        pc_packed = struct.pack('@Q', pc)  # Pack as 8 bytes regardless of arch
        self._trace.writeMemory(m, self._park_code_template)
        self._trace.writeMemory(m + len(self._park_code_template), pc_packed)

        self._conout_pc('Parking debuggee at ' + phex(m) + ', from PC ' +
                        phex(pc))

        self._trace.setProgramCounter(m)

        tid = self._trace.getCurrentThread()
        return (pc, m, tid)  # Return old and new PC and TID

    def unpark(self, spec=UnparkSpec.First, tid=None):
        """Verify that the specified thread(s) have been parked, read the
        stored program counter value after the infinite infloop code, and set
        the program counter register to that value.

        For details on what parking means, see the documentation for park().

        This function only sets the program counter and does not automatically
        resume execution; the user must call run() when ready.

        This function will raise an exception if the specified thread or
        threads are not found to be parked.

        Examples:
            q = flareqdb.Qdb()
            q.attach(int(sys.argv[1], 10))
            q.unpark()
            q.run()

            "unpark(UnparkSpec.Specific, saved_tid)"  # Unpark some thread

        Parameters
        ----------
        spec : UnparkSpec enumeration member.
            Four possibilities:
            * UnparkSpec.First: Unpark the first parked thread found.
            * UnparkSpec.Any: Unpark any parked threads found.
            * UnparkSpec.All: Unpark all threads.
            * UnparkSpec.Specific: Unpark the thread specified by tid.
        tid : int
            Thread ID to unpark.
        """
        if tid and (spec != UnparkSpec.Specific):
            raise ValueError('tid specified without UnparkSpec.Specific')

        to_unpark = []

        if spec == UnparkSpec.Specific:
            tid_ok, pc = self._check_parked(tid)
            if tid_ok:
                to_unpark.append((tid_ok, pc))
        else:  # Find the parked thread
            for tid in self._trace.getThreads():
                tid_ok, pc = None, None
                tid_ok, pc = self._check_parked(tid)
                if tid_ok:
                    to_unpark.append((tid_ok, pc))
                    if spec == UnparkSpec.First:
                        break
                elif spec == UnparkSpec.All:
                    raise ValueError('One or more threads not parked')

        if not len(to_unpark):
            raise ValueError('Not parked, cannot unpark')

        for tid, pc in to_unpark:
            self._unpark(tid, pc)

    def hit(self):
        """Indicate on the console that a location was hit.

        returns:
            bool: True - useful for setting a flag.
        """
        self._conout_pc('Hit')
        return True

    def count(self):
        """Accumulate a count of occasions when a location was hit.

        The counts are stored in (and can be retrieved from) the dictionary
        self.counts in which each key is the symbolic name for a program
        counter value and each value is the number of times an instruction at
        that location was executed.

        returns:
            int: Current count for this location.
        """
        prettypc = self._pretty_pc()
        self.counts[prettypc] = self.counts[prettypc] + 1
        return self.counts[prettypc]

    def _getmodoff(self, vexpr_va):
        va = self._vex(vexpr_va)
        maps = self._trace.getMemoryMaps()
        for (va_start, sz, p, filename) in maps:
            if filename and (va_start < va) and (va < (va_start + sz)):
                off = va - va_start
                basename = os.path.splitext(os.path.basename(filename))[0]
                return '%s+%s' % (basename, phex(off))

        return None

    def _getsym(self, vexpr_va):
        """Quietly get the symbol associated with a location. Alias: ln.

        No console output.

        Parameters
        ----------
        vexpr_va : str
            Vivisect expression indicating the virtual address for which to
            resolve the symbol name.
        returns:
            str: Symbol name or None if unknown.
        """
        va = self._vex(vexpr_va)
        return self._trace.getSymByAddrThunkAware(va)[0]

    def getsym(self, vexpr_va):
        """Get the symbol associated with a location. Alias: ln.

        Parameters
        ----------
        vexpr_va : str
            Vivisect expression indicating the virtual address for which to
            resolve the symbol name.
        returns:
            str: Symbol name or '(unknown)' if unknown.
        """
        va = self._vex(vexpr_va)
        sym_instance = self._getsym(va)
        symname = '(unknown)' if sym_instance is None else str(sym_instance)
        self._conout_pc('Symbol for ' + str(vexpr_va) + ' = ' + phex(va) +
                        ' = ' + str(symname))
        return symname

    def ln(self, vexpr_va):
        """Alias for getsym."""
        return self.getsym(vexpr_va)

    def setreg(self, vexpr_reg, vexpr_val):
        """Set a register to a value. Quasi-alias: r.

        Examples:
            q.setreg('eax', 0)
            "setreg('eax', 0)"

        Parameters
        ----------
        vexpr_reg : str
            Register of concern. Can be any width supported by the architecture
            of the debuggee. For instance, eax can be accessed as 'eax', 'ax',
            'al', or 'ah'. On 64-bit debuggees, rax can also be accessed as
            'rax'.
        vexpr_val : str or int
            Vivisect expression or integer value to assign to the register
            specified by vexpr_reg.
        """
        val = self._vex(vexpr_val)
        self._conout_pc('Setting ' + str(vexpr_reg) + ' <= ' + phex(val))
        self._trace.setRegisterByName(vexpr_reg, val)
        return val

    def r(self, vexpr_reg, vexpr_val=None):
        """Get or set a register.

        Examples:
            q.r('eax')
            q.r('eax', 0)

            "r('eax')"
            "r('eax', 0)"

        Parameters
        ----------
        vexpr_reg : str
            Register of concern. Can be any width supported by the architecture
            of the debuggee. For instance, eax can be accessed as 'eax', 'ax',
            'al', or 'ah'. On 64-bit debuggees, rax can also be accessed as
            'rax'.
        vexpr_val : str or int, optional
            Optional Vivisect expression or integer value to assign to the
            register specified by vexpr_reg. If this is not specified, then the
            value of the register is merely retrieved.
        """
        if vexpr_val is None:
            return self.vex(vexpr_reg)
        else:
            return self.setreg(vexpr_reg, vexpr_val)

    def readmem(self, vexpr_va, elements, element_size, sentinel):
        """Read a range of bytes.

        Caller must either specify a non-zero number of elements, or specify a
        sentinel value upon which to stop, whose size must match element_size.
        Optional limit protects from run-away read, mainly intended for when a
        sentinel value is never encountered but enforced in the fixed range
        read as well for consistency.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer value expressing the virtual address
            at which to read memory.
        elements : int
            Number of elements of size element_size to read.
        element_size : int
            Size of each element.
        sentinel : str
            Sentinel element value upon which to stop.
        """
        va = self._vex(vexpr_va)
        try:
            return self._readMemUnsafe(va, elements, element_size, sentinel,
                                       ONE_MB)
        except vtrace.PlatformException:
            self._conout('Exception reading virtual address ' + phex(va))
            return b''

    def readstruct(self, factory, vexpr_va, vexpr_size=0):
        """Read a vstruct from memory.

        Parameters
        ----------
        factory : callable
            e.g. vstruct.defs.win32.OSVERSIONINFOEXW
        vexpr_va : str or int
            Vivisect expression or integer indicating the virtual address to
            read from.
        vexpr_size : str or int
            Vivisect expression or integer indicating the size to read.
            Default (0) will read up to the next page boundary.
        """
        stru = factory()
        base = self._vex(vexpr_va)
        size = self._vex(vexpr_size) if vexpr_size else len(stru)
        bytes = self.readmem(base, 1, size, None)
        stru.vsParse(bytes)
        return stru

    def writestruct(self, vexpr_va, stru):
        """Write a vstruct to memory.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer indicating the virtual address to
            read from.
        stru : vstruct
            Vivisect vstruct to write to memory.
        """
        bytes = stru.vsEmit()
        base = self._vex(vexpr_va)
        self._trace.writeMemory(base, bytes)

    def eu(self, vexpr_dst, s):
        """Edit (write) Unicode string without terminating NULL.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        s : str
            String to write.
        """
        self._strcpy_aw(vexpr_dst, s, True, False)

    def ea(self, vexpr_dst, s):
        """Edit (write) ASCII string without terminating NULL.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        s : str
            String to write.
        """
        self._strcpy_aw(vexpr_dst, s, False, False)

    def ezu(self, vexpr_dst, s):
        """Edit (write) Unicode string with terminating NULL.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        s : str
            String to write.
        """
        self._strcpy_aw(vexpr_dst, s, True, True)

    def eza(self, vexpr_dst, s):
        """Edit (write) ASCII string with terminating NULL.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        s : str
            String to write.
        """
        self._strcpy_aw(vexpr_dst, s, False, True)

    def writemem(self, vexpr_dst, bytes):
        """Write bytes to memory.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        bytes : string
            String of bytes to write.
        """
        addr = self._vex(vexpr_dst)
        self._trace.writeMemory(addr, bytes)
        self._conout_pc('Wrote ' + dec_phex(len(bytes)) + ' bytes to ' +
                        phex(addr))

    def eb(self, vexpr_dst, bytes):
        """Edit (write) one or more bytes.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        bytes : string
            Bytes to write.
        """
        if isinstance(bytes, str):  # Strings get turned into lists of bytes
            bytes = [ord(b) for b in bytes]
        self._ex(vexpr_dst, bytes, 1)

    def _ex(self, vexpr_dst, n, w):
        if isinstance(n, int):
            self.writemem(vexpr_dst, struct.pack('@' + UNPACK_FMTS[w], n))
        else:
            fmt = '@%s%s' % (len(n), UNPACK_FMTS[w])
            self.writemem(self._vex(vexpr_dst), struct.pack(fmt, *n))

    def eq(self, vexpr_dst, n):
        """Edit (write) quadword.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        n : int
            Value to write.
        """
        self._ex(vexpr_dst, n, 8)

    def ed(self, vexpr_dst, n):
        """Edit (write) dword.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        n : int or list
            Value(s) to write.
        """
        self._ex(vexpr_dst, n, 4)

    def ew(self, vexpr_dst, n):
        """Edit (write) word.

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        n : int
            Value to write.
        """
        self._ex(vexpr_dst, n, 2)

    def memcpy(self, vexpr_dst, vexpr_src, vexpr_n):
        """Copy vexpr_n bytes from vexpr_src to vexpr_dst within debuggee.

        Examples:
            q.memcpy('edi', 'esi', 1024)
            "memcpy('edi', 'esi', 1024)"

        Parameters
        ----------
        vexpr_dst : str or int
            Vivisect expression or integer value expressing the destination
            virtual address to write to.
        vexpr_src : str or int
            Vivisect expression or integer value expressing the soruce virtual
            address to read from.
        vexpr_n : int
            Number of bytes to read.
        """
        src = self._vex(vexpr_src)
        n = self._vex(vexpr_n)
        bytes = self._trace.readMemory(src, n)
        self.writemem(vexpr_dst, bytes)

    def dq(self, vexpr_va, n=16):
        """Dump n quadwords(s) starting at vexpr_va.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer value expressing the virtual address
            to start at.
        n : int
            Number of elements to dump.
        returns:
            list: array of elements retrieved from vexpr_va.
        """
        return self._dx(vexpr_va, Qdb._handle_dq, n)

    def dd(self, vexpr_va, n=32):
        """Dump n DWORD(s) starting at vexpr_va.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer value expressing the virtual address
            to start at.
        n : int
            Number of elements to dump.
        returns:
            list: array of elements retrieved from vexpr_va.
        """
        return self._dx(vexpr_va, Qdb._handle_dd, n)

    def dw(self, vexpr_va, n=64):
        """Dump n word(s) starting at vexpr_va.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer value expressing the virtual address
            to start at.
        n : int
            Number of elements to dump.
        returns:
            list: array of elements retrieved from vexpr_va.
        """
        return self._dx(vexpr_va, Qdb._handle_dw, n)

    def db(self, vexpr_va, n=128):
        """Dump n byte(s) starting at vexpr_va.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer value expressing the virtual address
            to start at.
        n : int
            Number of elements to dump.
        returns:
            list: array of elements retrieved from vexpr_va.
        """
        return self._dx(vexpr_va, Qdb._handle_db, n)

    def da(self, vexpr_va, cc=0):
        """Dump cc characters of ASCII string starting at vexpr_va.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer value expressing the virtual address
            to start at.
        cc : int
            Number of characters to dump.
        returns:
            str: string retrieved from vexpr_va.
        """
        return self._dx(vexpr_va, Qdb._handle_da, cc)

    def du(self, vexpr_va, cc=0):
        """Dump cc characters of Unicode string starting at vexpr_va.

        Parameters
        ----------
        vexpr_va : str or int
            Vivisect expression or integer value expressing the virtual address
            to start at.
        cc : int
            Number of characters to dump.
        returns:
            str: Unicode string retrieved from vexpr_va.
        """
        return self._dx(vexpr_va, Qdb._handle_du, cc)

    def uf(self, vexpr_va=None):
        """Unassemble (disassemble) function.

        Stops disassembly when a ret instruction is encountered.

        Parameters
        ----------
        vexpr_va : str
            Vivisect expression indicating the location to start disassembly.
        returns : list
            ASCII strings containing mnemonics and operands disassembled
            starting at vexpr_va.
        """
        return self.disas(vexpr_va, 0, True)

    def u(self, vexpr_va=None, count=5):
        """Unassemble (disassemble) bytes.

        Parameters
        ----------
        vexpr_va : str
            Vivisect expression indicating the location to start disassembly.
        count : int
            Number of instructions to disassemble.
        returns : list
            ASCII strings containing mnemonics and operands disassembled
            starting at vexpr_va.
        """
        return self.disas(vexpr_va, count, False)

    def _disas(self, vexpr_va, count=0, until_ret=False, conout=False):
        """Silently disassemble instructions.

        Parameters
        ----------
        vexpr_va : str
            Vivisect expression indicating the location to start disassembly.
        count : int
            Number of instructions to disassemble.
        until_ret : bool
            Whether to disassemble until a return instruction is encountered.
        returns : list
            ASCII strings containing mnemonics and operands disassembled
            starting at vexpr_va.
        """
        instrs = []
        pc = self._trace.getProgramCounter()
        va = self._vex(vexpr_va) if vexpr_va is not None else pc
        how_many = str(count) + ' instrs ' if count else ''

        if conout:
            self._conout_pc('Disassembling ' + how_many + 'at ' + phex(va))

        if until_ret:
            not_ret = True
            while not_ret:
                op = self._trace.parseOpcode(va)
                instrs.append(str(op))
                if conout:
                    self._conout('  ' + phex(va) + ': ' + str(op))
                va += op.size
                not_ret = not (str(op).startswith('ret ') or (str(op) ==
                                                              'ret'))
        else:
            for i in xrange(0, count):
                op = self._trace.parseOpcode(va)
                instrs.append(str(op))
                if conout:
                    self._conout('  ' + phex(va) + ': ' + str(op))
                va += op.size

        return instrs

    def disas(self, vexpr_va, count=0, until_ret=False):
        """Disassemble instructions.

        Parameters
        ----------
        vexpr_va : str
            Vivisect expression indicating the location to start disassembly.
        count : int
            Number of instructions to disassemble.
        until_ret : bool
            Whether to disassemble until a return instruction is encountered.
        returns : list
            ASCII strings containing mnemonics and operands disassembled
            starting at vexpr_va.
        """
        return self._disas(vexpr_va, count, until_ret, True)


class Qdb(QdbMethodsMixin, QdbBuiltinsMixin):
    """Query-oriented debugger object."""

    def __init__(self, conlogger=None):
        """Instantiate a qdb object with an optional logging.Logger
        representing the console.
        """
        # Instance fields that are generally invariant for the life of the
        # object
        self._park_code_template = (
            # If this gets any more elaborate (such as 32- and 64-bit support
            # for a Sleep() call to take it easy on the CPU), then it should be
            # replaced with a vstruct.
            '\xeb\xfe'  # JMP -2
            '\x00'  # Align 8
            '\x00'  # ...
            '\x00'  # ...
            '\x00'  # ...
            '\x00'  # ...
            '\x00'  # ...
        )

        self._stacktrace_impl = {
            'i386': self._stacktrace_x86,
        }

        # Instance fields that may be reset/cleared
        self._resetDefaults()
        self._setupBuiltins()
        self.clear_counts()
        self.clear_queries()

        # Logging based on :quiet:
        self._con = conlogger

    def _resetDefaults(self):
        self._trace = None
        self._runnable = True
        self._init_code = None
        self._exitcode = None
        self._parameters = None
        self._locals = {}
        self._bp_unknown_fail = False
        self._stored_exception = None

    def _prepareTrace(self, callback):
        self._exitcode = None
        self._trace = vtrace.getTrace()
        self._trace.setMode('NonBlocking', False)
        callback(self._trace)
        self._trace.setMode('RunForever', True)  # Requires an attached trace

    def _setupBuiltins(self):
        """Add an unbound function to the locals namespace for every instance
        method that comes from QdbBuiltinsMixin.
        """
        if '_qdb_has_set_locals' in self._locals:
            return

        self._locals['_qdb_has_set_locals'] = True

        # Collect the names of all methods in QdbBuiltinsMixin
        userfuncnames = [m[0] for m in inspect.getmembers(
                QdbBuiltinsMixin, predicate=inspect.ismethod)]

        # Assign bound functions from self to the corresponding unbound
        # callable name in the namespace
        for m in inspect.getmembers(self, predicate=inspect.ismethod):
            if m[0] in userfuncnames:
                self._locals[m[0]] = m[1]

    def _add_queries_ephemeral(self):
        """Add permanent queries to the current run.

        See the heredocs for add_query_ephemeral() and add_query() for
        an explanation of ephemeral vs. normal semantics.
        """
        for vexpr_pc, vexpr, conds in self._queries:
            try:
                self.add_query_ephemeral(vexpr_pc, vexpr, conds)
            except NameError:
                logging.warning('Adding delayed breakpoint for ' +
                                str(vexpr_pc))
                self._add_delayed_query(vexpr_pc, vexpr, conds)

    def _eval_exprs(self, query, exprs=None, qbp=None):
        """Run Python or callable"""
        pc = self._trace.getProgramCounter()
        context = {}
        context['pc'] = pc
        context['trace'] = self._trace
        context['q'] = self
        context['qbp'] = qbp  # Qdb Breakpoint
        context['exprs'] = exprs

        if callable(query):
            self._dispatch_callable(query, context)
        else:
            self._dispatch_python(query, context)

    def _expandNonPythonAliases(self, query):
        """Replace Python-incompatible aliases such as "?()" with real
        functions such as "vex()".
        """
        for frm, to in _SPECIAL_ALIASES:
            query = self._expandNonPythonAlias(query, frm, to)
        return query

    def _expandNonPythonAlias(self, query, frm, to):
        """Replace a a function alias with its corresponding function."""
        pat = frm + r'(\(.*\))'
        rep = to + r'\1'
        result = re.sub(pat, rep, query)
        result = query if result is None else result
        return result

    def _dispatch_python(self, query, context):
        """Evaluate Python text."""

        self._locals.update(self._parameters)
        self._locals.update(context)

        query = self._expandNonPythonAliases(query)

        exec(query, {}, self._locals)

        # We don't sync back local variable changes for callables because they
        # use the passed-in params argument to return output values, and
        # furthermore don't even access locals.
        #
        # But we DO sync back local variable changes for evaluated python text
        # because scripters providing Python text to be evaluated will expect
        # to be able to modify parameters directly.
        if self._parameters:
            for k in self._parameters:
                if k in self._locals:
                    self._parameters[k] = self._locals[k]

    def _dispatch_callable(self, query, context):
        """Evaluate a callable."""
        # self._qdb._parameters.update(context)
        context.update(self._parameters)
        query(self._parameters, **context)

    def _halt(self):
        self._trace.setMode('RunForever', False)
        self._trace.runAgain(False)

    def _vex(self, vexpr):
        return self._trace.parseExpression(str(vexpr))

    def _stacktrace_x86(self, archwidth, depth=None):
        """Stack backtrace implementation for x86.

        Parameters
        ----------
        archwidth : int
            Architecture width. This is obtained by the caller and as a matter
            of implementation is expected to be passed to any
            architecture-specific stack backtrace implementations to
            differentiate between different modes, etc.
        depth : int or NoneType
            Desired stack trace depth
        returns: list(StackTraceEntry)
            list of (frame number, ebp, ret, eip, and symbolic eip)

        """
        trace = []

        ebp = self._vex('ebp')
        eip = self._vex('eip')

        hexwidth = 2 * archwidth

        trace_range = range(depth) if depth else itertools.count()
        for n in trace_range:
            if not ebp:
                break

            # Calculating for this iteration
            try:
                ret = self._vex('poi(%s+%d)' % (phex(ebp), archwidth))
            except vtrace.PlatformException as e:
                break

            # Collect trace information
            eip_s = (self._getsym(eip) or self._getmodoff(eip) or
                     phex(eip)[2:].zfill(hexwidth))
            ent = StackTraceEntry(n, ebp, ret, eip, eip_s)
            trace.append(ent)

            # Formatting/output
            n_s = str(n).zfill(2)
            ebp_s = phex(ebp)[2:].zfill(hexwidth)
            ret_s = phex(ret)[2:].zfill(hexwidth)
            self._conout('%s %s %s %s' % (n_s, ebp_s, ret_s, eip_s))

            # For next iteration
            eip = ret
            try:
                ebp = self._vex('poi(%s)' % (phex(ebp)))
            except vtrace.PlatformException as e:
                break

        return trace

    def _retcallback_stepi(self, cb_ret=None, limit=16384):
        """Step the program counter, ignoring breakpoints, until a final return
        instruction is found, and then execute cb_ret.

        Parameters
        ----------
        cb_ret : callable
            Callback to execute upon finding the final return instruction.
        limit : int
            Maximum number of instructions to execute before giving up. Zero
            means infinite.
        returns:
            Callback return value.
        """
        retval = None
        callstack = 0

        while True:
            op = self._trace.parseOpcode(self._trace.getProgramCounter())

            if op.isCall():
                callstack += 1

            if op.isReturn():
                if callstack:
                    callstack -= 1
                else:
                    if cb_ret:
                        retval = cb_ret()

                    break

            # If limit is zero at the outset of the call, then this combination
            # will cause infinite iteration (as desired).
            limit -= 1
            if limit == 0:
                logger.error('Failed to find return instruction')
                break

            self.stepi()

        return retval

    def _retcallback_stepo(self, cb_ret=None, limit=16384):
        """Step the program counter, ignoring breakpoints, until a final return
        instruction is found, and then execute the callback.

        Parameters
        ----------
        cb_ret : callable
            Callback to execute upon finding the final return instruction.
        limit : int
            Maximum number of instructions to execute before giving up. Zero
            means infinite.
        returns:
            Callback return value.
        """
        retval = None
        callstack = 0

        while True:
            self.stepo()
            op = self._trace.parseOpcode(self._trace.getProgramCounter())

            if op.isReturn():
                if cb_ret:
                    retval = cb_ret()

                break

            # If limit is zero at the outset of the call, then this combination
            # will cause infinite iteration (as desired).
            limit -= 1
            if limit == 0:
                logger.error('Failed to find return instruction')
                break

        return retval

    def _check_parked(self, tid):
        self._trace.selectThread(tid)
        pc = self._trace.getProgramCounter()
        somecode = self.readmem(pc, 1, len(self._park_code_template), None)

        return (tid, pc) if somecode == self._park_code_template else (None,
                                                                       None)

    def _unpark(self, tid, pc):
        self._trace.selectThread(tid)
        old_pc = self.readmem(pc + len(self._park_code_template), 1, 8, None)
        old_pc_int = struct.unpack('@Q', old_pc)[0]

        self._conout_pc('Unparking TID ' + str(tid) + ' from PC = ' +
                        phex(pc) + ', to old PC ' + phex(old_pc_int))

        self._trace.setProgramCounter(old_pc_int)
        # Vivisect does not currently support freeMemory / platformFreeMemory,
        # so no cleanup will be done here.

    def _archRetRegName(self):
        if self._trace.getMeta('Architecture') == 'i386':
            return 'eax'
        else:
            return 'rax'

    def _archWidth(self):
        return 4 if self._trace.getMeta('Architecture') == 'i386' else 8

    def _pretty_pc(self):
        """Return the symbolic name specified on the command line corresponding
        to this program counter value, if any.
        """
        pc = self._trace.getProgramCounter()

        ret = phex(pc)
        try:
            pretty = str(self._exprs[pc]['sym'])
            if pretty != str(pc) and pretty != phex(pc):
                return pretty
        except KeyError:
            pass

        return phex(pc)

    def _conout(self, s):
        """Output to the logging object that represents the console."""
        if self._con:
            self._con.info(str(s))

    def _conout_pc(self, s):
        """Output to the logging object that represents the console, including
        the symbolic (if available) or hexadecimal program counter in the
        output.
        """
        if self._con:
            prettypc = self._pretty_pc()
            self._con.info('[' + prettypc + ']: ' + str(s))

    def _add_delayed_query(self, pc_symbolic, vexpr, conds):
        """Set delayed breakpoint."""
        self._exprs_delayed[pc_symbolic] = vexpr
        self._trace.addBreakpoint(QdbBreak(self, pc_symbolic, vexpr, conds))

    def _readMemUnsafe(self, va, elements, element_size, sentinel, limit=0):
        """Read a range of bytes.

        Caller must either specify a non-zero number of elements, or specify a
        sentinel value upon which to stop, whose size must match element_size.
        Optional limit protects from run-away read, mainly intended for when a
        sentinel value is never encountered but enforced in the fixed range
        read as well for consistency. The "_unsafe" prefix denotes that no
        try/except is used here.
        """
        bytes = b''

        cumulative = 0

        if 0 == elements:
            while True:
                this_element = self._trace.readMemory(va, element_size)
                bytes = bytes + this_element
                if 0 != limit:
                    cumulative += element_size
                    if cumulative > limit:
                        logger.error(
                            '_readMemUnsafe: 1MB limit exceeded, reading 1MB')
                        break
                va = va + element_size
                if sentinel == this_element:
                    break
        else:
            to_read = 0xffffffff & (elements * element_size)
            if (0 != limit) and (to_read > limit):
                logger.error('_readMemUnsafe: 1MB limit exceeded, reading 1MB')
                to_read = limit

            bytes = self._trace.readMemory(va, to_read)

        return bytes

    def _strcpy_aw(self, vexpr_dst, val, wide, terminator):
        """Copy ASCII string into debuggee.

        Parameters
        ----------
        vexpr_dst : str
            Vivisect expression or virtual address whose value will be the
            location to write to.
        val : str
            String to write.
        wide : bool
            True if writing a wide string.
        terminator : bool
            True if a string terminator should be written. Wide string
            terminator is two bytes long, ASCII is one.
        """
        addr_str = vexpr_dst
        val = val.encode('utf-16-le') if wide else val.encode('ascii')

        addr = self._vex(vexpr_dst)

        if self._con and self._con.getEffectiveLevel() == logging.INFO:
            prefix = 'L' if wide else ''
            if str(addr_str) == str(addr):
                addr_str = phex(addr_str)
            else:
                addr_str = addr_str + ' (' + phex(addr) + ')'

            self._conout_pc('Setting string: ' + str(addr_str) + ' <= ' +
                            str(prefix) + '"' + str(val) + '"')

        if terminator:
            if wide:
                val += 2 * '\x00'
            else:
                val += '\x00'

        self._trace.writeMemory(addr, val)

    def _dx(self, vexpr, handler, n):
        """Generic code for dd, db, etc."""
        try:
            va = self._vex(vexpr)
            return handler(self, va, vexpr, n)
        except NameError:
            self._conout_pc('Vivisect expression parse exception: ' +
                            str(sys.exc_info()[1]))
            raise

    def _conout_pc_hexdump(self, label, va, bytes, datasize):
        """Output hexdump the logger object representing the console and return
        an array of bytes, DWORDs, etc.
        """
        if self._con:
            prettypc = self._pretty_pc()
            self._con.info('[' + prettypc + ']: ' + str(label))
        return print_hexdump(va, bytes, datasize, self._con)

    def _handle_db(self, va, vexpr, elements=128):
        """Handle WinDbg-style 'db' command by reading bytes."""
        s = self.readmem(va, elements, 1, None)
        # WARNING, _conout_pc_hexdump returns a byte array, so it has a
        # side-effect and should not be eliminated without being refactored.
        return self._conout_pc_hexdump(hex_or_str(vexpr) + ': ', va, s, 1)

    def _handle_dw(self, va, vexpr, elements=64):
        """Handle WinDbg-style 'dw' command by reading words."""
        s = self.readmem(va, elements, 2, None)
        # WARNING, _conout_pc_hexdump returns a byte array, so it has a
        # side-effect and should not be eliminated without being refactored.
        return self._conout_pc_hexdump(hex_or_str(vexpr) + ': ', va, s, 2)

    def _handle_dd(self, va, vexpr, elements=32):
        """Handle WinDbg-style 'dd' command by reading dwords."""
        s = self.readmem(va, elements, 4, None)
        # WARNING, _conout_pc_hexdump returns a byte array, so it has a
        # side-effect and should not be eliminated without being refactored.
        return self._conout_pc_hexdump(hex_or_str(vexpr) + ': ', va, s, 4)

    def _handle_dq(self, va, vexpr, elements=16):
        """Handle WinDbg-style 'dq' command by reading dwords."""
        s = self.readmem(va, elements, 8, None)
        # WARNING, _conout_pc_hexdump returns a byte array, so it has a
        # side-effect and should not be eliminated without being refactored.
        return self._conout_pc_hexdump(hex_or_str(vexpr) + ': ', va, s, 8)

    def _handle_da(self, va, vexpr, elements):
        """Handle WinDbg-style 'da' command by reading an ASCII string."""
        s = self.readmem(va, elements, 1, '\x00')
        if 0 == elements:
            elements = len(s)
        bytes = elements
        s = s[0:bytes].decode('ascii')
        self._conout_pc(hex_or_str(vexpr) + ': ' + s)
        return s

    def _handle_du(self, va, vexpr, elements):
        """Handle WinDbg-style 'du' command by reading a Unicode string."""
        s = self.readmem(va, elements, 2, '\x00\x00')
        if 0 == elements:
            elements = len(s)
        bytes = elements * 2
        s = s[0:bytes].decode('utf-16')
        try:
            self._conout_pc(hex_or_str(vexpr) + ': ' + s)
        except UnicodeEncodeError as e:
            self._conout_pc(hex_or_str(vexpr) +
                            ': (cannot display Unicode string: ' +
                            str(sys.exc_info()[1]) + ')')
        return s


class QdbBreak(vtrace.Breakpoint):
    """Custom breakpoint to execute Python.

    Based on http://www.limited-entropy.com/plaidctf-2013-drmless/. More
    specifically, http://www.limited-entropy.com/stuff/drmless.py.txt
    """

    def __init__(self, qdb_, loc, query, conds):
        """Set the callback depending whether the breakpoint is delayed."""
        self._qdb = qdb_
        try:
            vtrace.Breakpoint.__init__(self, int(loc))
            self._callback = self.evaluate_breakpoint
        except ValueError:
            vtrace.Breakpoint.__init__(self, None, loc)
            self._callback = self.eval_exprs_delayed
        self._conds = conds
        self._query = query

    def notify(self, event, trace):
        """Evaluate conditions and conditionally execute callback."""
        # trace.parseExpression() returns an int. To avoid misleading readers
        # from this fact and to discourage the introduction of future logical
        # errors into this code, we initialize the variable that may hold its
        # return value with an int value corresponding to truth.
        do_callback = 1

        if self._conds is not None:
            try:
                do_callback = trace.parseExpression(self._conds)
            except NameError as e:
                self._qdb._conout_pc(
                    "Error: Vivisect failed parsing condition(s) '" +
                    self._conds + "': " + str(sys.exc_info()[1]))

                do_callback = 0
                self._qdb._halt()

        if do_callback:
            self._callback()

    def evaluate_breakpoint(self):
        """Evaluate expression(s) associated with this program counter."""
        q = self._qdb
        try:
            q._eval_exprs(self._query, self._qdb._exprs, self)
        except Exception as e:
            # This function is called in the context of a breakpoint notify()
            # routine, which itself is called by TracerBase._fireBreakpoint(),
            # which will catch and print any exception, causing execution to
            # continue. Instead of allowing this, this function will save the
            # exception and backtrace, terminate execution, and Qdb.run() will
            # re-raise the stored exception. The Qdb object can be used to
            # obtain the trace that was captured at this point.
            q._bp_unknown_fail = True
            q._stored_exception = QdbBpException(
                'Error evaluating expression',
                str(self._query),
                str(sys.exc_info()[1]),
                e,
                traceback.extract_tb(sys.exc_info()[2])
            )

            q._halt()

    def eval_exprs_delayed(self):
        """Evaluate expression(s) associated with a delay-loaded breakpoint."""
        pc = self._qdb._trace.getProgramCounter()

        for (symbolic_addr, expr) in self._qdb._exprs_delayed.iteritems():
            if self._qdb._trace.parseExpression(symbolic_addr) == pc:
                self._qdb._exprs[pc] = {}
                self._qdb._exprs[pc]['sym'] = symbolic_addr

        self.evaluate_breakpoint()


# Hexdump and data formatting helper functions


def ascii_or_dots(bytes):
    """Replace non-printable/control characters with dots.

    Not using string.printable because it includes string.whitespace, which
    includes tabs and cr/lf's, which would botch the output.
    """
    return ''.join([b if b in string.punctuation + string.letters +
                    string.digits + ' ' else '.' for b in bytes])


def print_hexdump(va, bytes, datasize, lgr):
    """hexdump won't accmmodate varying data sizes, hence this function."""
    ret = []

    for offset in range(0, len(bytes), 16):
        line = bytes[offset:offset + 16]
        label = hex_padded(va + offset)

        # Prepare printable characters only if dumping individual bytes.
        printable = ascii_or_dots(line) if 1 == datasize else ''

        # Unpack the correct number of datasize-sized elements to consume a
        # 16-byte line.
        data = struct.unpack(UNPACK_FMTS[datasize] * (len(line) / datasize),
                             line)

        if datasize == 8:
            hexline = ' '.join(
                [hex_padded_quadword(b, 2 * datasize) for b in data])
        else:
            hexline = ' '.join([hex_padded(b, 2 * datasize) for b in data])

        for d in data:
            ret.append(d)

        if lgr:
            lgr.info(label + ': ' + pad_after(hexline, 16 * 3, ' ') +
                     printable)

    if lgr and len(bytes) == 0:
        lgr.info('  (No bytes to print)')

    return ret


def phex(n): return hex(n).rstrip('L')


def phex_bare(n): return hex(n).lstrip('0x').rstrip('L')


def dec_phex(n): return str(n) + ' (' + phex(n) + ')'


def phex_dec(n): return phex(n) + ' (' + str(n) + ')'


def hex_or_str(n):
    ret = str(n)
    try:
        ret = phex(n)
    except TypeError:
        pass

    return ret


def pad_after(s, n, c):
    """Pad s by appending n bytes of c."""
    return s + (c * n)[:n - len(s)] if len(s) < n else s


def pad_before(s, n, c):
    """Pad s by prepending n bytes of c."""
    return (c * n)[:n - len(s)] + s if len(s) < n else s


def punctuate_quadword(s): return s[0:8] + '`' + s[8:]


def hex_padded(n, digits=8): return pad_before(phex_bare(n), digits, "0")


def hex_padded_quadword(n, digits=8):
    return punctuate_quadword(pad_before(phex_bare(n), digits, "0"))
