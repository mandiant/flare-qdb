# coding: utf-8
# Copyright (C) 2016 FireEye, Inc. All Rights Reserved.

import os
import sys
import struct
from flareqdb import Qdb, QdbBpException, UnparkSpec


__author__ = 'Michael Bailey'
__copyright__ = 'Copyright (C) 2016 FireEye'
__license__ = 'Apache License'
__version__ = '0.0'

"""Notes:
1.) Regarding `test_rapid_fire_WILL_TAKE_A_LONG_TIME()` - the name says it
    all, but if you must know, it takes a little over 2 minutes on a modern
    system.

2.) Some tests exercise issues #159 and/or #160 in Vivisect. If your
    traceback output contains this (or similar):

      PlatformException('Win32 Error kernel32.DebugBreakProcess failed: 5',)

     ...then update Vivisect.

3.) Expects hello.exe test binary (MD5: ca5735a956358503ec44737e5dd93e4c) to be
    in path. Here's hello!_main for reference...

     .text:00401000                            ; int __cdecl main(int argc,
                                               ; const char **argv, const char
                                               ; **envp)
     .text:00401000                            _main proc near
     .text:00401000
     .text:00401000                            var_4= dword ptr -4
     .text:00401000                            argc= dword ptr  8
     .text:00401000                            argv= dword ptr  0Ch
     .text:00401000                            envp= dword ptr  10h
     .text:00401000
     .text:00401000 55                         push    ebp
     .text:00401001 8B EC                      mov     ebp, esp
     .text:00401003 51                         push    ecx
     .text:00401004 C7 45 FC 00 00 00 00       mov     [ebp+var_4], 0
     .text:0040100B 68 00 C0 40 00             push    offset aHelloWorld
                                               ; "Hello, world!\n"
     .text:00401010 E8 0D 00 00 00             call    _printf
                                               ; _printf is at 0x401010 + 0xD
                                               ; = 0x401022
     .text:00401015 83 C4 04                   add     esp, 4
     .text:00401018 89 45 FC                   mov     [ebp+var_4], eax
     .text:0040101B 8B 45 FC                   mov     eax, [ebp+var_4]
     .text:0040101E 8B E5                      mov     esp, ebp
     .text:00401020 5D                         pop     ebp
     .text:00401021 C3                         retn
     .text:00401021                            _main endp

4.) Expects dll.dll test binary to be in path as well (MD5:
    3f8e81052513a899cbf0c4bac2ab299b). And here's dll!Add, for reference...

     .text:10001000                            public Add
     .text:10001000                            Add proc near
     .text:10001000
     .text:10001000                            arg_0= word ptr  8
     .text:10001000                            arg_4= word ptr  0Ch
     .text:10001000
     .text:10001000 55                         push    ebp
     .text:10001001 8B EC                      mov     ebp, esp
     .text:10001003 0F BF 45 08                movsx   eax, [ebp+arg_0]
     .text:10001007 0F BF 4D 0C                movsx   ecx, [ebp+arg_4]
     .text:1000100B 03 C1                      add     eax, ecx
     .text:1000100D 5D                         pop     ebp
     .text:1000100E C3                         retn
     .text:1000100E                            Add endp
"""

hello_exe_name = r'hello.exe'
hello_exe_dir = os.path.expandvars('%TESTFILES%')
hello_exe_path = os.path.join(hello_exe_dir, hello_exe_name)


def phex(n):
    return hex(n).rstrip('L')


def test_instantiate():
    dbg = Qdb()
    assert dbg is not None


def test_initcode():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.setInitCode('marker = 12345')
    result = dbg.run(hello_exe_path, locs)
    assert locs['marker'] is not None
    assert locs['marker'] == 12345


def test_run_no_breaks_and_exitcode():
    dbg = Qdb()
    result = dbg.run(hello_exe_path)
    assert result is True
    assert dbg.get_exitcode() == 14


def test_one_mb_read_limit():
    ONE_MB = 1024 * 1024
    MORE = ONE_MB + 10
    PAGE_READWRITE = 0x4
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000

    locs = {'location': None, 'size': None}

    args = (' -c "import ctypes; '

            'm = ctypes.windll.kernel32.VirtualAlloc(' +
            hex(0).rstrip('L') + ', ' +
            hex(MORE).rstrip('L') + ', ' +
            hex(MEM_COMMIT | MEM_RESERVE).rstrip('L') + ', ' +
            hex(PAGE_READWRITE).rstrip('L') +
            '); '

            # Disclose the location of the memory returned by VirtualAlloc
            'ctypes.windll.kernel32.VirtualQuery(m, 0, 0);'

            # Trigger one more breakpoint for clarity
            'ctypes.windll.kernel32.VirtualFree(' +
            'm, ' +
            hex(MORE).rstrip('L') + ', ' +
            '0x8000' +
            ');'
            )

    # When running under py.test.exe, sys.executable is python.exe
    cmdline = sys.executable + args

    dbg = Qdb()

    dbg.add_query('kernel32.VirtualQuery',
                  # If lpBuffer + dwLength == NULL, then this is the Python
                  # script's indication to qdb of where the memory is located.
                  # Read it.
                  "if not sum(dd('esp+8', 2)): location = dd('esp+4', 1)[0]; "
                  )

    # VirtualFree is called by the debuggee (above) to trigger this code.
    dbg.add_query('kernel32.VirtualFree',
                  "m = readmem("
                  "location, " +
                  hex(MORE).rstrip('L') + ", "
                  "1, "
                  "None"
                  ");"

                  "size = len(m)"  # Collect the length that was read
                  )

    result = dbg.run(cmdline, locs)
    assert result is True

    # If we did not get the location, that is useful to know for diagnosing
    # test failure.
    assert locs['location']

    # Check that ONE_MB of data was returned despite having tried to read MORE
    assert locs['size'] == ONE_MB


def test_python_ctypes_dll_control_case():
    cmdline = (sys.executable +
               ' -c "import ctypes; ctypes.windll.dll.Add(1, 2)"')
    dbg = Qdb()
    result = dbg.run(cmdline)
    assert result is True


def test_python_ctypes_dll_intercept():
    cmdline = (sys.executable +
               ' -c "import ctypes; ctypes.cdll.dll.Add(40, 2)"')
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query('dll.Add+0xd', "marker = r('eax')")
    result = dbg.run(cmdline, locs)
    assert result is True
    assert locs['marker'] == 42


def test_rundll_dll_control_case():
    dbg = Qdb()
    result = dbg.run(r'rundll32.exe dll.dll,Add')
    assert result is True


# This test currently fails. rundll32 loads its argument DLL more than once,
# and when the DLL is unloaded, Vivisect does not add the breakpoint back to
# the deferred list when it is cleared.
def test_rundll_dll_intercept_CURRENTLY_FAILS():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query('dll.Add+0xd', "marker = r('eax')")
    result = dbg.run(r'rundll32.exe dll.dll,Add dummytext', locs)
    assert result is True
    assert locs['marker'] == 0


def test_vexpr_nameerror():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010, "marker = vex('poi(EXP)')")
    got_exception = False
    try:
        result = dbg.run(hello_exe_path, locs)
    except QdbBpException as e:
        got_exception = True
        ex_type_is_name_error = isinstance(e.exception, NameError)
    assert got_exception
    assert ex_type_is_name_error
    assert locs['marker'] is None


def test_vexpr_retval():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x40101b, "marker = vex('poi(ebp-0x4)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 14


def test_vexpr_alias():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x40101b, "marker = ?('poi(ebp-0x4)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 14


def test_kill():
    dbg = Qdb()
    locs = {'marker1': None, 'marker2': None}
    dbg.add_query(0x401010, "marker1 = kill()")
    dbg.add_query(0x40101b, "marker2 = vex('poi(ebp-0x4)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker1'] is True
    assert locs['marker2'] is None


def test_dd():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010, "marker = dd('poi(esp)', 1)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    # DWORD of beginning of "Hello, world!"
    assert locs['marker'][0] == struct.unpack('L', 'Hell')[0]


def test_dw():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010, "marker = dw('poi(esp)', 1)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    # DWORD of beginning of "Hello, world!"
    assert locs['marker'][0] == struct.unpack('H', 'He')[0]


def test_db():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010, "marker = db('poi(esp)', 1)")
    result = False
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    # DWORD of beginning of "Hello, world!"
    assert locs['marker'][0] == struct.unpack('B', 'H')[0]


def test_da():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(
        0x401010, "marker = da('poi(esp)'); print('Marker = ' + str(marker))")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    # DWORD of beginning of "Hello, world!"
    assert locs['marker'] == 'Hello, world!\n\0'


def test_disas():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401000, "marker = disas(None, 1, False)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'][0] == 'push ebp'


def test_disas_alias_u():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401000, "marker = u(None, 1)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'][0] == 'push ebp'


def test_disas_alias_uf():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401000, "marker = uf(None)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'][0].startswith('push ebp')
    assert locs['marker'][1].startswith('mov ebp,esp')
    assert locs['marker'][2].startswith('push ecx')
    assert locs['marker'][3].startswith('mov dword [ebp - 4],0')
    assert locs['marker'][4].startswith('push 0x0040c000')
    assert locs['marker'][5].startswith('call 0x00401022')
    assert locs['marker'][6].startswith('add esp,4')
    assert locs['marker'][7].startswith('mov dword [ebp - 4],eax')
    assert locs['marker'][8].startswith('mov eax,dword [ebp - 4]')
    assert locs['marker'][9].startswith('mov esp,ebp')
    assert locs['marker'][10].startswith('pop ebp')
    assert locs['marker'][11].startswith('ret')


def test_setreg():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401015, "setreg('eax', 42);")
    dbg.add_query(0x40101b, "marker = vex('poi(ebp-0x4)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 42


def test_setreg_alias_r_get():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401015, "marker = r('eax');")
    dbg.add_query(0x40101b, "marker = vex('poi(ebp-0x4)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 14  # Length of hello world string


def test_setreg_alias_r_set():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401015, "r('eax', 42);")
    dbg.add_query(0x40101b, "marker = vex('poi(ebp-0x4)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 42


def test_memcpy():
    """FIXME: This test will break if dd breaks, which is confusing."""
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010,
                  "memcpy('poi(esp)', 'poi(esp)+4', 4); " +
                  "marker = dd('poi(esp)', 1)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'][0] == struct.unpack('@I', 'Hello, world!'[4:8])[0]


def test_writemem():
    """FIXME: This test will break if da breaks, which is confusing."""
    dbg = Qdb()
    locs = {'marker': None}
    s = "Goodbye, world!"
    print("writemem('poi(esp)', '" + s + "'); marker = da('poi(esp)')")
    dbg.add_query(0x401010,
                  "writemem('poi(esp)', '" + s +
                  "\\x00'); marker = da('poi(esp)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == s + '\x00'


def test_eza_and_da():
    """FIXME: This test depends on both eza and da, which makes it break
    when either piece breaks.
    """
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010,
                  "eza('poi(esp)', 'Bye, world'); marker = da('poi(esp)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 'Bye, world\0'


def test_ezu_and_du():
    """FIXME: This test depends on both eu and du, which makes it break
    when either piece breaks.
    """
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010,
                  "ezu('poi(esp)', u'Bye, world'); marker = du('poi(esp)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == u'Bye, world\x00'


def test_ea_and_da():
    """FIXME: This test depends on both ea and da, which makes it break
    when either piece breaks.
    """
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010,
                  "ea('poi(esp)', 'Bye, world'); marker = da('poi(esp)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 'Bye, worldld!\n\0'


def test_eu_and_du():
    """FIXME: This test depends on both eu and du, which makes it break
    when either piece breaks.
    """
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401010,
                  "eu('poi(esp)', u'Bye, world'); marker = du('poi(esp)', 3)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == u'Bye'


def test_ed():
    sentinel_value = 99999
    dbg = Qdb()
    locs = {'marker': None}
    # [ebp-4] here is equal to the length of the string "Hello, world!\n"
    dbg.add_query(0x40101b, "ed('ebp-4', " + str(sentinel_value) + ")")
    dbg.add_query(0x40101e, "marker = r('eax')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == sentinel_value


def test_ew():
    sentinel_value = 0xffff
    dbg = Qdb()
    locs = {'marker': None}
    # [ebp-4] here is equal to the length of the string "Hello, world!\n"
    dbg.add_query(0x40101b, "ew('ebp-4', " + str(sentinel_value) + ")")
    dbg.add_query(0x40101e, "marker = r('eax')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == sentinel_value


def test_eb1():
    sentinel_value = 0x0f
    dbg = Qdb()
    locs = {'marker': None}
    # [ebp-4] here is equal to the length of the string "Hello, world!\n"
    dbg.add_query(0x40101b, "eb('ebp-4', " + str(sentinel_value) + ")")
    dbg.add_query(0x40101e, "marker = r('eax')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == sentinel_value


def test_eb2():
    sentinel_value = 0xffff
    dbg = Qdb()
    locs = {'marker': None}
    # [ebp-4] here is equal to the length of the string "Hello, world!\n"
    dbg.add_query(0x40101b, "eb('ebp-4', '\xff\xff')")
    dbg.add_query(0x40101e, "marker = r('eax')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == sentinel_value


def test_getsym_invalid():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401000, "marker = getsym('eip')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == '(unknown)'


def test_getsym_valid():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query('kernel32.GetCommandLineA', "marker = getsym('eip')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 'kernel32.GetCommandLineA'


def test_getsym_alias_ln():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query('kernel32.GetCommandLineA', "marker = ln('eip')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 'kernel32.GetCommandLineA'


def test_get_pc():
    dbg = Qdb()
    locs = {'marker': None}
    pc = 0x401000
    dbg.add_query(pc, 'marker = get_pc()')
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == pc


def test_get_pcs():
    dbg = Qdb()
    locs = {'pcs': None, 'tid': None}
    pc = 0x401000
    dbg.add_query(pc, 'pcs = get_pcs(); tid = q._trace.getCurrentThread()')
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    # hello.exe is single-threaded
    for k, v in locs['pcs'].iteritems():
        assert k == locs['tid']
        assert v == pc


def test_bp():
    """FIXME: This test will break if da breaks, which is confusing."""
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x401000,
                  "bp(0x401010, 'marker = da(\\\'poi(esp)\\\', 5)')")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 'Hello'


def test_callback_gets_context_with_pc_and_locals_as_arg(*args, **kwargs):
    dbg = Qdb()

    def callback(p, **kwargs):
        p['marker'] = True

    locs = {'marker': False}
    dbg.add_query(0x401010, callback)
    try:
        result = dbg.run(hello_exe_path, locs)
    except QdbBpException as e:
        print('%s: %s' % (type(e), str(e)))

    assert result is True
    assert locs['marker'] is True


def test_cond_false():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x40101b, "marker = vex('poi(ebp-0x4)')",
                  "0 || esp && eax!=14")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] is None


def test_cond_true():
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query(0x40101b, "marker = vex('poi(ebp-0x4)')",
                  "0 or (esp and eax==14)")
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['marker'] == 14


def test_park_detach_attach_unpark():
    """This will spike CPU while the debuggee executes jmp -2 a few thousand
    times.
    """
    dbg = Qdb()
    locs = {'pid': None, 'flag': None}
    dbg.add_query(0x401010, "park(); pid = detach()")
    result = dbg.run(hello_exe_path, locs)
    assert result is True

    dbg = Qdb()
    dbg.attach(locs['pid'])
    dbg.add_query(0x401021, "flag = -1")
    dbg.unpark()
    result = dbg.run(parameters=locs)
    assert result is True

    assert locs['flag'] == -1


def test_get_push_arg():
    cmdline = (sys.executable +
               ' -c "import ctypes; ctypes.cdll.dll.Add(12, 34)"')
    dbg = Qdb()
    locs = {'arg_12': None, 'arg_34': None}
    dbg.add_query('dll.Add',
                  "arg_12 = get_push_arg(0); arg_34 = get_push_arg(1)")
    result = dbg.run(cmdline, locs)
    assert result is True
    assert locs['arg_12'] == 12
    assert locs['arg_34'] == 34


def test_stacktrace_alias_k():
    return _test_stacktrace("k()")


def test_stacktrace():
    return _test_stacktrace("stacktrace()")


def _test_stacktrace(command="stacktrace()"):
    dbg = Qdb()
    locs = {'backtrace': None}
    dbg.add_query(0x401022, 'backtrace = %s' %(command))
    result = dbg.run(hello_exe_path, locs)

    assert result is True
    assert locs['backtrace']
    bt = locs['backtrace']

    # At least main, _printf, and one other frame
    assert len(bt) > 2

    # Stack frames numbered as expected
    assert all([(bt[i].nr == i) for i in range(len(bt))])

    # ebp direction as expected
    assert all([(bt[i].bp < bt[i + 1].bp) for i in range(len(bt) - 1)])

    # Known addresses that should be at the top of this stack frame
    assert bt[0].pc == 0x401022
    assert bt[0].pc_s == 'hello+0x22'
    assert bt[1].pc == 0x40120b
    assert bt[1].pc_s == 'hello+0x20b'


def test_stepi():
    dbg = Qdb()
    locs = {'location': None}
    dbg.add_query(0x401010, "stepi(); location = r('eip')")  # call _printf
    result = dbg.run(hello_exe_path, locs)

    assert result is True
    assert locs['location']
    assert locs['location'] == (0xD + 0x401015)  # At _printf


def test_stepo():
    dbg = Qdb()
    locs = {'location': None}
    dbg.add_query(0x401010, "stepo(); location = r('eip')")  # call _printf
    result = dbg.run(hello_exe_path, locs)

    assert result is True
    assert locs['location']
    assert locs['location'] == 0x401015  # Right after call _printf


def test_gu():
    dbg = Qdb()
    locs = {'location': None}
    dbg.add_query(0x401022, "print(hex(r('eip'))); gu(); location = r('eip'); print(hex(location))")  # At _printf
    result = dbg.run(hello_exe_path, locs)
    assert result is True
    assert locs['location']
    assert locs['location'] == 0x401015  # Right after call _printf


def test_retwatch():
    cmdline = (sys.executable +
               ' -c "import ctypes; ctypes.cdll.dll.Add(1, 1)"')
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query('dll.Add', "marker = retwatch(8)")
    result = dbg.run(cmdline, locs)
    assert result is True
    assert locs['marker'] == 2


def test_retset():
    cmdline = (sys.executable +
               ' -c "import ctypes; ctypes.cdll.dll.Add(1, 1)"')
    dbg = Qdb()
    locs = {'marker': None}
    dbg.add_query('dll.Add', "marker = retset('eax+1', 8)")
    result = dbg.run(cmdline, locs)
    assert result is True
    assert locs['marker'] == 3


def test_retset():
    pass


# pytest seems to run these in order, so do testers a favor and leave this one
# last.
def test_rapid_fire_WILL_TAKE_A_LONG_TIME():
    runs_expected = 1
    # runs_expected = 1400
    runs_counted = 0

    locs = {'marker': runs_counted}
    dbg = Qdb()
    dbg.add_query(0x0401262, "marker += 1; kill()")
    for i in xrange(runs_expected):
        result = dbg.run(hello_exe_path, locs)
        assert result is True
    assert locs['marker'] == runs_expected
