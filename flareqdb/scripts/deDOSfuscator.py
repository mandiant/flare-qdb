# coding: utf-8
# Copyright (C) 2018 FireEye, Inc. All Rights Reserved

"""De-DOSfuscator.

PDB downloading adapted from:
  https://gist.github.com/steeve85/2665503
"""

from __future__ import print_function

import os
import sys
import pefile
import ctypes
import struct
import vstruct
import logging
import httplib
import os.path
import flareqdb
import platform
# from urllib.parse import urlparse # Python 3
import urlparse
import argparse
import traceback
from ctypes import sizeof, c_char_p, pointer
from vstruct import primitives as vp
import vtrace.platforms.win32 as vpwin

__author__ = 'Michael Bailey'
__copyright__ = 'Copyright (C) 2018 FireEye'
__license__ = 'Apache License'
__version__ = '1.0'


NM_SYMNAME_DISPATCH = 'Dispatch'
NM_SYMNAME_FDUMPPARSE = 'fDumpParse'
DEFAULT_SYMPATH = r'SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols'
PDB_URI = "/download/symbols/%s.pdb/%s/%s.pdb"

g_logfile = 'NUL'
g_nerf = False
g_arch = platform.architecture()[0]
g_cmd_cmdline = {
    '32bit': r'C:\Windows\SysWOW64\cmd.exe',
    '64bit': r'C:\Windows\system32\cmd.exe'
}


class CmdObj(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.pad0 = vp.v_ptr()
        self.pad1 = vp.v_ptr()
        self.pad2 = vp.v_ptr()
        self.pad3 = vp.v_ptr()
        self.pad4 = vp.v_ptr()
        self.pad5 = vp.v_ptr()
        self.pad6 = vp.v_ptr()
        self.pad7 = vp.v_ptr()
        self.pad8 = vp.v_ptr()
        self.pad9 = vp.v_ptr()
        self.pad10 = vp.v_ptr()
        self.pad11 = vp.v_ptr()
        self.pad12 = vp.v_ptr()
        self.pRedirList = vp.v_ptr()
        self.pCmd = vp.v_ptr()
        self.pArgs = vp.v_ptr()


class RedirObj(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.streamno = vp.v_size_t()
        self.pTarget = vp.v_ptr()
        self.pad0 = vp.v_uint32()
        self.append = vp.v_uint32()
        self.redir_chr_ordinal = vp.v_size_t()
        self.pNext = vp.v_ptr()


def dump_cmd_32b(p, q, **kwargs):
    """Read command struct from second argument, 32-bit"""
    try:
        cmdobj = q.readstruct(CmdObj, q.get_push_arg(1))
        dump_cmdobj(q, cmdobj)
    except Exception as e:
        logging.info('%s: %s' % (str(type(e)), str(e)))
        logging.info(traceback.format_exc())


def dump_cmd_64b(p, q, **kwargs):
    """Read command struct from second argument, 64-bit"""
    try:
        cmdobj = q.readstruct(CmdObj, 'rdx')
        dump_cmdobj(q, cmdobj)
    except Exception as e:
        logging.info('%s: %s' % (str(type(e)), str(e)))
        logging.info(traceback.format_exc())


def dump_cmdobj(q, cmdobj):
    """Dump a cmd.exe command object including arguments and redirections."""
    cmd = q.du(cmdobj.pCmd).strip('\x00')
    args = q.du(cmdobj.pArgs).strip('\x00')
    redirs = u''
    pRedir = cmdobj.pRedirList
    while pRedir:
        redirobj = q.readstruct(RedirObj, pRedir)
        occurrences = 1 + redirobj.append
        c = chr(redirobj.redir_chr_ordinal)
        target = q.du(redirobj.pTarget).strip('\x00')
        redirs += u' %d %s %s' % (redirobj.streamno, c * occurrences, target)
        pRedir = redirobj.pNext

    # Defeat CLS for funzies
    if cmd.lower() == u'cls':
        q.ezu(cmdobj.pCmd, u'REM')

    output = u'>>>cmd: %s%s%s' % (cmd, args, redirs)
    print(output)
    logging.info(output)

    if cmd.lower() == u'rem' and args[1:].startswith(u'status'):
        print('Mmhmm, DeDOSfuscator is listening...')
        print('Logging to %s' % (g_logfile))
        print('Oh, did I break yo\' concentration? Please. Continue.')

    if g_nerf:
        print('Nerfing')
        q.ezu(cmdobj.pCmd, u'')


def fmt_logfile_name(logdir, i):
    return os.path.join(logdir, 'dedosfuscated_%d.log' % i)


g_dump_cmd_cb = {
    '32bit': dump_cmd_32b,
    '64bit': dump_cmd_64b
}


def getSym(filename, symname, path_dbghelp=None, sympath=None):
    if not sympath:
        sympath = DEFAULT_SYMPATH

    # Note: symsrv.dll must be in the same directory as dbgeng.dll to download
    # symbol info
    if not path_dbghelp:
        dir = os.path.dirname(os.path.realpath(__file__))
        path_dbghelp = os.path.join(dir, g_arch, 'dbghelp.dll')
        print('Trying dbghelp from %s' % (path_dbghelp))

    dbghelp = None

    try:
        dbghelp = ctypes.WinDLL(path_dbghelp)
    except WindowsError as e:
        if e.winerror == 126:
            pass
        elif e.winerror == 193:
            print(str(e))
            print('Did we try to load a 64-bit dbghelp.dll in a 32-bit Python '
                  '(or vice-versa)?')
            return None
        else:
            print(str(e))
            return None

    # Fall back on any copy of dbghelp.dll, but may not have symbol server
    # support via an adjacent copy of symsrv.dll. Compensate for this by
    # downloading PDB manually
    if not dbghelp:
        # Try to get PDB manually to cope with the default Windows 7 setup
        # wherein dbghelp.dll is in system32 but symsrv.dll is not. Ignore
        # errors and fall back on symsrv (which indeed may not be present) in
        # case of failure.
        downloadPdbForBinIfNotExist(filename)

        dbghelp = ctypes.windll.dbghelp

    opts = dbghelp.SymGetOptions()
    opts |= vpwin.SYMOPT_DEBUG  # Can use SysInternals DbgView to troubleshoot
    dbghelp.SymSetOptions(opts)

    ok = dbghelp.SymInitialize(-1, sympath, False)
    if not ok:
        return None

    modbase = dbghelp.SymLoadModule64(-1, 0, filename, 0, 0, 0)
    if not modbase:
        return None

    si = vpwin.SYMBOL_INFO()
    si.SizeOfStruct = sizeof(si) - 2000
    si.MaxNameLen = 2000
    ok = dbghelp.SymFromName(-1, c_char_p(symname), pointer(si))

    # SymFromName failed; are dbghelp.dll and symsrv.dll in same dir?
    if not ok:
        return None

    return (si.Address - modbase) & 0xfffff  # Hack hack


def downloadPdb(dll_name, guid):
    final_uri = PDB_URI % (dll_name, guid, dll_name)

    conn = httplib.HTTPConnection("msdl.microsoft.com")
    headers = {
        'User-Agent': 'Microsoft-Symbol-Server/6.12.0002.633',
        # 'Accept-Encoding': 'gzip',
        # 'Connection': 'Keep-Alive',
        # 'Cache-Control': 'no-cache',
    }
    conn.request("GET", final_uri, "", headers)

    response = conn.getresponse()

    if response.status == 302:
        redir_url = response.getheader('Location')
        redir_parsed = urlparse.urlparse(redir_url)
        server = redir_parsed.netloc
        redir_uri = '%s?%s' % (redir_parsed.path, redir_parsed.query)

        if redir_parsed.scheme == 'https':
            conn = httplib.HTTPSConnection(server)
        else:
            conn = httplib.HTTPConnection(server)
        conn.request("GET", redir_uri, "", headers)
        response = conn.getresponse()

    if response.status == 200:
        pdb_buffer = response.read()

        pdb_filename = os.path.basename(PDB_URI % (dll_name, guid, dll_name))
        pdb_file = open(pdb_filename, 'wb')
        pdb_file.write(pdb_buffer)
        pdb_file.close()
        return True

    return False


def getPdbGuid(dll_path):
    # ugly code, isn't it ?
    try:
        dll = pefile.PE(dll_path)
        rva = dll.DIRECTORY_ENTRY_DEBUG[0].struct.AddressOfRawData
        tmp = ''
        tmp += '%0.*X' % (8, dll.get_dword_at_rva(rva+4))
        tmp += '%0.*X' % (4, dll.get_word_at_rva(rva+4+4))
        tmp += '%0.*X' % (4, dll.get_word_at_rva(rva+4+4+2))
        x = dll.get_word_at_rva(rva+4+4+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H', struct.pack('>H', x))[0])
        x = dll.get_word_at_rva(rva+4+4+2+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H', struct.pack('>H', x))[0])
        x = dll.get_word_at_rva(rva+4+4+2+2+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H', struct.pack('>H', x))[0])
        x = dll.get_word_at_rva(rva+4+4+2+2+2+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H', struct.pack('>H', x))[0])
        tmp += '%0.*X' % (1, dll.get_word_at_rva(rva+4+4+2+2+2+2+2+2))
    except AttributeError, e:
        print('Error appends during %s parsing' % (dll_path))
        print(e)
        return None
    return tmp.upper()


def downloadPdbForBinIfNotExist(filepath):
    got_pdb = False
    if os.path.exists('cmd.pdb'):
        got_pdb = True

    if not got_pdb:
        got_pdb = downloadPdbForBin(filepath)

    return got_pdb


def downloadPdbForBin(filepath):
    guid = getPdbGuid(filepath)
    filename = os.path.splitext(os.path.basename(filepath))[0]
    if guid:
        return downloadPdb(filename, guid)
    return False


def runHookedCmd(offset, logdir, nerf=False):
    global g_logfile
    global g_nerf

    g_nerf = nerf
    if logdir:
        i = 0
        while os.path.exists(fmt_logfile_name(logdir, i)):
            i += 1

        g_logfile = fmt_logfile_name(logdir, i)

    logging.basicConfig(filename=g_logfile, level=logging.INFO)

    q = flareqdb.Qdb()

    print('Running hooked cmd.exe, logging to %s' % (g_logfile))
    q.add_query(offset, g_dump_cmd_cb[g_arch])
    q.run(g_cmd_cmdline[g_arch])


def runWith_fDumpParse(offset):
    ep = pefile.PE(g_cmd_cmdline[g_arch]).OPTIONAL_HEADER.AddressOfEntryPoint
    q = flareqdb.Qdb()

    print('Running cmd.exe with fDumpParse enabled')
    q.add_query('cmd+0x%x' % (ep), "eb('%s', 1)" % (offset))
    q.run(g_cmd_cmdline[g_arch])


def main():
    desc = 'DeDOSfuscator: de-obfuscate batch files by executing them.\n'
    desc += 'You can get the needed symbol offsets by running this script\n'
    desc += 'on a network-connected machine with the --getoff switch which\n'
    desc += 'expects the path to a copy of the version of cmd.exe that you\n'
    desc += 'plan to use in your isolated malware analysis environment.\n'
    desc += 'You can then pass the resulting symbolic offset as an argument\n'
    desc += 'to the --useoff switch which will use it for hooking cmd.exe.\n'
    desc += 'Once DeDOSfuscator is running, change to the directory where\n'
    desc += 'your malicious batch file is located (in your isolated or safe\n'
    desc += 'analysis environment), and invoke the batch file. If you can\'t\n'
    desc += 'remember whether you\'re running under the DeDOSfuscator, type\n'
    desc += 'REM status.\n'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('--logdir', type=str, default=os.getcwd(),
                        help='Override logging directory. Default: %%CD%%')
    parser.add_argument('--getoff', type=str, metavar='path_to_cmd',
                        help='Get symbolic offsets for specified copy of '
                        'cmd.exe')
    parser.add_argument('--useoff', type=str, metavar='symbolic_offset',
                        help='Use symbolic offsets')
    parser.add_argument('--fDumpParse', action='store_true',
                        help='Use cmd-native AST dumping via fDumpParse')
    parser.add_argument('--nerf', default=False, action='store_true',
                        help='Don\'t allow commands to execute. Mutually '
                        'exclusive with --fDumpParse. Warnings: '
                        '(1) In many cases your malicious batch file will not '
                        'work with this switch enabled. '
                        '(2) No guarantee is implied or expressed that this '
                        'will protect your system -- especially if you '
                        'provide invalid/incorrect offsets! '
                        '(3) You won\'t be able to exit normally, so instead '
                        'exit by hitting Ctrl+C.')
    parser.add_argument('--sympath', type=str,
                        help='Override symbol path. Default: %s' %
                        (DEFAULT_SYMPATH))
    parser.add_argument('--dbghelp', type=str, metavar='path_to_dbghelp_dll',
                        help='Override path to a copy of dbghelp.dll. '
                        'Default: %%CD%%\dbghelp.dll')
    args = parser.parse_args()

    symname = NM_SYMNAME_FDUMPPARSE if args.fDumpParse else NM_SYMNAME_DISPATCH
    if args.useoff:
        offset = args.useoff
    else:
        path_cmd = args.getoff if args.getoff else g_cmd_cmdline[g_arch]

        sym_off = getSym(path_cmd, symname, args.dbghelp, args.sympath)

        if not sym_off:
            print('Failed to get symbol address for cmd!%s' % symname)
            print('Run me alongside SysInternals DbgView to troubleshoot')
            print('If you see a symsrv load failure:')
            print('  * Is symsrv.dll located in the same dir as dbghelp.dll?')
            print('If you see no debug messages:')
            print('  * Are you supplying a %s dbghelp.dll?' % (g_arch))
            sys.exit(1)

        offset = 'cmd+0x%x' % (sym_off)

    if args.getoff:
        print(offset)
        sys.exit(0)

    if args.nerf and args.fDumpParse:
        print('You can\'t use --nerf with --fDumpParse')
        sys.exit(1)

    if not args.fDumpParse:
        runHookedCmd(offset, args.logdir, args.nerf)
    else:
        runWith_fDumpParse(offset)


if __name__ == '__main__':
    main()
