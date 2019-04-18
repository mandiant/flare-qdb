# coding: utf-8
# Copyright (C) 2016 FireEye, Inc. All Rights Reserved.
from flareqdb import *


def qdb_parse_cmdline_args(console):
    t = vtrace.getTrace()
    archlabel = '[' + t.getMeta('Architecture') + ']'
    t.release()
    desc = 'FireEye Labs Query-Oriented Debugger ' + archlabel
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('cmdline', nargs='?',
                        help='program and arguments to run')
    parser.add_argument('-q', help='suppress normal console output',
                        default=False, action='store_true')
    parser.add_argument('-init', metavar='pythontext', help='Initialization')
    parser.add_argument('-at', metavar=('vexpr-pc', 'pythontext'),
                        default=[], nargs=2, action='append', help='query')
    parser.add_argument('-at-if', dest='at_if', metavar=('vexpr-pc',
                        'vexpr-cond', 'pythontext'), default=[], nargs=3,
                        action='append',
                        help='conditional query based on Vivisect ' +
                        'expression truth value')
    parser.add_argument('--help-builtins', dest='help_builtins', default=False,
                        action='store_true',
                        help='display flare-qdb builtin documentation')

    args = parser.parse_args()

    if args.help_builtins:
        console.info(help(QdbBuiltinsMixin))
        raise SystemExit
    elif not args.cmdline:
        print('A cmdline is required')
        print('')
        parser.print_help()
        raise SystemExit

    return args


def qdb_get_console_logger():
    ch = logging.StreamHandler(sys.stdout)
    cf = logging.Formatter('qdb: %(message)s')
    ch.setFormatter(cf)

    conlogger = logging.getLogger(__name__ + '.console')
    conlogger.addHandler(ch)
    conlogger.propagate = False

    return conlogger


def main():
    logging.basicConfig(level=logging.WARNING, format='qdb: %(message)s')

    console = qdb_get_console_logger()
    args = qdb_parse_cmdline_args(console)

    if args.q:
        console.setLevel(logging.ERROR)
    else:
        console.setLevel(logging.INFO)

    dbg = Qdb(console)

    if args.init:
        dbg.setInitCode(args.init)

    dbg.add_queries(args.at)

    for (a, c, e) in args.at_if:
        dbg.add_query(a, e, c)

    try:
        dbg.run(args.cmdline)
    except QdbBpException as e:
        console.error(str(e))
        for s in e.backtrace:
            console.error(s)
    except vtrace.PlatformException as e:
        console.error(e.message)
    except Exception as e:
        if e.message == 'CreateProcess failed!':
            console.error(e.message)
        else:
            raise

    ret = dbg.get_exitcode()
    if ret:
        console.info('Debuggee returned ' + str(ret))
    else:
        console.warning('Debuggee terminated without returning an exit code')

    if len(dbg.counts):
        console.info('Counts:')
        for k, v in dbg.counts.iteritems():
            console.info(hex_or_str(k) + ' hit ' + str(v) + ' time(s)')


if __name__ == '__main__':
    main()
