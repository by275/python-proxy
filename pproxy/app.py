"""Command-line application lifecycle for pproxy."""

import argparse
import asyncio
import sys

from . import admin
from . import server as runtime
from .__doc__ import __description__, __url__, __version__


def main(args=None):
    """Parse CLI arguments, start configured servers, and own shutdown."""
    origin_argv = sys.argv[1:] if args is None else args

    parser = argparse.ArgumentParser(
        description=__description__
        + '\nSupported protocols: http,socks4,socks5,shadowsocks,shadowsocksr,redirect,pf,tunnel',
        epilog=f'Online help: <{__url__}>',
    )
    parser.add_argument('-l', dest='listen', default=[], action='append', type=runtime.proxies_by_uri, help='tcp server uri (default: http+socks4+socks5://127.0.0.1:8080/)')
    parser.add_argument('-r', dest='rserver', default=[], action='append', type=runtime.proxies_by_uri, help='tcp remote server uri (default: direct)')
    parser.add_argument('-ul', dest='ulisten', default=[], action='append', type=runtime.proxies_by_uri, help='udp server setting uri (default: none)')
    parser.add_argument('-ur', dest='urserver', default=[], action='append', type=runtime.proxies_by_uri, help='udp remote server uri (default: direct)')
    parser.add_argument('-b', dest='block', type=runtime.compile_rule, help='block regex rules')
    parser.add_argument('-a', dest='alived', default=0, type=int, help='interval to check remote alive (default: no check)')
    parser.add_argument('-s', dest='salgorithm', default='fa', choices=('fa', 'rr', 'rc', 'lc'), help='scheduling algorithm (default: first_available)')
    parser.add_argument('-d', dest='debug', action='count', help='turn on debug to see tracebacks (default: no debug)')
    parser.add_argument('-v', dest='v', action='count', help='print verbose output')
    parser.add_argument('--ssl', dest='sslfile', help='certfile[,keyfile] if server listen in ssl mode')
    parser.add_argument('--pac', help='http PAC path')
    parser.add_argument('--get', dest='gets', default=[], action='append', help='http custom {path,file}')
    parser.add_argument('--auth', dest='authtime', type=int, default=86400 * 30, help='re-auth time interval for same ip (default: 86400*30)')
    parser.add_argument('--sys', action='store_true', help='change system proxy setting (mac, windows)')
    parser.add_argument('--reuse', dest='ruport', action='store_true', help='set SO_REUSEPORT (Linux only)')
    parser.add_argument('--daemon', dest='daemon', action='store_true', help='run as a daemon (Linux only)')
    parser.add_argument('--test', help='test this url for all remote proxies and exit')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args(args)
    if args.sslfile:
        sslfile = args.sslfile.split(',')
        for context in runtime.sslcontexts:
            context.load_cert_chain(*sslfile)
    elif any(o.sslclient or isinstance(o, runtime.ProxyQUIC) for o in args.listen + args.ulisten):
        print('You must specify --ssl to listen in ssl mode')
        return
    if args.test:
        asyncio.run(runtime.test_url(args.test, args.rserver))
        return
    if not args.listen and not args.ulisten:
        args.listen.append(runtime.proxies_by_uri('http+socks4+socks5://127.0.0.1:8080/'))
    args.httpget = {}
    if args.pac:
        pactext = 'function FindProxyForURL(u,h){' + (f'var b=/^(:?{args.block.__self__.pattern})$/i;if(b.test(h))return "";' if args.block else '')
        for i, option in enumerate(args.rserver):
            pactext += (f'var m{i}=/^(:?{option.rule.__self__.pattern})$/i;if(m{i}.test(h))' if option.rule else '') + 'return "PROXY %(host)s";'
        args.httpget[args.pac] = pactext + 'return "DIRECT";}'
        args.httpget[args.pac + '/all'] = 'function FindProxyForURL(u,h){return "PROXY %(host)s";}'
        args.httpget[args.pac + '/none'] = 'function FindProxyForURL(u,h){return "DIRECT";}'
    for gets in args.gets:
        path, filename = gets.split(',', 1)
        with open(filename, 'rb') as file:
            args.httpget[path] = file.read()
    if args.daemon:
        try:
            __import__('daemon').DaemonContext().open()
        except ModuleNotFoundError:
            print('Missing library: pip3 install python-daemon')
            return
    try:
        __import__('uvloop').install()
        print('Using uvloop')
    except ModuleNotFoundError:
        pass
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if args.v:
        from . import verbose

        verbose.setup(loop, args)
    servers = []
    admin.config.update({'argv': origin_argv, 'servers': servers, 'args': args, 'loop': loop})

    def print_fn(option, bind=None):
        if runtime.is_unauthenticated_wildcard(option):
            print('WARNING: wildcard listener has no authentication; use loopback or configure credentials')
        print('Serving on', (bind or option.bind), 'by', ','.join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({}{})'.format(option.cipher.name, ' ' + ','.join(i.name() for i in option.cipher.plugins) if option.cipher and option.cipher.plugins else '') if option.cipher else '')

    for option in args.listen:
        try:
            handler = loop.run_until_complete(option.start_server(vars(args)))
            runtime.print_server_started(option, handler, print_fn)
            servers.append(handler)
        except Exception as ex:  # noqa: BLE001 - preserve CLI startup reporting
            print_fn(option)
            print('Start server failed.\n\t==>', ex)

    def print_fn(option, bind=None):
        print('Serving on UDP', (bind or option.bind), 'by', ','.join(i.name for i in option.protos), f'({option.cipher.name})' if option.cipher else '')

    for option in args.ulisten:
        try:
            handler, _protocol = loop.run_until_complete(option.udp_start_server(vars(args)))
            runtime.print_server_started(option, handler, print_fn)
            servers.append(handler)
        except Exception as ex:  # noqa: BLE001 - preserve CLI startup reporting
            print_fn(option)
            print('Start server failed.\n\t==>', ex)

    def print_fn(option, bind=None):
        print('Serving on', (bind or option.bind), 'backward by', ','.join(i.name for i in option.protos) + ('(SSL)' if option.sslclient else ''), '({}{})'.format(option.cipher.name, ' ' + ','.join(i.name() for i in option.cipher.plugins) if option.cipher and option.cipher.plugins else '') if option.cipher else '')

    for option in args.rserver:
        if isinstance(option, runtime.ProxyBackward):
            try:
                handler = loop.run_until_complete(option.start_backward_client(vars(args)))
                runtime.print_server_started(option, handler, print_fn)
                servers.append(handler)
            except Exception as ex:  # noqa: BLE001 - preserve CLI startup reporting
                print_fn(option)
                print('Start server failed.\n\t==>', ex)
    if servers:
        if args.sys:
            from . import sysproxy

            args.sys = sysproxy.setup(args)
        if args.alived > 0 and args.rserver:
            loop.create_task(runtime.check_server_alive(args.alived, args.rserver, args.verbose if args.v else runtime.DUMMY))
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print('exit')
        if args.sys:
            args.sys.clear()
    for task in asyncio.all_tasks(loop):
        task.cancel()
    for handler in servers:
        handler.close()
    for handler in servers:
        if hasattr(handler, 'wait_closed'):
            loop.run_until_complete(handler.wait_closed())
    loop.run_until_complete(loop.shutdown_asyncgens())
    if admin.config.get('reload', False):
        admin.config['reload'] = False
        main(admin.config['argv'])
    loop.close()
