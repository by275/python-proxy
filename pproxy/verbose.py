"""Optional console statistics and verbose runtime reporting."""

import asyncio
import functools
import sys
import time

def b2s(value):
    """Format a byte count using a compact human-readable unit."""
    if value >= 2**30:
        return f'{value/2**30:.1f}G'
    if value >= 2**20:
        return f'{value/2**20:.1f}M'
    return f'{value/1024:.1f}K'


class StatUpdater:  # pylint: disable=too-few-public-methods
    """Update two aggregate counters for one statistics field."""

    __slots__ = ("primary", "secondary", "index")

    def __init__(self, primary, secondary, index):
        self.primary = primary
        self.secondary = secondary
        self.index = index

    def __call__(self, size):
        """Add a byte or connection delta to both counters."""
        index = self.index
        self.primary[index] += size
        self.secondary[index] += size


class ConnectionStat:  # pylint: disable=too-few-public-methods
    """Expose per-field statistic updaters for one connection."""

    __slots__ = ("updaters",)

    def __init__(self, primary, secondary):
        self.updaters = tuple(
            StatUpdater(primary, secondary, index) for index in range(6)
        )

    def __call__(self, index):
        """Return the updater for a statistics field index."""
        return self.updaters[index]

def all_stat_other(stats):
    """Wait for console input and print aggregate statistics."""
    _cmd = sys.stdin.readline()
    all_stat(stats)

def all_stat(stats):
    """Print aggregate traffic and connection statistics."""
    if len(stats) <= 1:
        print('no traffic')
        return
    print('='*70)
    hstat = {}
    for remote_ip, v in stats.items():
        if remote_ip == 0:
            continue
        stat = [0]*6
        for host_name, v2 in v.items():
            for h in (stat, hstat.setdefault(host_name, [0]*6)):
                for i in range(6):
                    h[i] += v2[i]
        stat = [b2s(i) for i in stat[:4]] + stat[4:]
        print(remote_ip, f'\tDIRECT: {stat[5]} ({stat[1]},{stat[3]})  PROXY: {stat[4]} ({stat[0]},{stat[2]})')
    print(' '*3+'-'*64)
    hstat = sorted(hstat.items(), key=lambda x: sum(x[1]), reverse=True)[:15]
    hlen = max(map(lambda x: len(x[0]), hstat)) if hstat else 0
    for host_name, stat in hstat:
        stat, conn = (b2s(stat[0]+stat[1]), b2s(stat[2]+stat[3])), stat[4]+stat[5]
        print(host_name.ljust(hlen+5), f'{stat[0]} / {stat[1]}', f'/ {conn}' if conn else '')
    print('='*70)

async def realtime_stat(stats):
    """Continuously print one-second traffic rates to the console."""
    history = [(stats[:4], time.perf_counter())]
    while True:
        await asyncio.sleep(1)
        history.append((stats[:4], time.perf_counter()))
        i0, t0, i1, t1 = history[0][0], history[0][1], history[-1][0], history[-1][1]
        stat = [b2s((i1[i]-i0[i])/(t1-t0))+'/s' for i in range(4)] + stats[4:]
        sys.stdout.write(f'DIRECT: {stat[5]} ({stat[1]},{stat[3]})   PROXY: {stat[4]} ({stat[0]},{stat[2]})\x1b[0K\r')
        sys.stdout.flush()
        if len(history) >= 10:
            del history[:1]

def setup(loop, args):
    """Install verbose output, statistics callbacks, and console readers."""
    def verbose(s):
        if args.v >= 1:
            sys.stdout.write('\x1b[32m'+time.strftime('%Y-%m-%d %H:%M:%S')+'\x1b[m ')
            sys.stdout.write(s+'\x1b[0K\n')
        else:
            sys.stdout.write(s+'\n')
        sys.stdout.flush()
    args.verbose = verbose
    args.stats = {0: [0]*6}
    def modstat(user, remote_ip, host_name, stats=args.stats):
        u = user.decode().split(':')[0]+':' if isinstance(user, (bytes,bytearray)) else ''
        host_name_2 = (
            '.'.join(host_name.split('.')[-3 if host_name.endswith('.com.cn') else -2:])
            if host_name.split('.')[-1].isalpha() else host_name
        )
        return ConnectionStat(stats[0], stats.setdefault(u+remote_ip, {}).setdefault(host_name_2, [0]*6))
    args.modstat = modstat
    def win_readline(handler):
        while True:
            _line = sys.stdin.readline()
            handler()
    if args.v >= 2:
        loop.create_task(realtime_stat(args.stats[0]))
        if sys.platform != 'win32':
            loop.add_reader(sys.stdin, functools.partial(all_stat_other, args.stats))
        else:
            loop.run_in_executor(None, win_readline, functools.partial(all_stat, args.stats))
