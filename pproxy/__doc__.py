import subprocess
from pathlib import Path


__title__       = "pproxy"
__license__     = "MIT"
__description__ = "Proxy server that can tunnel among remote servers by regex rules."
__keywords__    = "proxy socks http shadowsocks shadowsocksr ssr redirect pf tunnel cipher ssl udp"
__author__      = "Qian Wenjie"
__email__       = "qianwenjie@gmail.com"
__url__         = "https://github.com/qwj/python-proxy"

def _git_version(root):
    try:
        description = subprocess.check_output(
            ['git', 'describe', '--tags', '--long', '--dirty', '--always'],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return None
    dirty = description.endswith('-dirty')
    if dirty:
        description = description[:-6]
    parts = description.rsplit('-', 2)
    if len(parts) == 3 and parts[1].isdigit() and parts[2].startswith('g'):
        version_text = f'{parts[0]}.dev{parts[1]}+{parts[2]}'
    else:
        version_text = description
    return version_text + ('.dirty' if dirty else '')


def _source_version():
    root = Path(__file__).resolve().parents[1]
    if not (root / '.git').exists():
        return None
    try:
        from setuptools_scm import get_version

        return get_version(root=root)
    except Exception:
        return _git_version(root)


try:
    from importlib.metadata import PackageNotFoundError, version
    __version__ = _source_version() or version(__title__)
except PackageNotFoundError:
    __version__ = _source_version() or 'unknown'

__all__ = ['__version__', '__description__', '__url__']
