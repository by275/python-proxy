"""Minimal HTTP administration handlers for runtime reload support."""

import json

from .runtime import ADMIN_BODY_LIMIT

config = {}
MAX_ADMIN_BODY = ADMIN_BODY_LIMIT


async def reply_http(reply, ver, code, content):
    await reply(code, f'{ver} {code}\r\nConnection: close\r\nContent-Type: text/plain\r\nCache-Control: max-age=900\r\nContent-Length: {len(content)}\r\n\r\n'.encode(), content, True)


async def status_handler(reply, **kwarg):
    method = kwarg.get('method')
    if method == 'GET':
        data = {"status": "ok"}
        value = json.dumps(data).encode()
        ver = kwarg.get('ver')
        await reply_http(reply, ver, '200 OK', value)


async def configs_handler(reply, **kwarg):
    method = kwarg.get('method')
    ver = kwarg.get('ver')

    if method == 'GET':
        data = {
            "reload": bool(config.get('reload')),
            "actions": ["reload"],
        }
        value = json.dumps(data).encode()
        await reply_http(reply, ver, '200 OK', value)
    elif method == 'POST':
        try:
            request = json.loads(kwarg.get('content', b'{}'))
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            await reply_http(reply, ver, '400 Bad Request', b'invalid JSON')
            return
        if request != {'action': 'reload'}:
            await reply_http(reply, ver, '400 Bad Request', b'unsupported action')
            return
        config['reload'] = True
        data = {"result": 'reload scheduled'}
        value = json.dumps(data).encode()
        await reply_http(reply, ver, '200 OK', value)
        raise KeyboardInterrupt


httpget = {
    '/status': status_handler,
    '/configs': configs_handler,
}
