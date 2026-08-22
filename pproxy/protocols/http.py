"""Pure HTTP header parsing helpers."""

import re

HTTP_LINE = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)$')
HTTP_METHOD_LINE = re.compile(br'([^ ]+) +(.+?) +(HTTP/[^ ]+)$')


def _decode_header_value(value):
    return value.decode('latin1')


def parse_http_request_head(data):
    request_line, *header_lines = data.split(b'\r\n')
    match = HTTP_METHOD_LINE.match(request_line)
    if match is None:
        raise Exception('Unknown HTTP header')
    method_b, path_b, ver_b = match.groups()
    filtered_headers = []
    host = ''
    proxy_authorization = None
    sec_websocket_key = None
    for header in header_lines:
        key, sep, value = header.partition(b': ')
        if sep:
            if key == b'Host':
                host = _decode_header_value(value)
            elif key == b'Proxy-Authorization':
                proxy_authorization = _decode_header_value(value)
            elif key == b'Sec-WebSocket-Key':
                sec_websocket_key = _decode_header_value(value)
        if not header.startswith(b'Proxy-'):
            filtered_headers.append(header)
    return (
        _decode_header_value(method_b),
        _decode_header_value(path_b),
        _decode_header_value(ver_b),
        b'\r\n'.join(filtered_headers),
        host,
        proxy_authorization,
        sec_websocket_key,
    )


def decode_http_header_block(header_block):
    header_lines = header_block.split(b'\r\n') if header_block else ()
    headers = {}
    for line in header_lines:
        key, sep, value = line.partition(b': ')
        if sep:
            headers[_decode_header_value(key)] = _decode_header_value(value)
    return headers, '\r\n'.join(_decode_header_value(line) for line in header_lines)
