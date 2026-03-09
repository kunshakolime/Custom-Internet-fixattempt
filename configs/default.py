# configs/default.py
# MODE: direct | http_payload | sni_fronted

CONFIG = {
    'MODE':           'http_payload',
    'PROXY':          'your.proxy.host:80',    # host your ISP sees
    'TARGET':         'your.target.host:80',   # SSH-over-WS server
    'SSH_USERNAME':   '',
    'SSH_PASSWORD':   '',
    'LOCAL_SOCKS_PORT': 1080,
    'FRONT_DOMAIN':   '',                      # sni_fronted only

    # [host] → TARGET host:port  |  [crlf] → \r\n  |  [split] → block boundary
    'PAYLOAD_TEMPLATE': (
        "GET / HTTP/1.1[crlf]"
        "Host: [host][crlf]"
        "Connection: Upgrade[crlf]"
        "Upgrade: websocket[crlf]"
        "[crlf]"
    ),
}
