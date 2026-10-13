"""Source-owned native flows for offline API-surface verification; no listener."""
from mitmproxy import connection, http, tcp, version
from mitmproxy.io import FlowWriter


def write_api_surface_capture(path):
    assert version.VERSION == "12.2.3", version.VERSION
    client = connection.Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2))
    server = connection.Server(address=("example.test", 443))
    flows = []
    for target, status, headers in [
        ("/items/1?token=QUERY_VALUE_ONLY", 200, [(b"Content-Type", b"application/json; charset=utf-8")]),
        ("https://example.test/items/2?token=QUERY_VALUE_ONLY", 404, [(b"Content-Type", b"text/plain")]),
        ("/health", None, []),
        ("/dup", 200, [(b"Content-Type", b"application/json"), (b"content-type", b"text/plain")]),
        ("*", 200, []),
        ("https://user:AUTH_ONLY@example.test/hidden", 200, []),
    ]:
        flow = http.HTTPFlow(client, server)
        flow.request = http.Request.make("OPTIONS" if target == "*" else "GET", "https://example.test/", headers=[(b"Authorization", b"Bearer AUTH_ONLY")])
        flow.request.path = target
        if status is not None:
            flow.response = http.Response.make(status, b"BODY_ONLY", headers + [(b"Set-Cookie", b"session=AUTH_ONLY")])
        flows.append(flow)
    flows.append(tcp.TCPFlow(client, server))
    with path.open("wb") as handle:
        writer = FlowWriter(handle)
        for flow in flows:
            writer.add(flow)
