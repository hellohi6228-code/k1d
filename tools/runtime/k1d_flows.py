"""mitmproxy add-on for k1d runtime tests.

Writes one JSON line per decrypted HTTP request, and one line per TLS connection the app refused
to make through the proxy (usually certificate pinning), to the file given by --set k1d_flowlog=...

Run: mitmdump --listen-port 8080 -s k1d_flows.py --set k1d_flowlog=flows.jsonl
"""
import json
import time

from mitmproxy import ctx

MAX_BODY = 65536
KEEP_HEADERS = {"user-agent", "content-type", "content-encoding", "x-requested-with", "cookie", "authorization"}


class K1dFlows:
    def __init__(self):
        self.fh = None

    def load(self, loader):
        loader.add_option("k1d_flowlog", str, "flows.jsonl", "Where to write k1d flow records")

    def running(self):
        self.fh = open(ctx.options.k1d_flowlog, "a", encoding="utf-8")

    def _write(self, rec):
        if self.fh:
            self.fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.fh.flush()

    @staticmethod
    def _text(message):
        if message is None or message.raw_content is None:
            return "", 0
        size = len(message.raw_content)
        try:
            body = message.get_content(strict=False) or b""
        except Exception:
            body = message.raw_content or b""
        body = body[:MAX_BODY]
        try:
            return body.decode("utf-8"), size
        except UnicodeDecodeError:
            return body.decode("latin-1"), size

    def response(self, flow):
        req = flow.request
        body, size = self._text(req)
        resp_body, resp_size = self._text(flow.response)
        self._write({
            "t": req.timestamp_start or time.time(),
            "host": req.pretty_host,
            "method": req.method,
            "url": req.pretty_url[:4096],
            "status": flow.response.status_code if flow.response else None,
            "headers": {k.lower(): v[:512] for k, v in req.headers.items() if k.lower() in KEEP_HEADERS},
            "body": body,
            "bodySize": size,
            "respSize": resp_size,
            "respType": (flow.response.headers.get("content-type", "") if flow.response else "")[:120],
        })

    def tls_failed_client(self, data):
        sni = data.context.client.sni or (data.context.server.address[0] if data.context.server.address else "")
        self._write({"t": time.time(), "tlsFailed": True, "host": sni, "error": str(data.conn.error or "")[:300]})

    def done(self):
        if self.fh:
            self.fh.close()


addons = [K1dFlows()]
