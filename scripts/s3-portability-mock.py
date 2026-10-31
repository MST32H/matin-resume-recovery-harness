#!/usr/bin/env python3
import argparse
import hashlib
import os
import shutil
from email.utils import formatdate
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

class S3MockHandler(BaseHTTPRequestHandler):
    server_version = "MatinResumeS3Mock/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("S3MOCK %s - %s\n" % (self.address_string(), fmt % args))

    @property
    def root(self):
        return Path(self.server.storage_root)

    def _segments(self):
        path = unquote(urlsplit(self.path).path)
        return [part for part in path.split("/") if part]

    def _safe_path(self, parts):
        for part in parts:
            if part in (".", "..") or "/" in part or "\\" in part:
                raise ValueError("unsafe path segment")
        candidate = self.root.joinpath(*parts)
        resolved_root = self.root.resolve()
        resolved = candidate.resolve()
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise ValueError("path escapes storage root")
        return candidate

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _not_found(self):
        body = b'<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>Not Found</Message></Error>'
        self._send(404, body, {"Content-Type": "application/xml"})

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        if urlsplit(self.path).path == "/healthz":
            self._send(200, b"ok\n", {"Content-Type": "text/plain"})
            return
        parts = self._segments()
        if len(parts) < 2:
            self._not_found()
            return
        try:
            obj = self._safe_path(parts)
        except ValueError:
            self._send(400)
            return
        if not obj.is_file():
            self._not_found()
            return
        data = obj.read_bytes()
        etag = hashlib.md5(data).hexdigest()
        self._send(200, data, {
            "Content-Type": "application/octet-stream",
            "ETag": f'"{etag}"',
            "Last-Modified": formatdate(obj.stat().st_mtime, usegmt=True),
            "Accept-Ranges": "bytes"
        })

    def do_HEAD(self):
        parts = self._segments()
        if not parts:
            self._send(200)
            return
        try:
            target = self._safe_path(parts)
        except ValueError:
            self._send(400)
            return
        if len(parts) == 1:
            self._send(200 if target.is_dir() else 404)
            return
        if not target.is_file():
            self._send(404)
            return
        size = target.stat().st_size
        etag = hashlib.md5(target.read_bytes()).hexdigest()
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.send_header("ETag", f'"{etag}"')
        self.send_header("Last-Modified", formatdate(target.stat().st_mtime, usegmt=True))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()

    def do_PUT(self):
        parts = self._segments()
        if not parts:
            self._send(400)
            return
        try:
            target = self._safe_path(parts)
        except ValueError:
            self._send(400)
            return
        if len(parts) == 1:
            target.mkdir(parents=True, exist_ok=True)
            self._send(200)
            return
        bucket = self._safe_path(parts[:1])
        if not bucket.is_dir():
            self._not_found()
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        body = self._read_body()
        target.write_bytes(body)
        etag = hashlib.md5(body).hexdigest()
        self._send(200, headers={"ETag": f'"{etag}"'})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4566)
    parser.add_argument("--storage-root", required=True)
    args = parser.parse_args()

    root = Path(args.storage_root)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer((args.host, args.port), S3MockHandler)
    server.storage_root = str(root)
    print(f"S3_PORTABILITY_MOCK_READY host={args.host} port={args.port} root={root}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
