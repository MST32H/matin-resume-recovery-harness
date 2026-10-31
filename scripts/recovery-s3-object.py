#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

class S3Error(Exception):
    pass

def require(value, message):
    if not value:
        raise S3Error(message)
    return value

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def hmac_sha256(key, data):
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()

def signing_key(secret, date, region, service):
    k_date = hmac_sha256(("AWS4" + secret).encode("utf-8"), date)
    k_region = hmac_sha256(k_date, region)
    k_service = hmac_sha256(k_region, service)
    return hmac_sha256(k_service, "aws4_request")

def canonical_query(params):
    if not params:
        return ""
    encoded = []
    for key, value in params:
        encoded.append((
            quote(str(key), safe="-_.~"),
            quote(str(value), safe="-_.~"),
        ))
    encoded.sort()
    return "&".join(f"{k}={v}" for k, v in encoded)

def request(method, key, data=b"", query_params=None):
    endpoint = require(os.environ.get("RECOVERY_VAULT_S3_ENDPOINT"), "RECOVERY_VAULT_S3_ENDPOINT is required").rstrip("/")
    bucket = require(os.environ.get("RECOVERY_VAULT_S3_BUCKET"), "RECOVERY_VAULT_S3_BUCKET is required")
    access_key = require(os.environ.get("AWS_ACCESS_KEY_ID"), "AWS_ACCESS_KEY_ID is required")
    secret_key = require(os.environ.get("AWS_SECRET_ACCESS_KEY"), "AWS_SECRET_ACCESS_KEY is required")
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    service = "s3"

    parsed = urlsplit(endpoint)
    require(parsed.scheme in ("http", "https") and parsed.netloc, "invalid S3 endpoint")
    base_path = parsed.path.rstrip("/")
    raw_path = f"{base_path}/{bucket}/{key.lstrip('/')}"
    canonical_uri = quote(raw_path, safe="/-_.~")
    query = canonical_query(query_params or [])
    url = f"{parsed.scheme}://{parsed.netloc}{canonical_uri}" + (f"?{query}" if query else "")

    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = sha256_bytes(data)
    canonical_headers = (
        f"host:{parsed.netloc}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join([
        method,
        canonical_uri,
        query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(
        signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{scope},"
        f"SignedHeaders={signed_headers},"
        f"Signature={signature}"
    )
    headers = {
        "Host": parsed.netloc,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": authorization,
    }
    req = Request(url, data=(data if method == "PUT" else None), headers=headers, method=method)
    try:
        with urlopen(req, timeout=120) as response:
            return response.read(), response.status
    except HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise S3Error(f"S3 {method} failed: HTTP {exc.code}: {body[:500]}") from exc
    except URLError as exc:
        raise S3Error(f"S3 {method} failed: {exc}") from exc

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("put", "get", "head", "ensure-bucket", "list-prefix", "delete"))
    parser.add_argument("local_path")
    parser.add_argument("object_key")
    args = parser.parse_args()
    path = Path(args.local_path)
    try:
        if args.mode == "list-prefix":
            import json
            import xml.etree.ElementTree as ET
            prefix = args.object_key
            token = ""
            objects = []
            while True:
                params = [("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")]
                if token:
                    params.append(("continuation-token", token))
                body, _ = request("GET", "", query_params=params)
                root = ET.fromstring(body)
                def lname(tag):
                    return tag.rsplit("}", 1)[-1]
                next_token = ""
                truncated = False
                for child in root.iter():
                    name = lname(child.tag)
                    if name == "Contents":
                        row = {}
                        for item in child:
                            row[lname(item.tag)] = item.text or ""
                        if row.get("Key"):
                            objects.append({
                                "key": row.get("Key", ""),
                                "size": int(row.get("Size") or 0),
                                "last_modified": row.get("LastModified", ""),
                            })
                    elif name == "IsTruncated":
                        truncated = (child.text or "").strip().lower() == "true"
                    elif name == "NextContinuationToken":
                        next_token = child.text or ""
                if not truncated:
                    break
                require(next_token, "truncated S3 listing missing continuation token")
                token = next_token
            Path(args.local_path).parent.mkdir(parents=True, exist_ok=True)
            Path(args.local_path).write_text(json.dumps(objects, sort_keys=True) + "\n", encoding="utf-8")
            print(f"RECOVERY_S3_LIST_OK prefix={prefix} objects={len(objects)}")
        elif args.mode == "delete":
            request("DELETE", args.object_key)
            print(f"RECOVERY_S3_DELETE_OK key={args.object_key}")
        elif args.mode == "ensure-bucket":
            try:
                _, status = request("HEAD", "")
                print(f"RECOVERY_S3_BUCKET_OK status={status}")
            except S3Error:
                request("PUT", "", b"")
                _, status = request("HEAD", "")
                print(f"RECOVERY_S3_BUCKET_CREATED status={status}")
        elif args.mode == "put":
            require(path.is_file() and path.stat().st_size > 0, f"local file missing: {path}")
            data = path.read_bytes()
            request("PUT", args.object_key, data)
            request("HEAD", args.object_key)
            print(f"RECOVERY_S3_PUT_OK key={args.object_key} bytes={len(data)} sha256={sha256_bytes(data).upper()}")
        elif args.mode == "get":
            path.parent.mkdir(parents=True, exist_ok=True)
            data, _ = request("GET", args.object_key)
            require(data, f"downloaded object is empty: {args.object_key}")
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, path)
            print(f"RECOVERY_S3_GET_OK key={args.object_key} bytes={len(data)} sha256={sha256_bytes(data).upper()}")
        else:
            _, status = request("HEAD", args.object_key)
            print(f"RECOVERY_S3_HEAD_OK key={args.object_key} status={status}")
    except (S3Error, OSError) as exc:
        print(f"RECOVERY_S3_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
