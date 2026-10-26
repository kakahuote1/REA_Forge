"""Fixed single-request wire semantics; no fuzztag, script or proxy surface."""
from urllib.parse import urlsplit
import re


def request_arguments(values: dict) -> dict:
    raw = values["url"]
    if len(raw) > 8192 or re.search(r"[\x00-\x20\x7f]", raw) or not re.match(r"^https?://", raw):
        raise ValueError("requires an explicit bounded HTTP(S) URL")
    url = urlsplit(raw)
    if not url.hostname or url.username is not None or url.password is not None or url.fragment:
        raise ValueError("credentials, fragments and absent authorities are not admitted")
    host = url.hostname.encode("idna").decode("ascii")
    if ":" in host:
        host = "[" + host + "]"
    port = url.port or (443 if url.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("HTTP destination port is invalid")
    authority = host + ":" + str(port)
    method = values["method"]
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ValueError("unsupported fixed request method")
    lines = [method + " " + (url.path or "/") + ("?" + url.query if url.query else "") + " HTTP/1.1", "Host: " + authority]
    if len(values["headers"]) > 80:
        raise ValueError("request header count exceeds bound")
    for item in values["headers"]:
        name, value = item["name"], item["value"]
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name) or name.casefold() in {"host", "content-length", "transfer-encoding", "connection"} or len(value) > 8192 or any(char in value for char in "\r\n\0"):
            raise ValueError("request header overrides fixed authority/framing or injects a line")
        lines.append(name + ": " + value)
    body = values["body"]
    if len(body) > 65536:
        raise ValueError("UTF8 request body exceeds bound")
    if body or method in {"POST", "PUT", "PATCH"}:
        lines.append("Content-Length: " + str(len(body.encode("utf-8"))))
    lines.append("Connection: close")
    wire = "\r\n".join(lines) + "\r\n\r\n" + body
    if len(wire.encode("utf-8")) > 256 * 1024:
        raise ValueError("constructed UTF8 HTTP request exceeds256KiB")
    # In the pinned vendor, any positive repeatTimes prefixes {{repeat(n)}}
    # even when fuzzTagMode is close. Omit this optional input so a single
    # literal request remains a valid HTTP request; never enable tags to fix it.
    return {"request": wire, "actualAddr": authority, "isHttps": url.scheme == "https", "concurrent": 1, "fuzzTagMode": "close", "noSystemProxy": True, "noFollowRedirect": True, "redirectTimes": 0, "disableUseConnPool": True, "perRequestTimeoutSeconds": values["request_timeout_seconds"]}
