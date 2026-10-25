"""Documented Apipost interchange semantics, independent of GUI/profile data."""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"})
MAX_ENDPOINTS = 4096
MAX_TEXT = 4096


def validate_shape(value: object) -> None:
    pending = [(value, 0)]
    examined = 0
    while pending:
        current, depth = pending.pop()
        examined += 1
        if examined > 100000 or depth > 48:
            raise ValueError("API document exceeds structural bounds")
        if isinstance(current, dict):
            if any(len(key) > MAX_TEXT for key in current):
                raise ValueError("API document member name exceeds its bound")
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def variable(name: str, value: object, enabled: bool) -> dict:
    if len(name) > MAX_TEXT:
        raise ValueError("API variable name exceeds its text bound")
    rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {"name": name, "enabled": enabled, "value_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest()}


def endpoint(method: str, path: str, label: str, details: dict) -> dict:
    # This reader intentionally exposes paths, not recorded hosts/query values.
    path = path.split("?", 1)[0] or "/"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > MAX_TEXT or len(label) > MAX_TEXT:
        raise ValueError("API endpoint text exceeds its bound")
    return {"identity": method + " " + path, "method": method, "path": path, "label": label, **details}


def postman_path(value: object) -> str:
    if isinstance(value, str):
        return urlsplit(value).path or "/"
    if isinstance(value, dict):
        if isinstance(value.get("path"), list) and all(isinstance(part, str) for part in value["path"]):
            return "/" + "/".join(value["path"])
        if isinstance(value.get("raw"), str):
            return urlsplit(value["raw"]).path or "/"
    raise ValueError("Postman request has no supported URL/path representation")


def normalize(document: dict) -> dict:
    validate_shape(document)
    endpoints, variables = [], []
    metadata = {}
    if (isinstance(document.get("openapi"), str) and document["openapi"].startswith("3.")) or document.get("swagger") == "2.0":
        kind = "openapi_3" if "openapi" in document else "swagger_2"
        if not isinstance(document.get("paths"), dict):
            raise ValueError("API document has no paths object")
        metadata = document.get("info", {})
        for path, path_item in document["paths"].items():
            if not path.startswith("/") or not isinstance(path_item, dict):
                raise ValueError("invalid API path item")
            for raw_method, operation in path_item.items():
                method = raw_method.upper()
                if method not in METHODS:
                    continue
                if not isinstance(operation, dict):
                    raise ValueError("invalid API operation")
                label = operation.get("operationId") or operation.get("summary") or operation.get("description") or ""
                if not isinstance(label, str):
                    raise ValueError("API operation label is not text")
                parameters = operation.get("parameters", [])
                inherited = path_item.get("parameters", [])
                responses = operation.get("responses", {})
                if not isinstance(parameters, list) or not isinstance(inherited, list) or not isinstance(responses, dict):
                    raise ValueError("invalid API operation structure")
                tags = operation.get("tags", [])
                if not isinstance(tags, list):
                    raise ValueError("API tags are not an array")
                endpoints.append(endpoint(method, path, label, {"parameter_count": len(parameters), "path_parameter_count": len(inherited), "tag_count": len(tags),
                    "has_request_body": isinstance(operation.get("requestBody"), dict) or any(isinstance(item, dict) and item.get("in") == "body" for item in parameters),
                    "response_codes": sorted(responses)}))
        servers = document.get("servers", [])
        if not isinstance(servers, list):
            raise ValueError("API servers are not an array")
        for server in servers:
            if isinstance(server, dict) and isinstance(server.get("variables"), dict):
                for name, definition in server["variables"].items():
                    if isinstance(definition, dict):
                        variables.append(variable(name, definition.get("default"), True))
    elif isinstance(document.get("info"), dict) and document["info"].get("schema") in {
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        "http://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    }:
        kind, metadata = "postman_collection_v2_1", document["info"]
        if not isinstance(document.get("item"), list):
            raise ValueError("Postman collection has no item array")
        pending = [(document["item"], [])]
        collection_variables = document.get("variable", [])
        if not isinstance(collection_variables, list):
            raise ValueError("Postman collection variables are not an array")
        for item in collection_variables:
            if isinstance(item, dict) and isinstance(item.get("key"), str):
                variables.append(variable(item["key"], item.get("value"), item.get("disabled") is not True))
        while pending:
            items, parents = pending.pop()
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError("invalid Postman item")
                name = item.get("name", "")
                if not isinstance(name, str):
                    raise ValueError("Postman item name is not text")
                if isinstance(item.get("item"), list):
                    pending.append((item["item"], parents + [name]))
                    continue
                request = item.get("request")
                if not isinstance(request, dict) or not isinstance(request.get("method"), str):
                    raise ValueError("Postman item has no structured request")
                method = request["method"].upper()
                if method not in METHODS:
                    raise ValueError("unsupported Postman request method")
                endpoints.append(endpoint(method, postman_path(request.get("url")), " / ".join(parents + [name]), {
                    "header_count": len(request.get("header", [])) if isinstance(request.get("header", []), list) else 0,
                    "has_body": isinstance(request.get("body"), dict),
                }))
    elif isinstance(document.get("values"), list) and isinstance(document.get("name"), str):
        kind, metadata = "postman_environment", {"name": document["name"]}
        for item in document["values"]:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                raise ValueError("invalid Postman environment variable")
            variables.append(variable(item["key"], item.get("value"), item.get("enabled") is not False))
    else:
        raise ValueError("unsupported API interchange format; use native inspect_web_network_capture for HAR/SAZ")
    if len(endpoints) > MAX_ENDPOINTS or len(variables) > MAX_ENDPOINTS:
        raise ValueError("API document exceeds endpoint/variable bound")
    if not isinstance(metadata, dict):
        raise ValueError("API metadata is not an object")
    title, version = metadata.get("title") or metadata.get("name") or "", metadata.get("version") or ""
    if not isinstance(title, str) or not isinstance(version, str) or max(len(title), len(version)) > MAX_TEXT:
        raise ValueError("API metadata is outside its text bound")
    return {"format": kind, "metadata": {"title": title, "version": version},
            "endpoints": sorted(endpoints, key=lambda item: item["identity"]), "variables": sorted(variables, key=lambda item: item["name"]),
            "variable_values": "sha256-only", "referenced_urls_fetched": False}
