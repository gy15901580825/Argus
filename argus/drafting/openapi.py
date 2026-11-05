from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml


MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 50_000
METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace", "query"})


class _Role(Enum):
    DOCUMENT = "document"
    COMPONENTS = "components"
    PATH_ITEM = "path_item"
    OPERATION = "operation"
    SCHEMA = "schema"
    PARAMETER = "parameter"
    REQUEST_BODY = "request_body"
    RESPONSE = "response"
    MEDIA = "media"
    SERVER = "server"
    LINK = "link"
    ENCODING = "encoding"
    DISCRIMINATOR = "discriminator"
    DATA = "data"
    PLAIN = "plain"


@dataclass(frozen=True)
class _NamedMap:
    child: _Role | _NamedMap


_CHILD_ROLES = {
    _Role.DOCUMENT: {"components": _Role.COMPONENTS, "paths": _NamedMap(_Role.PATH_ITEM),
                     "webhooks": _NamedMap(_Role.PATH_ITEM), "servers": _Role.SERVER,
                     "security": _NamedMap(_Role.PLAIN)},
    _Role.COMPONENTS: {"schemas": _NamedMap(_Role.SCHEMA), "parameters": _NamedMap(_Role.PARAMETER),
                      "responses": _NamedMap(_Role.RESPONSE), "requestBodies": _NamedMap(_Role.REQUEST_BODY),
                      "headers": _NamedMap(_Role.PARAMETER), "securitySchemes": _NamedMap(_Role.PLAIN),
                      "links": _NamedMap(_Role.LINK), "callbacks": _NamedMap(_NamedMap(_Role.PATH_ITEM)),
                      "pathItems": _NamedMap(_Role.PATH_ITEM)},
    _Role.PATH_ITEM: {**{method: _Role.OPERATION for method in METHODS},
                     "parameters": _Role.PARAMETER, "servers": _Role.SERVER,
                     "additionalOperations": _NamedMap(_Role.OPERATION)},
    _Role.OPERATION: {"parameters": _Role.PARAMETER, "servers": _Role.SERVER,
                     "requestBody": _Role.REQUEST_BODY, "responses": _NamedMap(_Role.RESPONSE),
                     "callbacks": _NamedMap(_NamedMap(_Role.PATH_ITEM)), "security": _NamedMap(_Role.PLAIN)},
    _Role.SCHEMA: {"properties": _NamedMap(_Role.SCHEMA), "patternProperties": _NamedMap(_Role.SCHEMA),
                  "$defs": _NamedMap(_Role.SCHEMA), "definitions": _NamedMap(_Role.SCHEMA),
                  "dependentSchemas": _NamedMap(_Role.SCHEMA),
                  "dependentRequired": _NamedMap(_Role.DATA), "enum": _Role.DATA, "const": _Role.DATA,
                  "discriminator": _Role.DISCRIMINATOR,
                  **{key: _Role.SCHEMA for key in ("items", "additionalProperties", "not", "allOf",
                                                 "anyOf", "oneOf", "if", "then", "else", "prefixItems")}},
    _Role.PARAMETER: {"schema": _Role.SCHEMA, "content": _NamedMap(_Role.MEDIA)},
    _Role.REQUEST_BODY: {"content": _NamedMap(_Role.MEDIA)},
    _Role.RESPONSE: {"content": _NamedMap(_Role.MEDIA), "headers": _NamedMap(_Role.PARAMETER),
                     "links": _NamedMap(_Role.LINK)},
    _Role.MEDIA: {"schema": _Role.SCHEMA, "encoding": _NamedMap(_Role.ENCODING)},
    _Role.SERVER: {"variables": _NamedMap(_Role.PLAIN)},
    _Role.LINK: {"parameters": _NamedMap(_Role.DATA), "requestBody": _Role.DATA, "server": _Role.SERVER},
    _Role.ENCODING: {"headers": _NamedMap(_Role.PARAMETER)},
    _Role.DISCRIMINATOR: {"mapping": _NamedMap(_Role.DATA)},
}


class DocumentError(ValueError):
    pass


@dataclass(frozen=True)
class Source:
    file: str
    pointer: str

    def to_dict(self):
        return {"file": self.file, "pointer": self.pointer}


@dataclass(frozen=True)
class DocumentIssue:
    code: str
    source: Source


@dataclass(frozen=True)
class ApiDocument:
    data: dict
    sources: dict[str, Source]
    inputs: tuple[dict, ...]
    issues: tuple[DocumentIssue, ...]

    def source(self, pointer: str) -> Source:
        return self.sources[pointer]


@dataclass(frozen=True)
class Operation:
    id: str
    method: str
    path: str
    pointer: str
    data: dict
    path_data: dict


@dataclass(frozen=True)
class OperationCatalog:
    document: ApiDocument
    operations: tuple[Operation, ...]


def pointer_child(pointer, key):
    return pointer + "/" + str(key).replace("~", "~0").replace("/", "~1")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise DocumentError("Document keys must be unique strings")
        result[key] = value
    return result


class _SafeLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    return _unique((loader.construct_object(key), loader.construct_object(value))
                   for key, value in node.value)


_SafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


class _Reader:
    def __init__(self, root):
        self.root = root
        self.documents = {}
        self.inputs = []
        self.bytes = 0
        self.nodes = 0
        self.sources = {}
        self.issues = []

    def read(self, file):
        if file in self.documents:
            return self.documents[file]
        if file.suffix.lower() not in {".json", ".yaml", ".yml"}:
            raise DocumentError("Only local JSON/YAML document files are allowed")
        if re.search(r"(^|[-_.])(key|keys|token|tokens|secret|secrets|credential|credentials|password|auth|apikey)([-_.]|$)", file.stem, re.I):
            raise DocumentError("Credential files are not document inputs")
        try:
            relative = file.relative_to(self.root)
        except ValueError:
            raise DocumentError("Reference escapes the input directory") from None
        cursor = self.root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise DocumentError("Document symlinks are not allowed")
        try:
            info = file.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size + self.bytes > MAX_BYTES:
                raise DocumentError("Document byte limit exceeded or file is not regular")
            with file.open("rb") as handle:
                raw = handle.read(MAX_BYTES - self.bytes + 1)
            self.bytes += len(raw)
            if self.bytes > MAX_BYTES:
                raise DocumentError("Document byte limit exceeded")
            text = raw.decode("utf-8")
            if file.suffix.lower() == ".json":
                data = json.loads(text, object_pairs_hook=_unique)
            else:
                depth = 0
                count = 0
                for event in yaml.parse(text):
                    count += 1
                    if isinstance(event, yaml.AliasEvent):
                        raise DocumentError("YAML aliases are not allowed")
                    if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                        depth += 1
                    elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                        depth -= 1
                    if depth > MAX_DEPTH or count > MAX_NODES * 3:
                        raise DocumentError("Document structure limit exceeded")
                data = yaml.load(text, Loader=_SafeLoader)
        except (OSError, UnicodeError, yaml.YAMLError, json.JSONDecodeError, RecursionError) as exc:
            raise DocumentError(f"Cannot parse local document ({type(exc).__name__})") from None
        if not isinstance(data, dict):
            raise DocumentError("Document root must be an object")
        self.documents[file] = data
        self.inputs.append({"file": relative.as_posix(), "sha256": hashlib.sha256(raw).hexdigest()})
        return data

    def reference(self, file, reference):
        if not isinstance(reference, str):
            raise DocumentError("Reference must be a string")
        parts = urlsplit(reference)
        if parts.scheme or parts.netloc or parts.query or "\\" in reference:
            raise DocumentError("Network references are not allowed")
        name = unquote(parts.path)
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise DocumentError("Reference escapes the input directory")
        target = file.parent / name if name else file
        raw = self.read(target)
        pointer = unquote(parts.fragment)
        if (pointer and not pointer.startswith("/")) or re.search(r"~(?![01])", pointer):
            raise DocumentError("Reference must use a JSON Pointer")
        value = raw
        try:
            for key in pointer.split("/")[1:]:
                key = key.replace("~1", "/").replace("~0", "~")
                if isinstance(value, list):
                    if not re.fullmatch(r"0|[1-9]\d*", key):
                        raise ValueError("Invalid array pointer")
                    value = value[int(key)]
                else:
                    value = value[key]
        except (KeyError, IndexError, TypeError, ValueError):
            raise DocumentError("Reference pointer does not exist") from None
        return target, pointer, value

    def expand(self, value, file, source_pointer, output_pointer="", stack=(), depth=0,
               role: _Role | _NamedMap = _Role.DOCUMENT):
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise DocumentError("Expanded document structure limit exceeded")
        source = Source(file.relative_to(self.root).as_posix(), source_pointer)
        self.sources[output_pointer] = source
        if isinstance(value, dict):
            if "$ref" in value and role != _Role.DATA and not isinstance(role, _NamedMap):
                target, pointer, resolved = self.reference(file, value["$ref"])
                key = (target, pointer)
                if key in stack:
                    self.issues.append(DocumentIssue("reference_cycle", source))
                    return {"$ref": value["$ref"]}
                result = self.expand(resolved, target, pointer, output_pointer, stack + (key,), depth + 1, role)
                if not isinstance(result, dict):
                    raise DocumentError("Referenced object must be a mapping")
                for name, item in value.items():
                    if name not in {"$ref", "example", "examples", "default"}:
                        if name not in {"description", "summary"}:
                            self.issues.append(DocumentIssue("reference_siblings_unsupported", source))
                        else:
                            result[name] = self.expand(item, file, pointer_child(source_pointer, name),
                                                       pointer_child(output_pointer, name), stack, depth + 1,
                                                       _CHILD_ROLES.get(role, {}).get(name, _Role.DATA))
                return result
            result = {}
            for name, item in value.items():
                if role != _Role.DATA and not isinstance(role, _NamedMap) and name in {"example", "examples", "default"}:
                    continue
                if role == _Role.PATH_ITEM and name == "additionalOperations":
                    if not isinstance(item, dict) or any(not isinstance(op, dict) for op in item.values()):
                        raise DocumentError("Additional operations must be an operation map")
                    self.issues.append(DocumentIssue("additional_operations_unsupported",
                                                     Source(source.file, pointer_child(source_pointer, name))))
                if role == _Role.PATH_ITEM and name in {"trace", "query"}:
                    self.issues.append(DocumentIssue("http_method_unsupported",
                                                     Source(source.file, pointer_child(source_pointer, name))))
                child_role = (role.child if isinstance(role, _NamedMap) else _Role.DATA if role == _Role.DATA
                              else _CHILD_ROLES.get(role, {}).get(name, _Role.DATA))
                result[name] = self.expand(item, file, pointer_child(source_pointer, name),
                                           pointer_child(output_pointer, name), stack, depth + 1, child_role)
            return result
        if isinstance(value, list):
            return [self.expand(item, file, pointer_child(source_pointer, index),
                                pointer_child(output_pointer, index), stack, depth + 1, role)
                    for index, item in enumerate(value)]
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise DocumentError("Document contains non-JSON values")
        if isinstance(value, float) and not math.isfinite(value):
            raise DocumentError("Document contains non-finite numbers")
        return value


def load_openapi(path: Path) -> ApiDocument:
    path = Path(path).absolute()
    reader = _Reader(path.parent.resolve())
    data = reader.expand(reader.read(path), path, "")
    if not isinstance(data.get("openapi"), str) or not re.fullmatch(r"3\.[012]\.\d+", data["openapi"]):
        raise DocumentError("OpenAPI 3.0, 3.1 or 3.2 is required")
    if not isinstance(data.get("info"), dict) or not isinstance(data.get("paths"), dict):
        raise DocumentError("OpenAPI info and paths must be objects")
    if any(not isinstance(data["info"].get(key), str) or not data["info"][key] for key in ("title", "version")):
        raise DocumentError("OpenAPI info requires title and version strings")
    return ApiDocument(data, reader.sources, tuple(reader.inputs), tuple(reader.issues))


def catalog_operations(document: ApiDocument) -> OperationCatalog:
    operations = []
    ids = set()
    for path, item in document.data["paths"].items():
        if not path.startswith("/") or not isinstance(item, dict):
            raise DocumentError("OpenAPI path items must be objects with absolute paths")
        path_pointer = pointer_child("/paths", path)
        for method, operation in item.items():
            if method not in METHODS:
                continue
            if not isinstance(operation, dict):
                raise DocumentError("OpenAPI operations must be objects")
            identifier = operation.get("operationId", method.upper() + " " + path)
            if not isinstance(identifier, str) or not identifier or identifier in ids:
                raise DocumentError("Operation IDs must be nonempty and unique")
            ids.add(identifier)
            operations.append(Operation(identifier, method.upper(), path,
                                        pointer_child(path_pointer, method), operation, item))
    return OperationCatalog(document, tuple(operations))
