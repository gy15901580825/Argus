from __future__ import annotations

import json
import ipaddress
import os
import re
import tempfile
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx
import idna

from argus_transport import TransportSpecV2
from argus_transport.models import AuthSpec, path as transport_path
from argus_transport.spec_v2 import CONTEXT_KEYS_V2, NAME_RE, SECRET_WORDS

from .bindings import DraftInputs, UserField, UserStep, UserId
from .openapi import OperationCatalog, Source, pointer_child


DECISIONS = {
    "operation_ambiguous": "Select the documented invoke operation with --operation.",
    "invoke_proposed": "Confirm that the selected operation is the agent invocation.",
    "server_missing": "Provide an OpenAPI file that declares the intended server.",
    "server_ambiguous": "Select one declared origin with --server-origin.",
    "server_invalid": "Correct unsafe server URLs or unresolved variables in the input document.",
    "prompt_binding_missing": "Identify the documented prompt property before compiling a target.",
    "reply_binding_missing": "Identify the documented answer property in a successful response.",
    "completion_missing": "Provide the documented terminal-success state instead of relying on HTTP status alone.",
    "prompt_binding_proposed": "Confirm that this request property carries the question.",
    "reply_binding_proposed": "Confirm that this response property carries the agent answer.",
    "completion_proposed": "Confirm that this enum value means the agent completed successfully.",
    "authentication_binding_required": "Bind TARGET_API_KEY to the required credential outside the generated files.",
    "authentication_unsupported": "Select an unambiguous supported authentication scheme or supply its missing declaration.",
    "cleanup_endpoint_missing": "Decide whether invocation creates persistent resources and supply cleanup documentation if needed.",
    "cleanup_mapping_missing": "Select the documented cleanup relation; no cleanup request is generated yet.",
    "business_input_missing": "Provide an explicit binding for the required business field; examples are not production values.",
    "parameter_binding_required": "Supply the non-secret parameter through the generated TARGET_INPUT environment binding.",
    "body_binding_required": "Supply the required non-secret body field through the generated TARGET_INPUT environment binding; examples are not production values.",
    "schema_constraints_unchecked": "Confirm that values sent and received satisfy these schema constraints; the draft does not check them.",
    "optional_inputs_unbound": "Decide whether the omitted optional fields or material are required for your use case.",
    "reference_cycle": "Provide a bounded schema without cyclic references.",
    "async_poll_missing": "Provide the documented GET operation that returns the submitted job's state and result.",
    "poll_ambiguous": "Select the documented poll operation with --poll-operation.",
    "poll_id_binding_missing": "Document which submit response field fills each poll path parameter.",
    "poll_proposed": "Confirm that this GET operation returns the submitted job's state and result.",
    "poll_id_binding_proposed": "Confirm that this submit response field identifies the job the poll operation reads.",
    "poll_id_extraction_proposed": "Confirm that the submit ID is a full resource name with the documented poll prefix. If the submit returns a bare ID, set ids.<field>.last_segment to false.",
    "poll_identity_unchecked": "Review how the poll response verifies the submitted ID. No documented identity field was found.",
    "poll_resource_format_unsupported": "Correct the resource-name Format declaration to match a supported poll path and carried values.",
    "poll_status_proposed": "Confirm the success value and the values that mean the job is still running.",
    "poll_status_unclassified": "Confirm that these documented values should end the run as target errors.",
    "async_shape_unsupported": "Review the asynchronous flow; this command drafts only a documented GET poll with a top-level string status enum.",
    "success_conditions_minimal": "Confirm which fields a successful response must carry; add exists checks to the success rule if the API guarantees them.",
    "required_fields_unchecked": "Decide whether a successful response must carry these fields; the success rule does not check them.",
    "field_path_unwritable": "Document another field for this role; no transport path can name an empty field or one that contains a quote, backslash or line break.",
    "binding_user_supplied": "Confirm that this bindings file entry is right; the draft took it from the file, not the document.",
    "binding_unresolved": "Correct the bindings file entry so it names a documented field whose schema accepts it.",
    "setup_undo_proposed": "Confirm that this DELETE removes what the step creates and that the captured field identifies it.",
}

# Fixed word table for no-model status classification; every result is still a proposal.
STATUS_WORDS = {
    **dict.fromkeys(("completed", "succeeded", "success", "done"), "succeeded"),
    **dict.fromkeys(("pending", "queued", "running", "in_progress", "processing", "started"), "pending"),
    **dict.fromkeys(("failed", "error", "cancelled", "canceled", "expired", "timed_out"), "failed"),
}
POLL_INTERVAL_S = 5
MAX_POLLS = 60
POLL_DEADLINE_S = 330
RETRY_AFTER_MAX_S = 60

DOCUMENT_ISSUE_TEXT = {
    "reference_siblings_unsupported": (
        "Reference siblings cannot replace or add schema constraints in this command.",
        "Provide a schema without unsupported reference siblings."),
    "additional_operations_unsupported": (
        "Additional OpenAPI operations cannot be compiled by this command.",
        "Use documented supported HTTP operations or review the unsupported operation flow."),
    "http_method_unsupported": (
        "This HTTP method cannot be compiled by this command.",
        "Use a documented supported HTTP method or review the unsupported operation flow."),
}


class DraftState(str, Enum):
    READY = "ready"
    NEEDS_REVIEW = "needs_review"
    NEEDS_INPUT = "needs_input"
    INVALID = "invalid"


@dataclass(frozen=True)
class Gap:
    field: str
    why: str
    decision: str
    code: str
    kind: str
    blocking: bool
    source: tuple[Source, ...]

    def to_dict(self):
        return {"field": self.field, "why": self.why, "decision": self.decision,
                "code": self.code, "kind": self.kind, "blocking": self.blocking,
                "source": [source.to_dict() for source in self.source]}


@dataclass(frozen=True)
class Binding:
    path: tuple[str, ...]  # property names from the body root; a key under additionalProperties is never a document fact
    pointer: str
    basis: str = "proposal"
    value: str | None = None


@dataclass(frozen=True)
class ReplyPresence:
    pass


@dataclass(frozen=True)
class CarriedBinding:
    parameter: str
    submit_parameter: str
    submit_pointer: str
    poll_pointer: str
    source: Source | None = None


@dataclass(frozen=True)
class PollIdentity:
    field: Binding
    prefix_parts: tuple[str | CarriedBinding, ...]


@dataclass(frozen=True)
class IdBinding:
    name: str
    submit: Binding
    parameter: str
    last_segment: bool = False
    identity: PollIdentity | None = None
    override: UserId | None = None
    fallback: Binding | None = None


@dataclass(frozen=True)
class StatusMap:
    """The asynchronous completion: field.value is the one documented success value."""
    field: Binding
    pending: tuple[str, ...]
    failed: tuple[str, ...]


@dataclass(frozen=True)
class PollChoice:
    operation: str
    ids: tuple[IdBinding, ...]
    carried: tuple[CarriedBinding, ...] = ()


@dataclass(frozen=True)
class OperationSelection:
    operation: str
    prompt: Binding
    reply: Binding | None
    completion: Binding | ReplyPresence | None


@dataclass(frozen=True)
class StepValue:
    """A checked value of a setup step or its undo: where it is sent, its expression and the schema that accepts it."""
    location: str  # body, path or query
    path: tuple[str, ...]  # body path, or the one parameter name
    expression: dict
    leaf: str
    source: Source | None  # None when the draft proposed it


@dataclass(frozen=True)
class StepCapture:
    name: str
    path: tuple[str, ...]
    leaf: str
    source: Source | None  # None when the draft proposed it


@dataclass(frozen=True)
class StepUndo:
    operation: str
    values: tuple[StepValue, ...]
    source: Source | None  # None when the draft proposed it


@dataclass(frozen=True)
class SetupStep:
    """A bindings file step the document accepts, ready to compile into the lifecycle."""
    entry: UserStep
    field: str  # its transport pointer, /transport/lifecycle/<scope>/<index>
    values: tuple[StepValue, ...]
    capture: tuple[StepCapture, ...]
    undo: StepUndo | None
    reads: tuple[str, ...]  # every schema pointer its values, parameters and captures were checked against


@dataclass(frozen=True)
class DraftChoices:
    operation: str | None
    server: str | None
    prompt: Binding | None
    reply: Binding | None
    completion: Binding | ReplyPresence | StatusMap | None
    gaps: tuple[Gap, ...]
    intent: str
    # None means synchronous; otherwise reply and completion refer to the poll operation.
    delivery: PollChoice | None = None
    inputs: DraftInputs | None = None
    values: tuple[UserField, ...] = ()  # bindings file request values that resolved against the document
    steps: tuple[SetupStep, ...] = ()  # bindings file setup steps that resolved against the document


@dataclass(frozen=True)
class DraftArtifacts:
    state: DraftState
    spec: dict | None
    gaps: tuple[Gap, ...]
    provenance: dict

    def validated(self):
        return replace(self, provenance={**self.provenance, "validation": {"offline": "passed"}})

    def with_proposal(self, disclosure):
        return replace(self, provenance={**self.provenance, "model_proposal": disclosure,
                       "selection": {**self.provenance["selection"], "mode": disclosure["effective_mode"]}})


def _gap(catalog, field, code, why, *, pointer="", kind="documentation_gap", blocking=True):
    return Gap(field, why, DECISIONS.get(code, "Provide a supported documented representation for this field before compiling the flow."),
               code, kind, blocking, (catalog.document.source(pointer),))


def _server(url):
    if not isinstance(url, str) or any(char in url for char in "\\{}\r\n\t"):
        raise ValueError("Invalid server URL")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
        raise ValueError("Invalid server URL")
    if parsed.password is not None or parsed.query or parsed.fragment or "%" in parsed.netloc:
        raise ValueError("Invalid server URL")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid server port")
    decoded = unquote(parsed.path)
    if decoded != parsed.path or "//" in decoded or ".." in decoded.split("/"):
        raise ValueError("Invalid server path")
    try:
        host = httpx.URL(url).raw_host.decode("ascii")
        if ":" in host:
            host = "[" + str(ipaddress.IPv6Address(host)) + "]"
        else:
            host = idna.encode(host, std3_rules=True).decode("ascii").lower()
    except (httpx.InvalidURL, UnicodeError, ValueError):
        raise ValueError("Invalid server host") from None
    port = parsed.port
    origin = parsed.scheme.lower() + "://" + host
    if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
        origin += ":" + str(port)
    return origin, origin + parsed.path.rstrip("/")


def validate_server_origin(value: str) -> str:
    origin, server = _server(value)
    if origin != server:
        raise ValueError("Expected a bare HTTP(S) origin")
    return origin


def _object_schema(content):
    if not isinstance(content, dict) or set(content) != {"application/json"}:
        return None
    media = content["application/json"]
    schema = media.get("schema") if isinstance(media, dict) else None
    if not isinstance(schema, dict) or schema.get("type") != "object" or not isinstance(schema.get("properties"), dict):
        return None
    return {**schema, "properties": {name: _nullable(field) for name, field in schema["properties"].items()}}


def _nullable(schema):
    """Read `anyOf` or `oneOf` of one schema and `{type: null}` as that schema, as `_type` reads `type: [T, "null"]` as T."""
    if not isinstance(schema, dict):
        return schema
    keyword = "anyOf" if "anyOf" in schema else "oneOf"
    branches = schema.get(keyword)
    if not isinstance(branches, list) or len(branches) != 2 or {"type": "null"} not in branches:
        return schema
    inner = branches[1 - branches.index({"type": "null"})]
    rest = {key: value for key, value in schema.items() if key != keyword}
    if not isinstance(inner, dict) or rest.keys() & inner.keys():
        return schema
    return {**rest, **inner}


def _type(schema):
    value = schema.get("type") if isinstance(schema, dict) else None
    if isinstance(value, list) and len(value) == 2 and "null" in value:
        return next(item for item in value if item != "null")
    if isinstance(value, list):
        return None
    return value


_METADATA_NAME = re.compile(r"(?i:id|uuid)|.*(?:_(?i:id|uuid|at)|[a-z0-9](?:Id|ID|Uuid|UUID|At))")


def _metadata(name, schema):
    """Identifiers, timestamps and plain-string states describe the call; binding one as the reply or terminal state measures nothing."""
    schema = schema if isinstance(schema, dict) else {}
    return (bool(_METADATA_NAME.fullmatch(name)) or schema.get("format") in {"uuid", "date-time"}
            or name.lower() in {"status", "state"} and not schema.get("enum"))


SCHEMA_KEYWORDS =frozenset({"type", "properties", "required", "items", "enum", "nullable", "additionalProperties",
                             "description", "title", "deprecated", "readOnly", "writeOnly"})
# Value constraints the draft neither encodes nor checks; on a schema it reads they become one review gap.
CONSTRAINT_KEYWORDS = frozenset({"format", "minLength", "maxLength", "pattern", "minimum", "maximum",
                                 "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minItems", "maxItems",
                                 "uniqueItems", "minProperties", "maxProperties"})


def _at(catalog, pointer):
    value = catalog.document.data
    for key in pointer.split("/")[1:]:
        key = key.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def _schema_at(catalog, pointer):
    return _nullable(_at(catalog, pointer))


def _keywords(schema):
    """Unsupported and unchecked keywords of one schema the draft reads, ignoring its subschemas."""
    if not isinstance(schema, dict):
        return ("schema",), ()
    unsupported = set(schema) - SCHEMA_KEYWORDS - CONSTRAINT_KEYWORDS
    unchecked = set(schema) & CONSTRAINT_KEYWORDS
    extra = schema.get("additionalProperties", False)
    if isinstance(extra, dict):
        unchecked.add("additionalProperties")
    elif not isinstance(extra, bool):
        unsupported.add("additionalProperties")
    return tuple(sorted(unsupported)), tuple(sorted(unchecked))


def _unsupported_reads(catalog, read):
    found = {}
    for pointer, schema in read.items():
        unsupported = _keywords(schema)[0]
        if unsupported:
            found[pointer] = unsupported
        media = pointer.removesuffix("/schema")
        if media != pointer and "encoding" in _at(catalog, media):
            found[media] = ("encoding",)
    return found


def _unsupported_gap(catalog, pointer, keywords):
    return _gap(catalog, "/transport/response" if "/responses/" in pointer else "/transport/request", "operation_unsupported",
                "A schema this draft reads uses unsupported keywords: " + ", ".join(keywords) + ".",
                pointer=pointer, kind="unsupported_feature")


def _success(op):
    """An operation's (status, response) 2xx pairs, lowest status first, or None.

    Several 2xx responses count as one result only when they include 202 and document the same body;
    otherwise which response carries the IDs or the answer would be a guess."""
    responses = op.data.get("responses", {})
    statuses = sorted(str(status) for status in responses if re.fullmatch(r"2\d\d", str(status))) if isinstance(responses, dict) else []
    if not statuses or any(not isinstance(responses[status], dict) for status in statuses):
        return None
    content = responses[statuses[0]].get("content")
    if len(statuses) > 1 and ("202" not in statuses or any(responses[status].get("content") != content for status in statuses)):
        return None
    return tuple((status, responses[status]) for status in statuses)


def _body_schema(op):
    """The 2xx JSON object body schema and its pointer under the lowest 2xx status, or (None, "")."""
    success = _success(op)
    schema = _object_schema(success[0][1].get("content")) if success else None
    if schema is None:
        return None, ""
    return schema, op.pointer + "/responses/" + success[0][0] + "/content/application~1json/schema"


def _response_fields(op):
    """The properties of the 2xx JSON object body and their pointer prefix under the lowest 2xx status."""
    schema, pointer = _body_schema(op)
    return (schema["properties"], pointer + "/properties") if schema else (None, "")


def _id_variable(name):
    variable = re.sub(r"[^a-z0-9_]", "_", name.lower())
    # Poll IDs may reuse the run_id context name; transport v2 admits it for delivery.ids.
    if (not NAME_RE.fullmatch(variable) or variable != "run_id" and variable in CONTEXT_KEYS_V2
            or any(word in variable for word in SECRET_WORDS + ("credential",))):
        return None
    return variable


def _id_candidates(op):
    fields, prefix = _response_fields(op)
    return {name: Binding((name,), pointer_child(prefix, name)) for name, schema in (fields or {}).items()
            if isinstance(schema, dict) and _type(schema) in {"string", "integer"} and not schema.get("writeOnly")
            and _id_variable(name)}


def _parameters(op):
    path_level = op.path_data.get("parameters", [])
    operation_level = op.data.get("parameters", [])
    if not isinstance(path_level, list) or not isinstance(operation_level, list):
        return None
    return ([(parameter, pointer_child(op.pointer.rsplit("/", 1)[0] + "/parameters", index)) for index, parameter in enumerate(path_level)]
            + [(parameter, pointer_child(op.pointer + "/parameters", index)) for index, parameter in enumerate(operation_level)])


def _path_parameters(op):
    parameters = _parameters(op)
    if parameters is None or any(not isinstance(parameter, dict) for parameter, _ in parameters):
        return None
    found = [(parameter, pointer) for parameter, pointer in parameters if parameter.get("in") == "path"]
    names = [parameter.get("name") for parameter, _ in found]
    if (any(not isinstance(name, str) for name in names)
            or sorted(names) != sorted(re.findall(r"\{([^{}]+)\}", op.path)) or len(set(names)) != len(names)
            or any(parameter.get("required") is not True or parameter.get("style", "simple") != "simple" or "content" in parameter
                   or _type(parameter.get("schema")) not in {"string", "integer"} for parameter, _ in found)):
        return None
    return tuple((parameter["name"], (pointer, parameter["schema"])) for parameter, pointer in found)


def _poll_parameters(op):
    if (op.method != "GET" or op.path_data.get("servers") or op.data.get("servers") or op.data.get("callbacks")
            or _response_fields(op)[0] is None or [status for status, _ in _success(op)] == ["202"]):
        return None
    return _path_parameters(op) or None


def _pair(parameters, ids, submit, mappings=()):
    paths = dict(_path_parameters(submit) or ())
    response, _ = _response_fields(submit)
    explicit = {entry.parameter: entry for entry in mappings}
    if set(explicit) - {name for name, _ in parameters}:
        return None
    pairs, carried = [], []
    for parameter, (poll_pointer, schema) in parameters:
        selected = explicit.get(parameter)
        source = selected.submit_parameter if selected else parameter
        if selected or source in paths:
            if source not in paths or _type(paths[source][1]) != _type(schema):
                return None
            carried.append(CarriedBinding(parameter, source, paths[source][0], poll_pointer,
                                          selected.source if selected else None))
            continue
        named = [binding for binding in ids.values() if re.fullmatch(r".+(?:_id|[a-z0-9]Id)", binding.path[0])]
        match = ids.get(parameter) or (named[0] if parameter == "id" and len(named) == 1 else None)
        if match is None or _type(response[match.path[0]]) != _type(schema):
            return None
        pairs.append(IdBinding(_id_variable(match.path[0]), match, parameter))
    if not 1 <= len(pairs) <= 4 or len({pair.name for pair in pairs}) != len(pairs):
        return None
    return tuple(pairs), tuple(carried)


def _resource_identity(catalog, poll, pairs, carried, overrides, gaps):
    fields, prefix = _response_fields(poll)
    name = fields.get("name")
    templates = []
    if isinstance(name, dict):
        for text in (name.get("title"), name.get("description")):
            if isinstance(text, str) and re.search(r"(?i)\bFormat:", text):
                matches = re.findall(r"(?i)\bFormat:\s*`?([^\s`]+)", text)
                templates.extend(match.rstrip(".,;`") for match in matches or [""])
    identity = None
    if templates:
        template = templates[0]
        segments = template.split("/")
        path_segments = poll.path.lstrip("/").split("/")
        placeholder = lambda part: re.fullmatch(r"\{[^{}]+\}", part)
        canonical = lambda items: ["{}" if placeholder(part) else part for part in items]
        valid = (len(set(templates)) == 1 and _type(name) == "string" and not name.get("writeOnly")
                 and all(placeholder(part) or re.fullmatch(r"[A-Za-z0-9._~-]+", part) and part not in {".", ".."} for part in segments)
                 and canonical(segments) == canonical(path_segments[-len(segments):]))
        tail = path_segments[-len(segments):]
        target = next((item for item in pairs if "{" + item.parameter + "}" == tail[-1]), None) if valid else None
        known = {"{" + item.parameter + "}": item for item in carried}
        parts, literal = [], ""
        if target:
            for segment, parameter in zip(segments[:-1], tail[:-1]):
                if placeholder(segment):
                    if parameter not in known:
                        valid = False
                        break
                    if literal: parts.append(literal)
                    parts.append(known[parameter]); literal = "/"
                else:
                    literal += segment + "/"
            if literal: parts.append(literal)
        if not valid or target is None or not parts:
            gaps.append(_gap(catalog, "/transport/delivery/ids", "poll_resource_format_unsupported",
                             "The documented resource-name format does not uniquely match the poll path and carried parameters.",
                             pointer=pointer_child(prefix, "name"), kind="unsupported_feature"))
        else:
            identity = (target.name, PollIdentity(Binding(("name",), pointer_child(prefix, "name"), "document_fact"), tuple(parts)))
    supplied = {entry.field: entry for entry in overrides}
    used = {item.submit.path[0] for item in pairs}
    for field in supplied.keys() - used:
        gaps.append(_unresolved("/transport/delivery/ids", supplied[field], "The entry does not name a paired submit response ID."))
    result = []
    for item in pairs:
        override = supplied.get(item.submit.path[0])
        selected = identity[1] if identity and identity[0] == item.name else None
        extract = override.last_segment if override else selected is not None
        if extract and _type(_schema_at(catalog, item.submit.pointer)) != "string":
            gaps.append(_unresolved("/transport/delivery/ids", override, "Last-segment extraction requires a string submit ID.") if override
                        else _gap(catalog, "/transport/delivery/ids", "poll_resource_format_unsupported",
                                  "Resource-name extraction requires a string submit ID.", pointer=item.submit.pointer))
        fallback = fields.get(item.submit.path[0])
        comparable = (_type(fallback) == _type(_schema_at(catalog, item.submit.pointer))
                      and not fallback.get("writeOnly"))
        if selected is None and not comparable:
            gaps.append(_gap(catalog, "/transport/delivery/ids/" + item.name, "poll_identity_unchecked",
                             "The poll response documents no field that verifies this submit ID's identity.",
                             pointer=poll.pointer, blocking=False))
        checked_fallback = (Binding(item.submit.path, pointer_child(prefix, item.submit.path[0]), "document_fact")
                            if selected is None and comparable else None)
        result.append(replace(item, last_segment=extract, identity=selected, override=override, fallback=checked_fallback))
    return tuple(result)


def _input_variable(name):
    return "input_" + re.sub(r"[^a-zA-Z0-9_]", "_", name).lower()


def _id_selector(item):
    selector = {"path": _field_path(item.submit.path)}
    if item.last_segment:
        selector["last_segment"] = True
    if item.identity:
        prefix = {"concat": [{"literal": part} if isinstance(part, str)
                              else {"var": _input_variable(part.submit_parameter)} for part in item.identity.prefix_parts]}
        if item.last_segment:
            selector["expect_prefix"] = prefix
        selector["poll"] = {"path": _field_path(item.identity.field.path), "last_segment": True,
                            "expect_prefix": prefix}
    return selector


def _status_field(op):
    """The poll response's only top-level string enum, the presence of a non-enum state, and the field's pointer prefix."""
    fields, prefix = _response_fields(op)
    enums = [(name, schema) for name, schema in fields.items()
             if isinstance(schema, dict) and _type(schema) == "string" and not schema.get("writeOnly") and not _metadata(name, schema)
             and isinstance(schema.get("enum"), list) and len(schema["enum"]) >= 2 and all(isinstance(value, str) for value in schema["enum"])]
    # A field named status or state is the run state; an unrelated enum beside it must not stand in for it.
    named = {name for name in fields if name.lower() in {"status", "state"}}
    other_state = bool(named) and not any(name in named for name, _ in enums)
    return (enums[0] if len(enums) == 1 and not other_state else None), other_state, prefix


def _classify(values):
    classes = {"succeeded": [], "pending": [], "failed": []}
    for value in values:
        if value.lower() in STATUS_WORDS:
            classes[STATUS_WORDS[value.lower()]].append(value)
    return classes


def _poll_choice(catalog, submit, *, poll_operation, required, gaps, inputs=None):
    """Pair the submit with a documented GET poll. Returns (delivery, reply, completion), or None to stay synchronous."""
    ids = _id_candidates(submit)
    polls = [(op, _poll_parameters(op)) for op in catalog.operations if poll_operation in {None, op.id}]
    polls = [(op, parameters) for op, parameters in polls if parameters]
    paired = [(op, pairing) for op, parameters in polls
              if (pairing := _pair(parameters, ids, submit, inputs.poll.parameters if inputs and inputs.poll else ()))]
    if not paired and not required:
        return None
    candidates = [(op, pairs) for op, pairs in paired if _status_field(op)[0]]
    if not polls:
        gaps.append(_gap(catalog, "/transport/delivery", "async_poll_missing",
                         "The submit response carries no answer and no GET operation can return the job's result.", pointer=submit.pointer))
        return None, None, None
    if not paired:
        if inputs and inputs.poll:
            for entry in inputs.poll.parameters:
                gaps.append(_unresolved("/transport/delivery/request", entry,
                                        "This mapping cannot pair the documented poll with a compatible submit path parameter."))
        gaps.append(_gap(catalog, "/transport/delivery/ids", "poll_id_binding_missing",
                         "No submit response field maps uniquely to every poll path parameter.", pointer=polls[0][0].pointer))
        return None, None, None
    if len(paired) > 1:
        gaps.append(_gap(catalog, "/transport/delivery", "poll_ambiguous", "Several GET operations can poll the submitted job.",
                         pointer=submit.pointer, kind="ambiguous_choice"))
        return None, None, None
    op, (pairs, carried) = candidates[0] if candidates else paired[0]
    pairs = _resource_identity(catalog, op, pairs, carried, inputs.ids if inputs else (), gaps)
    status, other_state, prefix = _status_field(op)
    if status is None:
        gaps.append(_gap(catalog, "/transport/delivery/pending" if other_state else "/transport/outcome",
                         "async_shape_unsupported" if other_state else "completion_missing",
                         "The poll state is not a top-level string enum." if other_state else "The poll response documents no terminal state.",
                         pointer=op.pointer, kind="unsupported_feature" if other_state else "documentation_gap"))
        return PollChoice(op.id, pairs, carried), None, None
    (name, schema) = status
    unwritable = [(field, binding) for field, binding in [*(("/transport/delivery/ids", pair.submit) for pair in pairs),
                                                          ("/transport/outcome", Binding((name,), pointer_child(prefix, name)))]
                  if _field_path(binding.path) is None]
    if unwritable:
        gaps.extend(_gap(catalog, field, "field_path_unwritable", f"No transport path can name the field {json.dumps(binding.path[-1])}.",
                         pointer=binding.pointer, kind="unsupported_feature") for field, binding in unwritable)
        return None, None, None
    if poll_operation is None:
        gaps.append(_gap(catalog, "/transport/delivery", "poll_proposed", "The only matching GET operation was selected as the poll.",
                         pointer=op.pointer, kind="proposal", blocking=False))
    if any(parameter.get("in") != "path" and parameter.get("required") for parameter, _ in _parameters(op)):
        gaps.append(_gap(catalog, "/transport/delivery/request", "async_shape_unsupported",
                         "The poll operation requires parameters other than job identifiers.", pointer=op.pointer, kind="unsupported_feature"))
    classes = _classify(schema["enum"])
    completion = None
    if len(classes["succeeded"]) == 1 and classes["pending"]:
        completion = StatusMap(Binding((name,), pointer_child(prefix, name), value=classes["succeeded"][0]),
                               tuple(classes["pending"]), tuple(classes["failed"]))
    fields, _ = _response_fields(op)
    texts = [field for field, value in fields.items()
             if field.lower() in {"answer", "reply", "output", "result"} and _type(value) in {"string", "object"}
             and not value.get("writeOnly") and not _metadata(field, value)]
    reply = Binding((texts[0],), pointer_child(prefix, texts[0])) if len(texts) == 1 else None
    return PollChoice(op.id, pairs, carried), reply, completion


def choose_without_model(catalog: OperationCatalog, *, operation=None, server_origin=None, poll_operation=None,
                         intent="Ask an agent a question, optionally with third-party material.", inputs=None) -> DraftChoices:
    return _choose(catalog, operation=operation, server_origin=server_origin, poll_operation=poll_operation, intent=intent,
                   inputs=inputs)


def choices_from_selection(catalog: OperationCatalog, selection: OperationSelection, *, operation=None,
                           server_origin=None, poll_operation=None,
                           intent="Ask an agent a question, optionally with third-party material.", inputs=None) -> DraftChoices:
    if operation is not None and operation != selection.operation:
        raise ValueError("Model operation conflicts with the explicit selection")
    return _choose(catalog, operation=operation, server_origin=server_origin, poll_operation=poll_operation,
                   intent=intent, selection=selection, inputs=inputs)


def _body_field(path):
    """The transport pointer of a request body value at path."""
    return "/transport/request/body/json/" + "/object/".join(pointer_child("", name)[1:] for name in path)


def _user_record(catalog, pointer, entry):
    """Provenance of a value the bindings file chose: the documented field and the file entry."""
    record = {"source": [catalog.document.source(pointer).to_dict(), entry.source.to_dict()], "basis": "user_selection"}
    return {**record, "origin": entry.origin} if entry.origin is not None else record


def _unresolved(field, entry, why):
    return Gap(field, why, DECISIONS["binding_unresolved"], "binding_unresolved", "documentation_gap", True, (entry.source,))


def _supplied(catalog, field, pointer, entry, why):
    return Gap(field, why, DECISIONS["binding_user_supplied"], "binding_user_supplied", "documentation_gap", False,
               (catalog.document.source(pointer), entry.source))


def _user_binding(catalog, operation, entry, role, kinds, proposed, gaps):
    """The binding a file entry names for role, or None after a blocking gap that says why the document rejects it."""
    field = "/transport/request/body" if role == "prompt" else "/transport/response/text"
    chain, why = _resolve(catalog, operation, entry.path, role, kinds)
    if why is None and role == "reply" and _schema_at(catalog, chain[-1]).get("enum"):
        # The document's own reply proposals predate this rule; a fixed value set never carries the agent's answer.
        why = "A documented value set is a fixed value or a state, never the agent's answer."
    if why:
        gaps.append(_unresolved(field, entry, why))
        return None
    if proposed is None or proposed.path != entry.path:
        gaps.append(_supplied(catalog, field, chain[-1], entry, f"The bindings file names this {role} field; the document does not."))
    return Binding(entry.path, chain[-1], basis="user_selection")


LITERAL_KINDS = {str: ("string",), bool: ("boolean",), int: ("integer", "number"), float: ("number",)}


def _user_value(catalog, operation, entry, prompt, gaps):
    """Whether a file value fits the documented field at its path; a misfit adds a blocking gap."""
    literal = entry.value.get("literal")
    chain, why = _resolve(catalog, operation, entry.path, "value", LITERAL_KINDS[type(literal)] if "literal" in entry.value else ("string",))
    documented = _schema_at(catalog, chain[-1]).get("enum") if chain else None
    if why is None and prompt is not None and entry.path == prompt.path:
        why = "The prompt is sent at this path."
    elif why is None and documented is not None and ("env" in entry.value or literal not in documented):
        why = "The field documents a value set; send one of them as a literal: " + ", ".join(map(json.dumps, documented)) + "."
    if why:
        gaps.append(_unresolved(_body_field(entry.path), entry, why))
        return False
    gaps.append(_supplied(catalog, _body_field(entry.path), chain[-1], entry, "The bindings file supplies this request value; the document does not."))
    return True


STEP_LITERAL_KINDS = {**LITERAL_KINDS, list: ("array",), dict: ("object",)}
GENERATED_KINDS = {"uuid4": ("string",), "now_iso8601": ("string",), "now_unix_ms": ("integer", "number")}
ID_NAME = re.compile(r"(?i:id)|.+(?:_id|[a-z0-9]Id)")


def _leaf(catalog, pointer, kinds):
    """pointer, or the one branch of a union there whose type comes first in kinds; None when no single branch does."""
    schema = _schema_at(catalog, pointer)
    keyword = next((key for key in ("anyOf", "oneOf") if isinstance(schema, dict) and isinstance(schema.get(key), list)), None)
    if keyword is None:
        return pointer
    for kind in kinds:
        found = [index for index, branch in enumerate(schema[keyword]) if _type(_nullable(branch)) == kind]
        if found:
            return f"{pointer}/{keyword}/{found[0]}" if len(found) == 1 else None
    return None


def _value_kinds(expression, captured):
    """The JSON types a step expression sends."""
    kind, item = next(iter(expression.items()))
    if kind == "literal":
        return STEP_LITERAL_KINDS[type(item)]
    if kind == "generate":
        return GENERATED_KINDS[item]
    if kind == "var":
        return captured[item]
    return ("string",)


def _capture_kinds(catalog, capture):
    return ("string",) if _type(_schema_at(catalog, capture.leaf)) == "string" else ("integer", "number")


def _material(expression):
    return expression.get("context") == "material" or any(_material(part) for part in expression.get("concat", ()))


def _variables(expression):
    return ({expression["var"]} if "var" in expression else set()).union(*map(_variables, expression.get("concat", ())))


def _value_set(catalog, leaf, expression):
    documented = _schema_at(catalog, leaf).get("enum")
    if documented is not None and ("literal" not in expression or expression["literal"] not in documented):
        return "The field documents a value set; send one of them as a literal: " + ", ".join(map(json.dumps, documented)) + "."
    return None


def _auth_or_none(catalog, operation):
    try:
        return _auth(catalog, operation)
    except (ValueError, TypeError, AttributeError):
        return None


def _sendable(catalog, operation, auth, methods):
    """Why the draft cannot send operation beside the ask, or None."""
    if operation.method not in methods:
        return ("An undo must be a documented DELETE; anything else would report cleanup it never did." if methods == {"DELETE"}
                else "A setup step must create or change something with POST, PUT or PATCH.")
    if operation.path_data.get("servers") or operation.data.get("servers") or operation.data.get("callbacks"):
        return "The operation overrides the server or declares callbacks, which the draft does not follow."
    if _auth_or_none(catalog, operation) != auth:
        return "The operation's authentication differs from the ask's."
    if _unsafe_path(operation.path) or _parameters(operation) is None or _success(operation) is None:
        return "The operation's path, parameters or successful response cannot be compiled."
    request = operation.data.get("requestBody")
    if isinstance(request, dict) and request.get("required") and (operation.method == "DELETE" or _root(operation, "step") is None):
        return "The operation requires a request body this draft cannot send."
    return None


def _parameter_value(catalog, operation, entry, captured):
    """A checked path or query parameter value, or why the document rejects it."""
    name = entry.path[0]
    found = [(parameter, pointer) for parameter, pointer in _parameters(operation)
             if isinstance(parameter, dict) and parameter.get("name") == name and parameter.get("in") in {"path", "query"}]
    if len(found) != 1 or "content" in found[0][0] or "schema" not in found[0][0]:
        return None, "No path or query parameter of this name is documented with a schema."
    (parameter, pointer), kinds = found[0], _value_kinds(entry.value, captured)
    if parameter["in"] == "path" and set(entry.value) - {"var", "env"}:
        return None, "A path parameter takes a captured value or an environment value."
    leaf = _leaf(catalog, pointer + "/schema", kinds)
    if leaf is None or _type(_schema_at(catalog, leaf)) not in set(kinds) & {"string", "integer", "number", "boolean"}:
        return None, "The parameter's documented type is not " + " or ".join(kinds) + "."
    why = _value_set(catalog, leaf, entry.value)
    return (None, why) if why else (StepValue(parameter["in"], (name,), entry.value, leaf, entry.source), None)


def _unbound(names):
    return ", ".join(map(json.dumps, names)) + "."


def _missing_parameters(operation, given):
    return [parameter.get("name") for parameter, _ in _parameters(operation)
            if isinstance(parameter, dict) and (parameter.get("required") or parameter.get("in") == "path") and parameter.get("name") not in given]


def _unbound_required(catalog, root, paths):
    """Required fields of the body, and of each object a bound path passes through, that no path binds."""
    sent = {path[:end] for path in paths for end in range(1, len(path) + 1)}
    names = [(name,) for name in _schema_at(catalog, root).get("required") or () if isinstance(name, str)]
    for path in paths:
        chain = _walk(catalog, root, path)
        for depth in range(1, len(path)):
            names += [path[:depth] + (name,) for name in _schema_at(catalog, chain[depth]).get("required") or () if isinstance(name, str)]
    return sorted({".".join(name) for name in names if name not in sent})


def _parameter_values(catalog, operation, entries, captured, block, source):
    values = []
    for entry in entries:
        value, why = _parameter_value(catalog, operation, entry, captured)
        if why:
            block(entry.source, why)
        else:
            values.append(value)
    missing = _missing_parameters(operation, {entry.path[0] for entry in entries})
    if missing:
        block(source, "These required parameters have no value: " + _unbound(missing))
    return tuple(values)


def _proposed_undo(catalog, operation, entry, auth, captures, captured):
    """The only DELETE on the created resource's own path, fed by the step's one capture, or None when the document does not pin one."""
    deletes = [(other, match.group(1)) for other in catalog.operations if other.method == "DELETE"
               and (match := re.fullmatch(re.escape(operation.path) + r"/\{([^{}/]+)\}", other.path))]
    if len(deletes) != 1 or _sendable(catalog, deletes[0][0], auth, {"DELETE"}):
        return None
    (target, parameter), = deletes
    if entry.capture is None:
        schema = _body_schema(operation)[0] or {}
        names = [name for name in schema.get("required") or () if isinstance(name, str) and ID_NAME.fullmatch(name)]
        if len(names) != 1:
            return None
        chain, why = _resolve(catalog, operation, (names[0],), "capture", ("string", "integer"))
        if why or _id_variable(names[0]) is None:
            return None
        captures = (StepCapture(f"{entry.id}_{_id_variable(names[0])}", (names[0],), chain[-1], None),)
        captured = {**captured, captures[0].name: _capture_kinds(catalog, captures[0])}
    if len(captures) != 1:
        return None
    blocked = []
    values = _parameter_values(catalog, target, [UserField((parameter,), None, None, {"var": captures[0].name})], captured,
                               lambda source, why: blocked.append(why), None)
    return None if blocked else (StepUndo(target.id, values, None), captures)


def _setup_steps(catalog, invoke, inputs, gaps):
    """Check each bindings file step against the document; a step that fails adds blocking gaps and is left out."""
    auth = _auth_or_none(catalog, invoke)
    operations = {op.id: op for op in catalog.operations}
    captured, steps, counts = {}, [], {"run": 0, "attempt": 0}
    for entry in inputs.steps:
        field = f"/transport/lifecycle/{entry.scope}/{counts[entry.scope]}"
        counts[entry.scope] += 1
        found = []
        own_names = {capture.name for capture in entry.capture or ()}
        reads_from = set().union(*(_variables(item.value) for item in (*entry.values, *entry.parameters)),
                                 *(_variables(item.value) - own_names for item in (entry.undo.parameters if entry.undo else ())))
        if not reads_from <= set(captured):
            continue  # it reads a capture of an earlier step that already blocks the draft

        def block(source, why):
            found.append(Gap(field, why, DECISIONS["binding_unresolved"], "binding_unresolved", "documentation_gap", True, (source,)))

        op = operations.get(entry.operation)
        why = "The operation is not documented." if op is None else _sendable(catalog, op, auth, {"POST", "PUT", "PATCH"})
        if why:
            block(Source(entry.source.file, entry.source.pointer + "/operation"), why)
            gaps.extend(found)
            continue
        values, reads = [], set()
        for value in entry.values:
            chain, why = _resolve(catalog, op, value.path, "step", _value_kinds(value.value, captured))
            why = why or _value_set(catalog, chain[-1], value.value)
            if why:
                block(value.source, why)
                continue
            values.append(StepValue("body", value.path, value.value, chain[-1], value.source))
            reads.update(chain)
        root = _root(op, "step")
        missing = _unbound_required(catalog, root, [value.path for value in values]) if root and len(values) == len(entry.values) else []
        if missing:
            block(entry.source, "These required request fields have no value: " + _unbound(missing))
        values += _parameter_values(catalog, op, entry.parameters, captured, block, entry.source)
        if entry.scope == "run" and any(_material(value.value) for value in (*entry.values, *entry.parameters)):
            block(entry.source, "Material changes with every ask, so only an attempt step can send it.")
        captures = []
        for capture in entry.capture or ():
            chain, why = _resolve(catalog, op, capture.path, "capture", ("string", "integer"))
            if why:
                block(capture.source, why)
                continue
            captures.append(StepCapture(capture.name, capture.path, chain[-1], capture.source))
        own = {**captured, **{capture.name: _capture_kinds(catalog, capture) for capture in captures}}
        undo = None
        if entry.undo is not None and not any(gap.blocking for gap in found):
            target = operations.get(entry.undo.operation)
            why = "The operation is not documented." if target is None else _sendable(catalog, target, auth, {"DELETE"})
            if why:
                block(Source(entry.undo.source.file, entry.undo.source.pointer + "/operation"), why)
            else:
                undo = StepUndo(target.id, _parameter_values(catalog, target, entry.undo.parameters, own, block, entry.undo.source), entry.undo.source)
        elif entry.undo is None and not any(gap.blocking for gap in found):
            proposed = _proposed_undo(catalog, op, entry, auth, tuple(captures), own)
            if proposed:
                undo, proposal = proposed
                captures = list(proposal)
        gaps.extend(found)
        if any(gap.blocking for gap in found):
            continue
        captured.update({capture.name: _capture_kinds(catalog, capture) for capture in captures})
        for capture in captures:
            reads.update(_walk(catalog, _root(op, "capture"), capture.path))
        for value in undo.values if undo else ():
            reads.add(value.leaf)
        reads.update(value.leaf for value in values if value.location != "body")
        gaps.append(Gap(field, "The bindings file adds this setup step; the document does not say the ask needs it.",
                        DECISIONS["binding_user_supplied"], "binding_user_supplied", "documentation_gap", False,
                        (catalog.document.source(op.pointer), entry.source)))
        if undo is None:
            gaps.append(_gap(catalog, field + "/undo", "cleanup_mapping_missing",
                             f"Setup step {json.dumps(entry.id)} has no undo the document can express, so what it creates is left behind.",
                             pointer=op.pointer, blocking=False))
        elif undo.source is None:
            gaps.append(Gap(field + "/undo", f"The draft pairs this step with the only DELETE on its created path, fed by the response field "
                            f"{json.dumps('.'.join(captures[0].path))}.", DECISIONS["setup_undo_proposed"], "setup_undo_proposed", "proposal", False,
                            (catalog.document.source(operations[undo.operation].pointer), catalog.document.source(captures[0].leaf))))
        steps.append(SetupStep(entry, field, tuple(values), tuple(captures), undo, tuple(sorted(reads))))
    return tuple(steps)


def _choose(catalog, *, operation, server_origin, intent, poll_operation=None, selection=None, inputs=None):
    doc = catalog.document
    gaps = []
    chosen = None
    selected_id = operation or (selection.operation if selection else None)
    # A GET cannot be the invoke; with another method present it is a poll, so it never makes the pick ambiguous.
    candidates = ([op for op in catalog.operations if op.id == selected_id] if selected_id else
                  [op for op in catalog.operations if op.method != "GET"] or list(catalog.operations))
    if len(candidates) == 1:
        chosen = candidates[0]
        if operation is None:
            gaps.append(_gap(catalog, "/transport/request", "invoke_proposed",
                             "The only operation was selected; its agent role remains a proposal.",
                             pointer=chosen.pointer, kind="proposal", blocking=False))
    else:
        gaps.append(_gap(catalog, "/transport/request", "operation_ambiguous",
                         "No unique documented invoke operation is selected.", kind="ambiguous_choice"))
    servers = doc.data.get("servers", [])
    server = None
    if not isinstance(servers, list) or not servers:
        gaps.append(_gap(catalog, "/transport/request/url", "server_missing", "No server is declared."))
    else:
        valid = []
        try:
            for entry in servers:
                if not isinstance(entry, dict) or "variables" in entry:
                    raise ValueError("Unresolved server variables")
                valid.append(_server(entry.get("url")))
            selected = [item for item in valid if item[0] == _server(server_origin)[0]] if server_origin else valid
            if server_origin and _server(server_origin)[0] != _server(server_origin)[1]:
                raise ValueError("Override must be an origin")
            if len(selected) == 1:
                server = selected[0][1]
            else:
                gaps.append(_gap(catalog, "/transport/request/url", "server_ambiguous",
                                 "Choose one declared server origin.", kind="ambiguous_choice"))
        except (ValueError, TypeError):
            gaps.append(_gap(catalog, "/transport/request/url", "server_invalid",
                             "A server URL or origin override is unsafe or unresolved.", kind="unsupported_feature"))
    if inputs and inputs.poll:
        if poll_operation is not None and poll_operation != inputs.poll.operation:
            gaps.append(_unresolved("/transport/delivery", inputs.poll, "The file poll operation conflicts with --poll-operation."))
        elif inputs.poll.operation not in {op.id for op in catalog.operations}:
            gaps.append(_unresolved("/transport/delivery", inputs.poll, "The file poll operation is not documented."))
        else:
            poll_operation = inputs.poll.operation
    prompt = reply = completion = delivery = None
    values = steps = ()
    for issue in doc.issues:
        if issue.code != "reference_cycle":
            why, decision = DOCUMENT_ISSUE_TEXT[issue.code]
            gaps.append(Gap("/transport", why, decision,
                            issue.code, "unsupported_feature", True, (issue.source,)))
    if doc.data.get("webhooks"):
        gaps.append(_gap(catalog, "/transport", "webhooks_unsupported", "Webhook flows are not compiled.", kind="unsupported_feature"))
    if chosen:
        op = chosen.data
        pointer = chosen.pointer
        overrides = chosen.path_data.get("servers", []) or op.get("servers", [])
        if overrides:
            gaps.append(_gap(catalog, "/transport/request/url", "server_override_unsupported",
                             "Path or operation server overrides require an explicit flow decision.",
                             pointer=pointer, kind="unsupported_feature"))
        if chosen.method != "POST" or op.get("callbacks"):
            gaps.append(_gap(catalog, "/transport/request", "operation_unsupported",
                             "This skeleton supports JSON POST invoke operations.",
                             pointer=pointer, kind="unsupported_feature"))
        request = op.get("requestBody", {})
        request_schema = _object_schema(request.get("content")) if isinstance(request, dict) else None
        request_pointer = pointer + "/requestBody/content/application~1json/schema/properties"
        if request_schema:
            fields = [(name, schema) for name, schema in request_schema["properties"].items()
                      if name.lower() in {"question", "prompt", "message", "goal"} and _type(schema) == "string"
                      and not schema.get("enum") and not schema.get("readOnly")]
            if len(fields) == 1:
                name, _ = fields[0]
                prompt = Binding((name,), pointer_child(request_pointer, name))
        if selection is not None:
            prompt = selection.prompt
        if inputs and inputs.prompt:
            prompt = _user_binding(catalog, chosen, inputs.prompt, "prompt", ("string",), prompt, gaps)
        values = tuple(entry for entry in (inputs.values if inputs else ()) if _user_value(catalog, chosen, entry, prompt, gaps))
        steps = _setup_steps(catalog, chosen, inputs, gaps) if inputs else ()
        if prompt is None and not (inputs and inputs.prompt):
            gaps.append(_gap(catalog, "/transport/request/body", "prompt_binding_missing",
                             "No unique prompt field can be proposed from the JSON schema.", pointer=pointer))
        responses = op.get("responses", {})
        response_schema = None
        response_pointer = ""
        if not isinstance(responses, dict):
            gaps.append(_gap(catalog, "/transport/response", "response_invalid", "Responses must be an object.", pointer=pointer))
        else:
            successes = [(str(status), response) for status, response in responses.items()
                         if re.fullmatch(r"2\d\d", str(status))]
            if len(successes) > 1 and any(status == "202" for status, _ in successes) and _success(chosen) is None:
                gaps.append(_gap(catalog, "/transport/delivery", "async_shape_unsupported",
                                 "Several successful responses including 202 document different bodies.",
                                 pointer=pointer, kind="unsupported_feature"))
            if any(isinstance(response, dict) and response.get("links") for _, response in successes):
                gaps.append(_gap(catalog, "/transport/delivery", "links_unsupported",
                                 "Response links need an explicit flow choice.", pointer=pointer, kind="unsupported_feature"))
            if len(successes) == 1 and isinstance(successes[0][1], dict):
                status, response = successes[0]
                response_schema = _object_schema(response.get("content"))
                response_pointer = pointer + "/responses/" + status + "/content/application~1json/schema/properties"
        if response_schema:
            texts = [(name, schema) for name, schema in response_schema["properties"].items()
                     if name.lower() in {"answer", "reply", "output", "result"} and _type(schema) == "string" and not schema.get("writeOnly")
                     and not _metadata(name, schema)]
            states = [(name, schema) for name, schema in response_schema["properties"].items()
                      if name.lower() in {"status", "state"} and isinstance(schema, dict) and not _metadata(name, schema)
                      and _type(schema) == "string"
                      and not schema.get("writeOnly")
                      and schema.get("enum") in [["completed"], ["COMPLETED"], ["succeeded"], ["success"]]]
            if len(texts) == 1:
                reply = Binding((texts[0][0],), pointer_child(response_pointer, texts[0][0]))
            if len(states) == 1:
                completion = Binding((states[0][0],), pointer_child(response_pointer, states[0][0]), value=states[0][1]["enum"][0])
            elif reply is not None:
                completion = ReplyPresence()
        if selection is not None:
            reply, completion = selection.reply, selection.completion
        success = _success(chosen)
        required = success is not None and any(status == "202" for status, _ in success) or poll_operation is not None
        # A documented answer keeps the call synchronous unless the API or the user says otherwise.
        polled = (_poll_choice(catalog, chosen, poll_operation=poll_operation, required=required, gaps=gaps, inputs=inputs)
                  if success and (reply is None or required) else None)
        if polled is not None:
            delivery, reply, completion = polled
            pointer = next((op.pointer for op in catalog.operations if delivery and op.id == delivery.operation), pointer)
        if polled is None or delivery is not None:
            if inputs and inputs.reply:
                result = next(op for op in catalog.operations if op.id == delivery.operation) if delivery else chosen
                reply = _user_binding(catalog, result, inputs.reply, "reply", ("string", "object") if delivery else ("string",), reply, gaps)
                if delivery is None and not isinstance(completion, Binding):
                    completion = ReplyPresence() if reply else None
            for binding, field, missing in ((reply, "/transport/response/text", "reply_binding_missing"),
                                             (completion, "/transport/outcome", "completion_missing")):
                if (binding is None and not (missing == "reply_binding_missing" and inputs and inputs.reply)
                        and not (missing == "completion_missing" and any(gap.blocking and gap.code in {"async_shape_unsupported", "completion_missing"} for gap in gaps))):
                    gaps.append(_gap(catalog, field, missing, "No unique documented reply or terminal state can be proposed.", pointer=pointer))
        elif inputs and inputs.reply:
            gaps.append(_unresolved("/transport/response/text", inputs.reply,
                                    "No poll operation could be paired with the submit, so the reply path cannot be checked against its response."))
    if inputs and inputs.ids and delivery is None:
        gaps.extend(_unresolved("/transport/delivery/ids", entry, "No paired poll can use this submit ID extraction entry.") for entry in inputs.ids)
    return DraftChoices(chosen.id if chosen else None, server, prompt, reply, completion, tuple(gaps), intent, delivery,
                        inputs, values, steps)


def _auth(catalog, operation):
    security = operation.data.get("security", catalog.document.data.get("security", []))
    if security == []:
        return {"kind": "none"}
    if not isinstance(security, list) or len(security) != 1 or not isinstance(security[0], dict):
        raise ValueError("Authentication alternatives are unsupported")
    requirement = security[0]
    if not requirement:
        return {"kind": "none"}
    if len(requirement) != 1 or any(not isinstance(scopes, list) or scopes for scopes in requirement.values()):
        raise ValueError("Composite authentication is unsupported")
    schemes = catalog.document.data.get("components", {}).get("securitySchemes", {})
    scheme = schemes.get(next(iter(requirement))) if isinstance(schemes, dict) else None
    if not isinstance(scheme, dict):
        raise ValueError("Authentication scheme is missing")
    secret = {"source": "env", "name": "TARGET_API_KEY"}
    if scheme.get("type") == "http" and scheme.get("scheme", "").lower() == "bearer":
        return {"kind": "bearer", "secret": secret}
    if scheme.get("type") == "apiKey" and scheme.get("in") == "header" and isinstance(scheme.get("name"), str):
        auth = {"kind": "headers", "headers": [{"name": scheme["name"], "secret": secret}]}
        AuthSpec.from_dict(auth)
        return auth
    raise ValueError("Authentication scheme is unsupported")


def _field_path(path):
    """The transport path that reads the field at `path`, or None when no transport path can name it.

    A reserved word such as `where` fails the dot form and falls back to the bracket form."""
    dotted = ["$" + "".join("." + name for name in path)] if all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in path) else []
    for candidate in [*dotted, "$" + "".join("['" + name + "']" for name in path)]:
        try:
            return transport_path(candidate)
        except ValueError:
            pass
    return None


def _success_when(catalog, op, primary, field, gaps):
    """The success predicate on op's 2xx body: the success signal plus every documented required field.

    Required fields the rule cannot check go into one non-blocking review gap that names them.
    Returns the predicate and the `required` pointer it read, or None after adding a review gap when no list is usable."""
    schema, pointer = _body_schema(op)
    required = schema.get("required")
    if not isinstance(required, list) or not required or not all(isinstance(name, str) for name in required):
        gaps.append(_gap(catalog, field, "success_conditions_minimal",
                         "The response schema documents no required fields, so success checks only the success signal and the reply.",
                         pointer=pointer, blocking=False))
        return primary, None
    names = [name for name in dict.fromkeys(required) if name in schema["properties"] and _field_path((name,)) != primary["path"]]
    # `all` holds the signal plus 31 checks.
    checked = [name for name in names if _field_path((name,))]
    groups = (([name for name in names if name not in checked], "no rule path can name them"),
              (checked[31:], "a rule holds at most 31 field checks"))
    unchecked = [name for group, _ in groups for name in group]
    if unchecked:
        why = "; ".join(f"{', '.join(map(json.dumps, group))} ({reason})" for group, reason in groups if group)
        gaps.append(Gap(field, f"Success does not check these required fields: {why}.", DECISIONS["required_fields_unchecked"],
                        "required_fields_unchecked", "documentation_gap", False,
                        tuple(catalog.document.source(f"{pointer}/required/{required.index(name)}") for name in unchecked)))
    present = [{"path": _field_path((name,)), "exists": True} for name in checked[:31]]
    return ({"all": [primary, *present]} if present else primary), pointer + "/required"


def _status_rules(catalog, op, status, statuses, field, gaps):
    """Success and failure rules for a status map read on op's 2xx body.

    202 means accepted and not finished (RFC 9110, 15.3.3), so it never matches success; a documented failure on any 2xx ends the run."""
    when, required = _success_when(catalog, op, {"path": _field_path(status.field.path), "equals": status.field.value}, field, gaps)
    finished = [code for code in statuses if code != 202]
    rules = [{"id": "completed", "priority": 10, "http_status": finished, "when": when, "outcome": "succeeded"}] if finished else []
    if status.failed:
        rules.append({"id": "failed", "priority": 5, "http_status": statuses,
                      "when": {"path": _field_path(status.field.path), "one_of": list(status.failed)}, "outcome": "target_error"})
    return rules, required


REQUEST_ROLES = frozenset({"prompt", "value", "step"})


def _root(operation, role):
    """The JSON object body schema a role's path starts from: the request body for the prompt, else the 2xx body."""
    if role not in REQUEST_ROLES:
        return _body_schema(operation)[1] or None
    request = operation.data.get("requestBody")
    content = request.get("content") if isinstance(request, dict) else None
    return operation.pointer + "/requestBody/content/application~1json/schema" if _object_schema(content) else None


def _walk(catalog, root, path):
    """The schema pointers from root to the field at path, or None when the path leaves the documented objects.

    Each step descends an object's `properties`, or a schema-valued `additionalProperties` for a key the document
    does not name. Arrays, untyped schemas and unexpanded reference-cycle stubs end the walk before their children."""
    chain = [root]
    for key in path:
        raw = _at(catalog, chain[-1])
        schema = _nullable(raw)
        if _type(schema) != "object":
            return None
        base = chain[-1]
        if schema is not raw:
            keyword = "anyOf" if "anyOf" in raw else "oneOf"
            base += f"/{keyword}/{1 - raw[keyword].index({'type': 'null'})}"
        properties, extra = schema.get("properties"), schema.get("additionalProperties")
        if isinstance(properties, dict) and key in properties:
            chain.append(pointer_child(base + "/properties", key))
        elif isinstance(extra, dict):
            chain.append(base + "/additionalProperties")
        else:
            return None
    return tuple(chain)


def _resolve(catalog, operation, path, role, kinds=("string",)):
    """The schema pointers to the field at path for role, and why it cannot carry that role (None when it can).

    The pointers are None when the path names no documented field a transport path can reach."""
    root = _root(operation, role)
    chain = _walk(catalog, root, path) if root else None
    if chain is None or _field_path(path) is None:
        return None, "The path does not name a documented field of the " + ("request" if role in REQUEST_ROLES else "response") + " body."
    if role == "step":
        chain = chain[:-1] + (_leaf(catalog, chain[-1], kinds) or chain[-1],)
    schema = _schema_at(catalog, chain[-1])
    if _type(schema) not in kinds:
        return chain, "The field's documented type is not " + " or ".join(kinds) + "."
    if role == "prompt" and (schema.get("readOnly") or schema.get("enum")):
        return chain, "A read-only field or a documented value set cannot carry the question."
    if role in {"value", "step"} and schema.get("readOnly"):
        return chain, "A read-only field is never sent."
    if role not in REQUEST_ROLES and schema.get("writeOnly"):
        return chain, "A write-only field is never returned."
    if role == "reply" and _metadata(path[-1], schema):
        return chain, "An identifier, timestamp or plain state field describes the call; binding it as the reply measures nothing."
    return chain, None


def _binding_schema(catalog, operation, binding, role, kinds=("string",)):
    chain, why = _resolve(catalog, operation, binding.path, role, kinds)
    if chain is None or chain[-1] != binding.pointer or binding.basis not in {"proposal", "document_fact", "user_selection"}:
        raise ValueError("Choice references an unknown or unsupported operation field")
    if why:
        raise ValueError("Choice field has an incompatible schema")
    value = _schema_at(catalog, binding.pointer)
    if role == "completion" and (binding.value is None or binding.value not in value.get("enum", [])):
        raise ValueError("Choice terminal value is not documented")
    return value


def _binding_reads(catalog, operation, binding, role):
    """Every schema on the walk to a bound field: the body, each object it passes and the field itself."""
    return {pointer: _schema_at(catalog, pointer) for pointer in _walk(catalog, _root(operation, role), binding.path)}


def _poll_target(catalog, operation, choices):
    """Check the poll choice against the document; return the operation whose response holds the result."""
    delivery = choices.delivery
    if delivery is None:
        return operation, {}
    if isinstance(choices.completion, (Binding, ReplyPresence)):
        raise ValueError("A poll draft completes only through a status map")
    poll = next((op for op in catalog.operations if op.id == delivery.operation), None)
    parameters = dict(_poll_parameters(poll) or ()) if poll else {}
    if not parameters or sorted(item.parameter for item in (*delivery.ids, *delivery.carried)) != sorted(parameters):
        raise ValueError("Poll choice references an unknown or unsupported operation")
    for item in delivery.ids:
        _binding_schema(catalog, operation, item.submit, "id", kinds=("string", "integer"))
        if item.name != _id_variable(item.submit.path[0]):
            raise ValueError("Poll ID variable does not match its submit field")
    submit_parameters = dict(_path_parameters(operation) or ())
    for item in delivery.carried:
        if (item.submit_parameter not in submit_parameters
                or submit_parameters[item.submit_parameter][0] != item.submit_pointer
                or parameters[item.parameter][0] != item.poll_pointer
                or _type(submit_parameters[item.submit_parameter][1]) != _type(parameters[item.parameter][1])):
            raise ValueError("Carried poll parameter does not match a submit path parameter")
    return poll, parameters


def _cycle_gaps(catalog, read, operations):
    """One blocking row for reference cycles whose stub is a schema the draft sends or reads, one review row for the rest.

    Large vendor documents serialize dozens of cycles, so each row lists every source. A stub below a read schema stays
    unread: `_keywords` ignores subschemas and an object reply is cast as opaque JSON."""
    touched = set(read)
    for op in operations:
        bodies = [op.pointer + "/requestBody/content/application~1json/schema",
                  *(op.pointer + "/responses/" + status + "/content/application~1json/schema" for status, _ in _success(op) or ())]
        for body in (body for body in bodies if body in catalog.document.sources):
            touched.add(body)
            schema = _at(catalog, body)
            properties, required = (schema.get("properties"), schema.get("required")) if isinstance(schema, dict) else (None, None)
            if isinstance(properties, dict) and isinstance(required, list):
                touched.update(pointer_child(body + "/properties", name) for name in properties if name in required)
    cycles = [issue for issue in catalog.document.issues if issue.code == "reference_cycle"]
    blocked = {issue.source for issue in cycles if issue.at in touched}
    other = {issue.source for issue in cycles} - blocked
    gaps = []
    if blocked:
        why = ("1 reference cycle lies in a schema" if len(blocked) == 1 else f"{len(blocked)} reference cycles lie in schemas") + " this draft sends or reads."
        gaps.append(Gap("/transport", why, DECISIONS["reference_cycle"], "reference_cycle", "unsupported_feature", True,
                        tuple(sorted(blocked, key=lambda source: (source.file, source.pointer)))))
    if other:
        why = (("1 reference cycle lies" if len(other) == 1 else f"{len(other)} reference cycles lie")
               + " outside the schemas this draft sends or reads and " + ("is" if len(other) == 1 else "are") + " not expanded.")
        gaps.append(Gap("/transport", why, "Confirm that the draft never needs these cyclic schemas.", "reference_cycle",
                        "unsupported_feature", False, tuple(sorted(other, key=lambda source: (source.file, source.pointer)))))
    return gaps


def _nest(entries):
    """A transport JSON body from (path, expression) pairs, with one `object` expression per shared parent."""
    body = {}
    for path, expression in entries:
        node = body
        for key in path[:-1]:
            node = node.setdefault(key, {"object": {}})["object"]
        node[path[-1]] = expression
    return body


def _step_records(catalog, step):
    """Provenance of a setup step, its captures and its undo, each from the document and the file entry that chose it."""
    document = catalog.document.source
    operations = {op.id: op for op in catalog.operations}
    record = {"source": [document(operations[step.entry.operation].pointer).to_dict(), step.entry.source.to_dict(),
                         *(document(value.leaf).to_dict() for value in step.values)], "basis": "user_selection"}
    records = {step.field: {**record, "origin": step.entry.origin} if step.entry.origin is not None else record}
    for capture in step.capture:
        records[f"{step.field}/capture/{capture.name}"] = {
            "source": [document(capture.leaf).to_dict(), *([capture.source.to_dict()] if capture.source else [])],
            "basis": "user_selection" if capture.source else "proposal"}
    if step.undo:
        records[step.field + "/undo"] = {
            "source": [document(operations[step.undo.operation].pointer).to_dict(), *(document(value.leaf).to_dict() for value in step.undo.values),
                       *([step.undo.source.to_dict()] if step.undo.source else [])],
            "basis": "user_selection" if step.undo.source else "proposal"}
    return records


def _sent(catalog, server, operation_id, values, declarations):
    """The transport request that sends checked values to a documented operation, with its documented 2xx statuses.

    An environment value becomes a run variable, so a missing one stops the run before any request."""
    operation = next(op for op in catalog.operations if op.id == operation_id)
    url, query, body = operation.path, {}, []
    for value in values:
        expression = value.expression
        if "env" in expression:
            variable = "input_" + expression["env"].removeprefix("TARGET_INPUT_").lower()
            declarations.setdefault(variable, {"env": expression["env"]})
            expression = {"var": variable}
        if value.location == "path":
            url = url.replace("{" + value.path[0] + "}", "{" + expression["var"] + "}")
        elif value.location == "query":
            query[value.path[0]] = expression
        else:
            body.append((value.path, expression))
    request = {"method": operation.method, "url": server + url, "headers": {"Accept": "application/json"},
               **({"query": query} if query else {}),
               "body": {"json": _nest(body)} if operation.method != "DELETE" and _root(operation, "step") else {"none": True}}
    return request, [int(code) for code, _ in _success(operation)]


def _step_spec(catalog, server, step, declarations):
    request, statuses = _sent(catalog, server, step.entry.operation, step.values, declarations)
    spec = {"id": step.entry.id, "request": request, "expect": {"http_status": statuses}}
    if any(_material(value.expression) for value in step.values):
        spec["if_present"] = "material"
    if step.capture:
        spec["capture"] = {capture.name: {"path": _field_path(capture.path)} for capture in step.capture}
    if step.undo:
        undo, undo_statuses = _sent(catalog, server, step.undo.operation, step.undo.values, declarations)
        spec["undo"] = {"request": undo, "expect": {"http_status": undo_statuses}}
    return spec


def _unsafe_path(path):
    return path.startswith("//") or "\\" in path or unquote(path) != path or ".." in path.split("/") or "?" in path or "#" in path


def compile_draft(catalog: OperationCatalog, choices: DraftChoices) -> DraftArtifacts:
    gaps = list(choices.gaps)
    provenance = {"schema_version": 1, "openapi_version": catalog.document.data["openapi"],
                  "inputs": list(catalog.document.inputs), "fields": {}, "policy_defaults": {},
                  "selection": {"operation": choices.operation, "intent": choices.intent, "mode": "no-model"},
                  "document_policy": {"examples_and_defaults": "omitted", "network_refs": "denied"},
                  "validation": {"offline": "not_run"}}
    if choices.inputs:
        provenance["inputs"].append(dict(choices.inputs.source))
    operation = next((op for op in catalog.operations if op.id == choices.operation), None)
    auth = None
    read = {}
    result = operation
    if operation:
        result, poll_parameters = _poll_target(catalog, operation, choices)
        try:
            auth = _auth(catalog, operation)
            security_pointer = operation.pointer + "/security" if "security" in operation.data else "/security" if "security" in catalog.document.data else ""
            sources = [catalog.document.source(security_pointer).to_dict()]
            requirement = operation.data.get("security", catalog.document.data.get("security", []))
            if requirement and isinstance(requirement[0], dict) and requirement[0]:
                scheme_pointer = pointer_child("/components/securitySchemes", next(iter(requirement[0])))
                sources.append(catalog.document.source(scheme_pointer).to_dict())
            provenance["fields"]["/transport/auth"] = {"source": sources, "basis": "document_security_or_openapi_default"}
            if auth["kind"] != "none":
                provenance["fields"]["/transport/auth"]["environment_name_basis"] = "policy_default"
        except (ValueError, TypeError, AttributeError):
            gaps.append(_gap(catalog, "/transport/auth", "authentication_unsupported",
                             "Authentication is malformed, ambiguous or not supported.", pointer=operation.pointer, kind="unsupported_feature"))
        for binding, role, field, code in ((choices.prompt, "prompt", "/transport/request/body", "prompt_binding_proposed"),
                                           (choices.reply, "reply", "/transport/response/text", "reply_binding_proposed"),
                                           (choices.completion, "completion", "/transport/outcome/rules/0", "completion_proposed")):
            if isinstance(binding, StatusMap):
                values = _binding_schema(catalog, result, binding.field, "completion")["enum"]
                classified = (binding.field.value, *binding.pending, *binding.failed)
                if len(set(classified)) != len(classified) or not set(classified) <= set(values):
                    raise ValueError("Status values must be documented and disjoint")
                read.update(_binding_reads(catalog, result, binding.field, "completion"))
                source = catalog.document.source(binding.field.pointer)
                for target in (field, "/transport/delivery/pending"):
                    provenance["fields"][target] = {"source": [source.to_dict()], "basis": binding.field.basis, "strategy": "status_word_table"}
                if binding.field.basis == "proposal":
                    gaps.append(_gap(catalog, "/transport/delivery/pending", "poll_status_proposed",
                                     "Success, pending and failure values were classified by a fixed word table.",
                                     pointer=binding.field.pointer, kind="proposal", blocking=False))
                unclassified = [value for value in values if value not in classified]
                if unclassified:
                    gaps.append(_gap(catalog, "/transport/outcome/unmatched", "poll_status_unclassified",
                                     "These documented values end the run as target errors: " + ", ".join(unclassified) + ".",
                                     pointer=binding.field.pointer, kind="proposal", blocking=False))
            elif isinstance(binding, ReplyPresence):
                if choices.reply is None:
                    raise ValueError("Reply presence requires a selected reply field")
                _binding_schema(catalog, operation, choices.reply, "reply")
                provenance["fields"][field] = {"source": [catalog.document.source(choices.reply.pointer).to_dict()], "basis": "proposal", "strategy": "reply_presence_and_strict_mapping"}
                gaps.append(Gap(field,
                                "Reply presence with strict string mapping is a proposed synchronous completion rule.",
                                "Confirm that the synchronous reply rule matches the documented API's completion semantics.",
                                code, "proposal", False, (catalog.document.source(choices.reply.pointer),)))
            elif binding:
                _binding_schema(catalog, operation if role == "prompt" else result, binding, role,
                                kinds=("string", "object") if role == "reply" and choices.delivery else ("string",))
                read.update(_binding_reads(catalog, operation if role == "prompt" else result, binding, role))
                source = catalog.document.source(binding.pointer)
                entry = getattr(choices.inputs, role, None) if binding.basis == "user_selection" else None
                provenance["fields"][field] = (_user_record(catalog, binding.pointer, entry) if entry
                                               else {"source": [source.to_dict()], "basis": binding.basis})
                if binding.basis == "proposal":
                    gaps.append(_gap(catalog, field, code, "This field's business role is a name/schema-based proposal.",
                                     pointer=binding.pointer, kind="proposal", blocking=False))
        for item in choices.delivery.ids if choices.delivery else ():
            read.update(_binding_reads(catalog, operation, item.submit, "id"))
            parameter_pointer, parameter_schema = poll_parameters[item.parameter]
            read[parameter_pointer + "/schema"] = parameter_schema
            field = "/transport/delivery/ids/" + item.name
            if item.fallback:
                read.update(_binding_reads(catalog, result, item.fallback, "id"))
            if item.identity:
                read.update(_binding_reads(catalog, result, item.identity.field, "id"))
                provenance["fields"][field + "/poll"] = {
                    "source": [catalog.document.source(item.identity.field.pointer).to_dict()], "basis": "document_fact"}
            if item.override or item.identity:
                record = {"source": [catalog.document.source(item.submit.pointer).to_dict()],
                          "basis": "user_selection" if item.override else "proposal"}
                if item.override:
                    record["source"].append(item.override.source.to_dict())
                    if item.override.origin is not None: record["origin"] = item.override.origin
                    gaps.append(Gap(field + "/last_segment", "The file selects how this submit ID is extracted.",
                                    DECISIONS["binding_user_supplied"], "binding_user_supplied", "documentation_gap", False,
                                    (catalog.document.source(item.submit.pointer), item.override.source)))
                else:
                    record["source"].append(catalog.document.source(item.identity.field.pointer).to_dict())
                    gaps.append(_gap(catalog, field + "/last_segment", "poll_id_extraction_proposed",
                                     "The documented poll resource name suggests extracting the submit ID's last segment.",
                                     pointer=item.submit.pointer, kind="proposal", blocking=False))
                provenance["fields"][field + "/last_segment"] = record
            provenance["fields"][field] = {"source": [catalog.document.source(item.submit.pointer).to_dict(),
                                                      catalog.document.source(parameter_pointer).to_dict()],
                                           "basis": item.submit.basis}
            if item.submit.basis == "proposal":
                gaps.append(_gap(catalog, field, "poll_id_binding_proposed", "The submit field was paired with the poll path parameter by name.",
                                 pointer=item.submit.pointer, kind="proposal", blocking=False))
        for item in choices.delivery.carried if choices.delivery else ():
            source_schema = _schema_at(catalog, item.submit_pointer + "/schema")
            read[item.submit_pointer + "/schema"] = source_schema
            read[item.poll_pointer + "/schema"] = poll_parameters[item.parameter][1]
            field = "/transport/delivery/request/url/" + item.parameter
            record = {"source": [catalog.document.source(item.submit_pointer).to_dict(),
                                 catalog.document.source(item.poll_pointer).to_dict()],
                      "basis": "user_selection" if item.source else "document_fact"}
            if item.source:
                record["source"].append(item.source.to_dict())
                gaps.append(Gap(field, "The file maps this poll parameter to the submit path.",
                                DECISIONS["binding_user_supplied"], "binding_user_supplied", "documentation_gap", False,
                                (catalog.document.source(item.submit_pointer), catalog.document.source(item.poll_pointer), item.source)))
            provenance["fields"][field] = record
        for step in choices.steps:
            read.update({pointer: _schema_at(catalog, pointer) for pointer in step.reads})
            provenance["fields"].update(_step_records(catalog, step))
        if choices.delivery and auth is not None:
            try:
                same_auth = _auth(catalog, result) == auth
            except (ValueError, TypeError, AttributeError):
                same_auth = False
            if not same_auth:
                gaps.append(_gap(catalog, "/transport/auth", "async_shape_unsupported",
                                 "The poll operation's authentication differs from the submit operation's.",
                                 pointer=result.pointer, kind="unsupported_feature"))
        if auth and auth["kind"] != "none":
            gaps.append(_gap(catalog, "/transport/auth", "authentication_binding_required",
                             "Bind the documented authentication scheme to TARGET_API_KEY before execution.",
                             pointer=operation.pointer, blocking=False))
        gaps.extend(_unsupported_gap(catalog, pointer, keywords)
                    for pointer, keywords in _unsupported_reads(catalog, read).items())
        cleanup = any(op.method == "DELETE" or re.search(r"cancel|pause", op.id, re.I) for op in catalog.operations)
        gaps.append(_gap(catalog, "/transport/lifecycle", "cleanup_mapping_missing" if cleanup else "cleanup_endpoint_missing",
                         "No cleanup relation is selected." if cleanup else "No cleanup endpoint is documented; decide whether this operation requires cleanup.",
                         pointer=operation.pointer, blocking=False))
    spec = None
    if not any(gap.blocking for gap in gaps) and operation and choices.server and choices.prompt and choices.reply and choices.completion:
        _, server = _server(choices.server)
        declared = [_server(entry.get("url"))[1] for entry in catalog.document.data.get("servers", [])
                    if isinstance(entry, dict) and not entry.get("variables")]
        if server not in declared:
            raise ValueError("Choice server is not a declared root server")
        path = operation.path
        if _unsafe_path(path) or _unsafe_path(result.path):
            gaps.append(_gap(catalog, "/transport/request/url", "path_unsafe", "Operation path cannot be safely compiled.", pointer=operation.pointer, kind="unsupported_feature"))
        else:
            request_schema = _object_schema(operation.data["requestBody"]["content"])
            declarations = {}
            unbound_path = path
            path_bindings = {}
            query = {}
            path_parameters = operation.path_data.get("parameters", [])
            operation_parameters = operation.data.get("parameters", [])
            if not isinstance(path_parameters, list) or not isinstance(operation_parameters, list):
                raise ValueError("Malformed parameter list")
            parameters = [(parameter, pointer_child(operation.pointer.rsplit("/", 1)[0] + "/parameters", index))
                          for index, parameter in enumerate(path_parameters)]
            parameters += [(parameter, pointer_child(operation.pointer + "/parameters", index))
                           for index, parameter in enumerate(operation_parameters)]
            required = request_schema.get("required", [])
            if not isinstance(parameters, list) or not isinstance(required, list):
                raise ValueError("Malformed required fields or parameters")
            for parameter, parameter_pointer in parameters:
                if not isinstance(parameter, dict):
                    raise ValueError("Malformed parameter")
                if not parameter.get("required") and parameter.get("in") != "path":
                    continue
                name = parameter.get("name")
                place = parameter.get("in")
                if (not isinstance(name, str) or place not in {"path", "query"}
                        or _type(parameter.get("schema")) not in {"string", "integer", "number", "boolean"}
                        or parameter.get("style", "simple" if place == "path" else "form") != ("simple" if place == "path" else "form")
                        or "explode" in parameter and not isinstance(parameter["explode"], bool)
                        or "content" in parameter or parameter.get("allowReserved")):
                    gaps.append(_gap(catalog, "/transport/request", "parameter_unsupported", "A required parameter needs an explicit supported binding.", pointer=parameter_pointer, kind="unsupported_feature"))
                    continue
                schema_pointer = parameter_pointer + "/schema"
                unsupported = _keywords(parameter["schema"])[0]
                if unsupported:
                    gaps.append(_unsupported_gap(catalog, schema_pointer, unsupported))
                    continue
                variable = _input_variable(name)
                if re.search(r"key|token|password|secret|auth", name, re.I):
                    gaps.append(_gap(catalog, "/transport/request", "credential_parameter_unsupported", "Credential parameters must use a supported authentication scheme.", pointer=parameter_pointer, kind="unsupported_feature"))
                    continue
                if not NAME_RE.fullmatch(variable) or any(word in variable for word in SECRET_WORDS):
                    gaps.append(_gap(catalog, "/transport/request", "parameter_unsupported", "This parameter cannot use a supported transport variable name.", pointer=parameter_pointer, kind="unsupported_feature"))
                    continue
                if variable in declarations:
                    gaps.append(_gap(catalog, "/transport/request", "parameter_collision", "Required parameter bindings collide; select explicit names.", pointer=operation.pointer, kind="ambiguous_choice"))
                    continue
                declarations[variable] = {"env": "TARGET_" + variable.upper()}
                read[schema_pointer] = parameter["schema"]
                if place == "query":
                    query[name] = {"var": variable}
                else:
                    unbound_path = unbound_path.replace("{" + name + "}", "")
                    path_bindings[name] = variable
                binding_field = "/transport/let/run/" + variable
                provenance["fields"][binding_field] = {"source": [catalog.document.source(parameter_pointer).to_dict()], "basis": "non_secret_binding_required", "environment_name_basis": "policy_default"}
                gaps.append(_gap(catalog, binding_field, "parameter_binding_required", "Supply the documented non-secret parameter through its environment binding.", pointer=parameter_pointer, blocking=False))
            path = re.sub(r"\{([^{}]+)\}", lambda match: "{" + path_bindings.get(match[1], match[1]) + "}", path)
            entries = [(choices.prompt.path, {"context": "prompt"})]
            for entry in choices.values:
                chain = _walk(catalog, _root(operation, "value"), entry.path)
                read.update({pointer: _schema_at(catalog, pointer) for pointer in chain})
                expression = entry.value
                if "env" in expression:
                    variable = "input_" + expression["env"].removeprefix("TARGET_INPUT_").lower()
                    if variable in declarations:
                        gaps.append(_gap(catalog, "/transport/request", "parameter_collision", "Required parameter bindings collide; select explicit names.", pointer=operation.pointer, kind="ambiguous_choice"))
                        continue
                    declarations[variable] = {"env": expression["env"]}
                    expression = {"var": variable}
                entries.append((entry.path, expression))
                provenance["fields"][_body_field(entry.path)] = _user_record(catalog, chain[-1], entry)
            body = _nest(entries)
            bound = {keys[0] for keys, _ in entries}
            # Each object a bound path passes through is sent, so its own required fields must be sent too.
            sent = {keys[:end] for keys, _ in entries for end in range(1, len(keys) + 1)}
            for keys, _ in entries:
                chain = _walk(catalog, _root(operation, "value"), keys)
                for depth in range(1, len(keys)):
                    names = _schema_at(catalog, chain[depth]).get("required")
                    if isinstance(names, list) and any(keys[:depth] + (name,) not in sent for name in names):
                        gaps.append(_gap(catalog, "/transport/request/body", "business_input_missing",
                                         "An object the draft sends has a required field with no value binding.", pointer=chain[depth]))
            properties_pointer = operation.pointer + "/requestBody/content/application~1json/schema/properties"
            for name in required:
                if name in bound:
                    continue
                schema = request_schema["properties"].get(name)
                field_pointer = pointer_child(properties_pointer, name) if schema is not None else operation.pointer
                variable = _input_variable(name)
                if (_type(schema) != "string" or "enum" in schema or schema.get("readOnly") or _keywords(schema)[0]
                        or not NAME_RE.fullmatch(variable) or any(word in variable for word in SECRET_WORDS + ("credential",))):
                    gaps.append(_gap(catalog, "/transport/request/body", "business_input_missing", "A required business field has no documented value binding.", pointer=field_pointer))
                    continue
                if variable in declarations:
                    gaps.append(_gap(catalog, "/transport/request", "parameter_collision", "Required parameter bindings collide; select explicit names.", pointer=operation.pointer, kind="ambiguous_choice"))
                    continue
                declarations[variable] = {"env": "TARGET_" + variable.upper()}
                body[name] = {"var": variable}
                read[field_pointer] = schema
                binding_field = "/transport/let/run/" + variable
                provenance["fields"][binding_field] = {"source": [catalog.document.source(field_pointer).to_dict()], "basis": "non_secret_binding_required", "environment_name_basis": "policy_default"}
                gaps.append(_gap(catalog, binding_field, "body_binding_required", "Supply the required non-secret body field through its environment binding.", pointer=field_pointer, blocking=False))
            if any(name not in bound and name not in required for name in request_schema["properties"]):
                gaps.append(_gap(catalog, "/transport/request/body", "optional_inputs_unbound", "Optional request fields are omitted; this draft binds only the proposed prompt and required fields.", pointer=operation.pointer, blocking=False))
            lifecycle = {"run": [], "attempt": []}
            for step in choices.steps:
                lifecycle[step.entry.scope].append(_step_spec(catalog, server, step, declarations))
            if "{" in unbound_path:
                gaps.append(_gap(catalog, "/transport/request/url", "path_binding_missing", "Path parameters are not declared.", pointer=operation.pointer))
            if choices.delivery and any(item.name in declarations for item in choices.delivery.ids):
                gaps.append(_gap(catalog, "/transport/delivery/ids", "parameter_collision", "Poll IDs collide with input bindings; select explicit names.", pointer=result.pointer, kind="ambiguous_choice"))
            if not any(gap.blocking for gap in gaps):
                result_statuses = [int(code) for code, _ in _success(result)]
                if choices.delivery:
                    status = choices.completion
                    poll_path = result.path
                    replacements = {item.parameter: item.name for item in choices.delivery.ids}
                    replacements.update({item.parameter: _input_variable(item.submit_parameter)
                                         for item in choices.delivery.carried})
                    poll_path = re.sub(r"\{([^{}]+)\}", lambda match: "{" + replacements[match[1]] + "}", poll_path)
                    retry_after = any(isinstance(response.get("headers"), dict)
                                      and any(str(name).lower() == "retry-after" for name in response["headers"])
                                      for _, response in _success(result))
                    delivery = {"kind": "poll", "ids": {item.name: _id_selector(item) for item in choices.delivery.ids},
                                "request": {"method": "GET", "url": server + poll_path, "headers": {"Accept": "application/json"}, "body": {"none": True}},
                                "pending": {"path": _field_path(status.field.path), "one_of": list(status.pending)},
                                **({"wait": {"from": "Retry-After", "default_s": POLL_INTERVAL_S, "max_s": RETRY_AFTER_MAX_S}} if retry_after
                                   else {"interval_s": POLL_INTERVAL_S}),
                                "max_polls": MAX_POLLS, "submit_http_status": [int(code) for code, _ in _success(operation)],
                                "submit_outcome": {"kind": "rules", "unmatched": "accepted", "rules": []}}
                    rules, required = _status_rules(catalog, result, status, result_statuses, "/transport/outcome", gaps)
                    # A submit that documents the poll's state and answer can end the run itself; otherwise every accepted submit is polled.
                    submitted, submitted_prefix = _response_fields(operation)
                    polled = _response_fields(result)[0]
                    if all(submitted.get(name) == polled[name] for name in (status.field.path[0], choices.reply.path[0])):
                        delivery["submit_outcome"]["rules"], submit_required = _status_rules(
                            catalog, operation, status, delivery["submit_http_status"], "/transport/delivery/submit_outcome", gaps)
                        sources = [pointer_child(submitted_prefix, name) for name in (status.field.path[0], choices.reply.path[0])]
                        provenance["fields"]["/transport/delivery/submit_outcome"] = {
                            "source": [catalog.document.source(pointer).to_dict() for pointer in sources + ([submit_required] if submit_required else [])],
                            "basis": "proposal", "strategy": "submit_documents_poll_state_and_reply"}
                else:
                    delivery = {"kind": "sync"}
                    primary = ({"path": _field_path(choices.reply.path), "exists": True} if isinstance(choices.completion, ReplyPresence)
                               else {"path": _field_path(choices.completion.path), "equals": choices.completion.value})
                    when, required = _success_when(catalog, result, primary, "/transport/outcome", gaps)
                    rules = [{"id": "completed", "priority": 10, "http_status": result_statuses, "when": when, "outcome": "succeeded"}]
                if required:
                    provenance["fields"]["/transport/outcome/rules/0"]["source"].append(catalog.document.source(required).to_dict())
                cast = "string_or_json" if _type(_schema_at(catalog, choices.reply.pointer)) == "object" else "string"
                transport = {
                    "version": 2,
                    "request": {"method": operation.method, "url": server + path,
                                "headers": {"Accept": "application/json"}, "query": query, "body": {"json": body}},
                    "auth": auth,
                    "response": {"format": "json", "text": {"paths": [_field_path(choices.reply.path)], "cast": cast, "empty": "error"}, "metadata": {}},
                    "outcome": {"kind": "rules", "unmatched": "target_error", "rules": rules},
                    "delivery": delivery, "let": {"run": declarations},
                    **({"lifecycle": {scope: items for scope, items in lifecycle.items() if items}} if choices.steps else {}),
                    "timeout": {"total_deadline_s": POLL_DEADLINE_S if choices.delivery else 120, "read_s": 120, "cleanup_s": 60},
                    "session": {"mode": "none"},
                    "limits": {"response_bytes": 8388608, "event_bytes": 1048576, "max_events": 1024, "max_rules": 32},
                    # Every setup step and poll is charged against the request budget; each undo reserves its cleanup request
                    # before its step is sent. Both are sized for one attempt.
                    "budget": {"max_requests": len(choices.steps) + 1 + (MAX_POLLS if choices.delivery else 0),
                               "cleanup_reserve": sum(step.undo is not None for step in choices.steps)},
                }
                try:
                    spec = {"kind": "custom_http", "transport": TransportSpecV2.from_dict(transport).to_dict()}
                except ValueError as exc:
                    if not choices.steps:
                        raise
                    # Names from the bindings file can still clash with names the draft chose.
                    gaps.append(Gap("/transport/lifecycle", f"The setup steps do not compile into a valid transport: {exc}.",
                                    DECISIONS["binding_unresolved"], "binding_unresolved", "documentation_gap", True,
                                    (Source(choices.inputs.source["file"], "/steps"),)))
                    spec = None
                server_index = next(index for index, entry in enumerate(catalog.document.data["servers"]) if _server(entry["url"])[1] == server)
                provenance["fields"]["/transport/request/url"] = {"source": [catalog.document.source(operation.pointer).to_dict(), catalog.document.source(f"/servers/{server_index}/url").to_dict()], "basis": "document_path_and_selected_server"}
                provenance["policy_defaults"] = {key: {"value": transport[key], "basis": "policy_default"} for key in ("timeout", "limits", "budget", "session")}
                provenance["policy_defaults"]["request.headers"] = {"value": transport["request"]["headers"], "basis": "policy_default"}
                if choices.delivery:
                    provenance["fields"]["/transport/delivery/request/url"] = {"source": [catalog.document.source(result.pointer).to_dict(), catalog.document.source(f"/servers/{server_index}/url").to_dict()], "basis": "document_path_and_selected_server"}
                    for key in ("interval_s", "wait", "max_polls"):
                        if key in delivery:
                            provenance["policy_defaults"]["delivery." + key] = {"value": delivery[key], "basis": "policy_default"}
    unchecked = {pointer: _keywords(schema)[1] for pointer, schema in read.items() if _keywords(schema)[1]}
    if unchecked:
        names = ", ".join(sorted(set().union(*unchecked.values())))
        sources = sorted((catalog.document.source(pointer) for pointer in unchecked), key=lambda source: (source.file, source.pointer))
        gaps.append(Gap("/transport", "Schemas this draft binds carry constraints it does not check: " + names + ".",
                        DECISIONS["schema_constraints_unchecked"], "schema_constraints_unchecked",
                        "unsupported_feature", False, tuple(sources)))
    # Decided last, once every schema the draft reads is known.
    cycle_gaps = _cycle_gaps(catalog, read, (operation, result) if operation else ())
    gaps.extend(cycle_gaps)
    if any(gap.blocking for gap in cycle_gaps):
        spec = None
    gaps = tuple(sorted(set(gaps), key=lambda gap: (gap.field, gap.code, not gap.blocking,
                                                    [(source.file, source.pointer) for source in gap.source], gap.why)))
    state = DraftState.NEEDS_INPUT if spec is None else DraftState.NEEDS_REVIEW if gaps else DraftState.READY
    return DraftArtifacts(state, spec, gaps, provenance)


def artifact_destinations(out: Path) -> tuple[Path, ...]:
    out = Path(out)
    destinations = (out, out.with_suffix(".gaps.json"), out.with_suffix(".provenance.json"))
    if any(os.path.lexists(path) for path in destinations):
        raise FileExistsError("A draft artifact already exists; choose a new output path")
    if len(set(destinations)) != 3 or not out.parent.is_dir():
        raise ValueError("Output requires distinct JSON artifacts in an existing directory")
    return destinations


def write_artifacts(artifacts: DraftArtifacts, out: Path) -> tuple[Path, ...]:
    out = Path(out)
    destinations = artifact_destinations(out)
    gap_data = {"schema_version": 1, "state": artifacts.state.value,
                "spec_written": artifacts.spec is not None, "gaps": [gap.to_dict() for gap in artifacts.gaps]}
    payloads = [(destinations[1], gap_data), (destinations[2], artifacts.provenance)]
    if artifacts.spec is not None:
        payloads.insert(0, (out, artifacts.spec))
    staged = []
    created = []
    try:
        for path, data in payloads:
            descriptor, name = tempfile.mkstemp(prefix=".argus-draft-", dir=out.parent)
            temporary = Path(name)
            staged.append(temporary)
            with os.fdopen(descriptor, "w") as handle:
                json.dump(data, handle, indent=2, allow_nan=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
            created.append(path)
    except Exception:
        for path in created:
            path.unlink()
        raise
    finally:
        for temporary in staged:
            temporary.unlink(missing_ok=True)
    return tuple(created)
