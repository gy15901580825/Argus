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
    "poll_status_proposed": "Confirm the success value and the values that mean the job is still running.",
    "poll_status_unclassified": "Confirm that these documented values should end the run as target errors.",
    "async_shape_unsupported": "Review the asynchronous flow; this command drafts only a documented GET poll with a top-level string status enum.",
    "success_conditions_minimal": "Confirm which fields a successful response must carry; add exists checks to the success rule if the API guarantees them.",
    "required_fields_unchecked": "Decide whether a successful response must carry these fields; the success rule does not check them.",
    "field_path_unwritable": "Document another field for this role; no transport path can name an empty field or one that contains a quote, backslash or line break.",
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
class IdBinding:
    name: str
    submit: Binding
    parameter: str


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


@dataclass(frozen=True)
class OperationSelection:
    operation: str
    prompt: Binding
    reply: Binding | None
    completion: Binding | ReplyPresence | None


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


def _poll_parameters(op):
    """Required path parameters of a same-origin GET with one 2xx JSON object response, or None if it cannot be a poll.

    A GET that documents only 202 never reports a finished job, so it cannot be the poll."""
    if (op.method != "GET" or op.path_data.get("servers") or op.data.get("servers") or op.data.get("callbacks")
            or _response_fields(op)[0] is None or [status for status, _ in _success(op)] == ["202"]):
        return None
    parameters = _parameters(op)
    if parameters is None or any(not isinstance(parameter, dict) for parameter, _ in parameters):
        return None
    found = [(parameter, pointer) for parameter, pointer in parameters if parameter.get("in") == "path"]
    names = [parameter.get("name") for parameter, _ in found]
    if (not 1 <= len(found) <= 4 or sorted(names) != sorted(re.findall(r"\{([^{}]+)\}", op.path)) or len(set(names)) != len(names)
            or any(parameter.get("required") is not True or parameter.get("style", "simple") != "simple" or "content" in parameter
                   or _type(parameter.get("schema")) not in {"string", "integer"} for parameter, _ in found)):
        return None
    return tuple((parameter["name"], (pointer, parameter["schema"])) for parameter, pointer in found)


def _pair(parameters, ids):
    """Map each poll path parameter to one submit ID: equal names, or `id` to the only `<x>_id`/`<x>Id` field."""
    pairs = []
    for parameter, _ in parameters:
        named = [binding for binding in ids.values() if re.fullmatch(r".+(?:_id|[a-z0-9]Id)", binding.path[0])]
        match = ids.get(parameter) or (named[0] if parameter == "id" and len(named) == 1 else None)
        if match is None:
            return None
        pairs.append(IdBinding(_id_variable(match.path[0]), match, parameter))
    if len({pair.name for pair in pairs}) != len(pairs):
        return None
    return tuple(pairs)


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


def _poll_choice(catalog, submit, *, poll_operation, required, gaps):
    """Pair the submit with a documented GET poll. Returns (delivery, reply, completion), or None to stay synchronous."""
    ids = _id_candidates(submit)
    polls = [(op, _poll_parameters(op)) for op in catalog.operations if poll_operation in {None, op.id}]
    polls = [(op, parameters) for op, parameters in polls if parameters]
    paired = [(op, pairs) for op, parameters in polls if (pairs := _pair(parameters, ids))]
    if not paired and not required:
        return None
    candidates = [(op, pairs) for op, pairs in paired if _status_field(op)[0]]
    if not polls:
        gaps.append(_gap(catalog, "/transport/delivery", "async_poll_missing",
                         "The submit response carries no answer and no GET operation can return the job's result.", pointer=submit.pointer))
        return None, None, None
    if not paired:
        gaps.append(_gap(catalog, "/transport/delivery/ids", "poll_id_binding_missing",
                         "No submit response field maps uniquely to every poll path parameter.", pointer=polls[0][0].pointer))
        return None, None, None
    if not candidates:
        shape = any(_status_field(op)[1] for op, _ in paired)
        gaps.append(_gap(catalog, "/transport/delivery/pending" if shape else "/transport/outcome",
                         "async_shape_unsupported" if shape else "completion_missing",
                         "The poll state is not a top-level string enum." if shape else "The poll response documents no terminal state.",
                         pointer=paired[0][0].pointer, kind="unsupported_feature" if shape else "documentation_gap"))
        return None, None, None
    if len(candidates) > 1:
        gaps.append(_gap(catalog, "/transport/delivery", "poll_ambiguous", "Several GET operations can poll the submitted job.",
                         pointer=submit.pointer, kind="ambiguous_choice"))
        return None, None, None
    op, pairs = candidates[0]
    (name, schema), _, prefix = _status_field(op)
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
    return PollChoice(op.id, pairs), reply, completion


def choose_without_model(catalog: OperationCatalog, *, operation=None, server_origin=None, poll_operation=None,
                         intent="Ask an agent a question, optionally with third-party material.") -> DraftChoices:
    return _choose(catalog, operation=operation, server_origin=server_origin, poll_operation=poll_operation, intent=intent)


def choices_from_selection(catalog: OperationCatalog, selection: OperationSelection, *, operation=None,
                           server_origin=None, poll_operation=None,
                           intent="Ask an agent a question, optionally with third-party material.") -> DraftChoices:
    if operation is not None and operation != selection.operation:
        raise ValueError("Model operation conflicts with the explicit selection")
    return _choose(catalog, operation=operation, server_origin=server_origin, poll_operation=poll_operation,
                   intent=intent, selection=selection)


def _choose(catalog, *, operation, server_origin, intent, poll_operation=None, selection=None):
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
    prompt = reply = completion = delivery = None
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
        if prompt is None:
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
        polled = (_poll_choice(catalog, chosen, poll_operation=poll_operation, required=required, gaps=gaps)
                  if success and (reply is None or required) else None)
        if polled is not None:
            delivery, reply, completion = polled
            pointer = next((op.pointer for op in catalog.operations if delivery and op.id == delivery.operation), pointer)
        if polled is None or delivery is not None:
            for binding, field, missing in ((reply, "/transport/response/text", "reply_binding_missing"),
                                             (completion, "/transport/outcome", "completion_missing")):
                if binding is None:
                    gaps.append(_gap(catalog, field, missing, "No unique documented reply or terminal state can be proposed.", pointer=pointer))
    return DraftChoices(chosen.id if chosen else None, server, prompt, reply, completion, tuple(gaps), intent, delivery)


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


def _root(operation, role):
    """The JSON object body schema a role's path starts from: the request body for the prompt, else the 2xx body."""
    if role != "prompt":
        return _body_schema(operation)[1] or None
    request = operation.data.get("requestBody")
    content = request.get("content") if isinstance(request, dict) else None
    return operation.pointer + "/requestBody/content/application~1json/schema" if _object_schema(content) else None


def _walk(catalog, root, path):
    """The schema pointers from root to the typed field at path, or None when the path leaves the documented objects.

    Each step descends `properties`, or a schema-valued `additionalProperties` for a key the document does not name.
    Arrays, untyped schemas and unexpanded reference-cycle stubs end the walk."""
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
    return tuple(chain) if _type(_schema_at(catalog, chain[-1])) is not None else None


def _resolve(catalog, operation, path, role, kinds=("string",)):
    """The schema pointers to the field at path for role, and why it cannot carry that role (None when it can).

    The pointers are None when the path names no documented field a transport path can reach."""
    root = _root(operation, role)
    chain = _walk(catalog, root, path) if root else None
    if chain is None or _field_path(path) is None:
        return None, "The path does not name a documented field of the " + ("request" if role == "prompt" else "response") + " body."
    schema = _schema_at(catalog, chain[-1])
    if _type(schema) not in kinds:
        return chain, "The field's documented type is not " + " or ".join(kinds) + "."
    if role == "prompt" and (schema.get("readOnly") or schema.get("enum")):
        return chain, "A read-only field or a documented value set cannot carry the question."
    if role != "prompt" and schema.get("writeOnly"):
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
    if not parameters or sorted(item.parameter for item in delivery.ids) != sorted(parameters):
        raise ValueError("Poll choice references an unknown or unsupported operation")
    for item in delivery.ids:
        _binding_schema(catalog, operation, item.submit, "id", kinds=("string", "integer"))
        if item.name != _id_variable(item.submit.path[0]):
            raise ValueError("Poll ID variable does not match its submit field")
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


def _unsafe_path(path):
    return path.startswith("//") or "\\" in path or unquote(path) != path or ".." in path.split("/") or "?" in path or "#" in path


def compile_draft(catalog: OperationCatalog, choices: DraftChoices) -> DraftArtifacts:
    gaps = list(choices.gaps)
    provenance = {"schema_version": 1, "openapi_version": catalog.document.data["openapi"],
                  "inputs": list(catalog.document.inputs), "fields": {}, "policy_defaults": {},
                  "selection": {"operation": choices.operation, "intent": choices.intent, "mode": "no-model"},
                  "document_policy": {"examples_and_defaults": "omitted", "network_refs": "denied"},
                  "validation": {"offline": "not_run"}}
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
                provenance["fields"][field] = {"source": [source.to_dict()], "basis": binding.basis}
                if binding.basis == "proposal":
                    gaps.append(_gap(catalog, field, code, "This field's business role is a name/schema-based proposal.",
                                     pointer=binding.pointer, kind="proposal", blocking=False))
        for item in choices.delivery.ids if choices.delivery else ():
            read.update(_binding_reads(catalog, operation, item.submit, "id"))
            parameter_pointer, parameter_schema = poll_parameters[item.parameter]
            read[parameter_pointer + "/schema"] = parameter_schema
            field = "/transport/delivery/ids/" + item.name
            provenance["fields"][field] = {"source": [catalog.document.source(item.submit.pointer).to_dict(),
                                                      catalog.document.source(parameter_pointer).to_dict()],
                                           "basis": item.submit.basis}
            if item.submit.basis == "proposal":
                gaps.append(_gap(catalog, field, "poll_id_binding_proposed", "The submit field was paired with the poll path parameter by name.",
                                 pointer=item.submit.pointer, kind="proposal", blocking=False))
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
            body = _nest([(choices.prompt.path, {"context": "prompt"})])
            bound = {choices.prompt.path[0]}
            declarations = {}
            unbound_path = path
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
                variable = "input_" + re.sub(r"[^a-zA-Z0-9_]", "_", name).lower()
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
                    path = path.replace("{" + name + "}", "{" + variable + "}")
                binding_field = "/transport/let/run/" + variable
                provenance["fields"][binding_field] = {"source": [catalog.document.source(parameter_pointer).to_dict()], "basis": "non_secret_binding_required", "environment_name_basis": "policy_default"}
                gaps.append(_gap(catalog, binding_field, "parameter_binding_required", "Supply the documented non-secret parameter through its environment binding.", pointer=parameter_pointer, blocking=False))
            properties_pointer = operation.pointer + "/requestBody/content/application~1json/schema/properties"
            for name in required:
                if name in bound:
                    continue
                schema = request_schema["properties"].get(name)
                field_pointer = pointer_child(properties_pointer, name) if schema is not None else operation.pointer
                variable = "input_" + re.sub(r"[^a-zA-Z0-9_]", "_", name).lower()
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
            if "{" in unbound_path:
                gaps.append(_gap(catalog, "/transport/request/url", "path_binding_missing", "Path parameters are not declared.", pointer=operation.pointer))
            if choices.delivery and any(item.name in declarations for item in choices.delivery.ids):
                gaps.append(_gap(catalog, "/transport/delivery/ids", "parameter_collision", "Poll IDs collide with input bindings; select explicit names.", pointer=result.pointer, kind="ambiguous_choice"))
            if not any(gap.blocking for gap in gaps):
                result_statuses = [int(code) for code, _ in _success(result)]
                if choices.delivery:
                    status = choices.completion
                    poll_path = result.path
                    for item in choices.delivery.ids:
                        poll_path = poll_path.replace("{" + item.parameter + "}", "{" + item.name + "}")
                    retry_after = any(isinstance(response.get("headers"), dict)
                                      and any(str(name).lower() == "retry-after" for name in response["headers"])
                                      for _, response in _success(result))
                    delivery = {"kind": "poll", "ids": {item.name: {"path": _field_path(item.submit.path)} for item in choices.delivery.ids},
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
                    "timeout": {"total_deadline_s": POLL_DEADLINE_S if choices.delivery else 120, "read_s": 120, "cleanup_s": 60},
                    "session": {"mode": "none"},
                    "limits": {"response_bytes": 8388608, "event_bytes": 1048576, "max_events": 1024, "max_rules": 32},
                    # Every poll is charged against the request budget.
                    "budget": {"max_requests": 1 + MAX_POLLS if choices.delivery else 1, "cleanup_reserve": 0},
                }
                spec = {"kind": "custom_http", "transport": TransportSpecV2.from_dict(transport).to_dict()}
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
    gaps = tuple(sorted(set(gaps), key=lambda gap: (gap.field, gap.code, not gap.blocking)))
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
