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
from argus_transport.models import AuthSpec
from argus_transport.spec_v2 import NAME_RE, SECRET_WORDS

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
}

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
    name: str
    pointer: str
    basis: str = "proposal"
    value: str | None = None


@dataclass(frozen=True)
class ReplyPresence:
    pass


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
    completion: Binding | ReplyPresence | None
    gaps: tuple[Gap, ...]
    intent: str


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
    return schema


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
        value = value[key.replace("~1", "/").replace("~0", "~")]
    return value


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


def _read_schemas(catalog, pointer):
    """The bound property schema at pointer and the object schema that holds it."""
    container = pointer.rsplit("/properties/", 1)[0]
    return {item: _at(catalog, item) for item in (pointer, container)}


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


def choose_without_model(catalog: OperationCatalog, *, operation=None, server_origin=None,
                         intent="Ask an agent a question, optionally with third-party material.") -> DraftChoices:
    return _choose(catalog, operation=operation, server_origin=server_origin, intent=intent)


def choices_from_selection(catalog: OperationCatalog, selection: OperationSelection, *, operation=None,
                           server_origin=None, intent="Ask an agent a question, optionally with third-party material.") -> DraftChoices:
    if operation is not None and operation != selection.operation:
        raise ValueError("Model operation conflicts with the explicit selection")
    return _choose(catalog, operation=operation, server_origin=server_origin, intent=intent, selection=selection)


def _choose(catalog, *, operation, server_origin, intent, selection=None):
    doc = catalog.document
    gaps = []
    chosen = None
    selected_id = operation or (selection.operation if selection else None)
    candidates = [op for op in catalog.operations if op.id == selected_id] if selected_id else list(catalog.operations)
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
    prompt = reply = completion = None
    # One review row per document, because large vendor schemas serialize dozens of cycles.
    cycles = sorted({issue.source for issue in doc.issues if issue.code == "reference_cycle"},
                    key=lambda source: (source.file, source.pointer))
    if cycles:
        why = "1 reference cycle is not expanded." if len(cycles) == 1 else f"{len(cycles)} reference cycles are not expanded."
        gaps.append(Gap("/transport", why, DECISIONS["reference_cycle"],
                        "reference_cycle", "unsupported_feature", True, tuple(cycles)))
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
                             "This skeleton supports simple synchronous JSON POST operations.",
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
                prompt = Binding(name, pointer_child(request_pointer, name))
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
            if any(status == "202" for status, _ in successes):
                gaps.append(_gap(catalog, "/transport/delivery", "delivery_unsupported",
                                 "Accepted asynchronous responses require explicit poll/identity choices.",
                                 pointer=pointer, kind="unsupported_feature"))
            if len(successes) == 1 and isinstance(successes[0][1], dict):
                status, response = successes[0]
                response_schema = _object_schema(response.get("content"))
                response_pointer = pointer + "/responses/" + status + "/content/application~1json/schema/properties"
                if response.get("links"):
                    gaps.append(_gap(catalog, "/transport/delivery", "links_unsupported",
                                     "Response links need an explicit flow choice.", pointer=pointer, kind="unsupported_feature"))
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
                reply = Binding(texts[0][0], pointer_child(response_pointer, texts[0][0]))
            if len(states) == 1:
                completion = Binding(states[0][0], pointer_child(response_pointer, states[0][0]), value=states[0][1]["enum"][0])
            elif reply is not None:
                completion = ReplyPresence()
        if selection is not None:
            reply, completion = selection.reply, selection.completion
        for binding, field, missing in ((reply, "/transport/response/text", "reply_binding_missing"),
                                         (completion, "/transport/outcome", "completion_missing")):
            if binding is None:
                gaps.append(_gap(catalog, field, missing, "No unique documented reply or terminal state can be proposed.", pointer=pointer))
    return DraftChoices(chosen.id if chosen else None, server, prompt, reply, completion, tuple(gaps), intent)


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


def _field_path(name):
    return "$." + name


def _binding_schema(catalog, operation, binding, role):
    if role == "prompt":
        prefix = operation.pointer + "/requestBody/content/application~1json/schema/properties"
    else:
        successes = [status for status in operation.data.get("responses", {})
                     if re.fullmatch(r"2\d\d", str(status))]
        if len(successes) != 1:
            raise ValueError("Choice references an unknown or unsupported operation field")
        prefix = operation.pointer + "/responses/" + str(successes[0]) + "/content/application~1json/schema/properties"
    if (binding.pointer not in catalog.document.sources
            or binding.pointer != pointer_child(prefix, binding.name)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", binding.name)
            or binding.basis not in {"proposal", "document_fact", "user_selection"}):
        raise ValueError("Choice references an unknown or unsupported operation field")
    value = _at(catalog, binding.pointer)
    if _type(value) != "string" or value.get("readOnly") and role == "prompt" or value.get("writeOnly") and role != "prompt":
        raise ValueError("Choice field has an incompatible schema")
    if role == "completion" and (binding.value is None or binding.value not in value.get("enum", [])):
        raise ValueError("Choice terminal value is not documented")
    return value


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
    if operation:
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
            if isinstance(binding, ReplyPresence):
                if choices.reply is None:
                    raise ValueError("Reply presence requires a selected reply field")
                _binding_schema(catalog, operation, choices.reply, "reply")
                provenance["fields"][field] = {"source": [catalog.document.source(choices.reply.pointer).to_dict()], "basis": "proposal", "strategy": "reply_presence_and_strict_mapping"}
                gaps.append(Gap(field,
                                "Reply presence with strict string mapping is a proposed synchronous completion rule.",
                                "Confirm that the synchronous reply rule matches the documented API's completion semantics.",
                                code, "proposal", False, (catalog.document.source(choices.reply.pointer),)))
            elif binding:
                _binding_schema(catalog, operation, binding, role)
                read.update(_read_schemas(catalog, binding.pointer))
                source = catalog.document.source(binding.pointer)
                provenance["fields"][field] = {"source": [source.to_dict()], "basis": binding.basis}
                if binding.basis == "proposal":
                    gaps.append(_gap(catalog, field, code, "This field's business role is a name/schema-based proposal.",
                                     pointer=binding.pointer, kind="proposal", blocking=False))
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
        if path.startswith("//") or "\\" in path or unquote(path) != path or ".." in path.split("/") or "?" in path or "#" in path:
            gaps.append(_gap(catalog, "/transport/request/url", "path_unsafe", "Operation path cannot be safely compiled.", pointer=operation.pointer, kind="unsupported_feature"))
        else:
            request_schema = _object_schema(operation.data["requestBody"]["content"])
            body = {choices.prompt.name: {"context": "prompt"}}
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
                if name == choices.prompt.name:
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
            if any(name != choices.prompt.name and name not in required for name in request_schema["properties"]):
                gaps.append(_gap(catalog, "/transport/request/body", "optional_inputs_unbound", "Optional request fields are omitted; this draft binds only the proposed prompt and required fields.", pointer=operation.pointer, blocking=False))
            if "{" in unbound_path:
                gaps.append(_gap(catalog, "/transport/request/url", "path_binding_missing", "Path parameters are not declared.", pointer=operation.pointer))
            if not any(gap.blocking for gap in gaps):
                transport = {
                    "version": 2,
                    "request": {"method": operation.method, "url": server + path,
                                "headers": {"Accept": "application/json"}, "query": query, "body": {"json": body}},
                    "auth": auth,
                    "response": {"format": "json", "text": {"paths": [_field_path(choices.reply.name)], "cast": "string", "empty": "error"}, "metadata": {}},
                    "outcome": {"kind": "rules", "unmatched": "target_error", "rules": [{"id": "completed", "priority": 10,
                        "http_status": [int(next(key for key in operation.data["responses"] if re.fullmatch(r"2\d\d", str(key))))],
                        "when": ({"path": _field_path(choices.reply.name), "exists": True}
                                 if isinstance(choices.completion, ReplyPresence)
                                 else {"path": _field_path(choices.completion.name), "equals": choices.completion.value}), "outcome": "succeeded"}]},
                    "delivery": {"kind": "sync"}, "let": {"run": declarations},
                    "timeout": {"total_deadline_s": 120, "read_s": 120, "cleanup_s": 60},
                    "session": {"mode": "none"},
                    "limits": {"response_bytes": 8388608, "event_bytes": 1048576, "max_events": 1024, "max_rules": 32},
                    "budget": {"max_requests": 1, "cleanup_reserve": 0},
                }
                spec = {"kind": "custom_http", "transport": TransportSpecV2.from_dict(transport).to_dict()}
                server_index = next(index for index, entry in enumerate(catalog.document.data["servers"]) if _server(entry["url"])[1] == server)
                provenance["fields"]["/transport/request/url"] = {"source": [catalog.document.source(operation.pointer).to_dict(), catalog.document.source(f"/servers/{server_index}/url").to_dict()], "basis": "document_path_and_selected_server"}
                provenance["policy_defaults"] = {key: {"value": transport[key], "basis": "policy_default"} for key in ("timeout", "limits", "budget", "session")}
                provenance["policy_defaults"]["request.headers"] = {"value": transport["request"]["headers"], "basis": "policy_default"}
    unchecked = {pointer: _keywords(schema)[1] for pointer, schema in read.items() if _keywords(schema)[1]}
    if unchecked:
        names = ", ".join(sorted(set().union(*unchecked.values())))
        sources = sorted((catalog.document.source(pointer) for pointer in unchecked), key=lambda source: (source.file, source.pointer))
        gaps.append(Gap("/transport", "Schemas this draft binds carry constraints it does not check: " + names + ".",
                        DECISIONS["schema_constraints_unchecked"], "schema_constraints_unchecked",
                        "unsupported_feature", False, tuple(sources)))
    gaps = tuple(sorted(set(gaps), key=lambda gap: (gap.field, gap.code)))
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
