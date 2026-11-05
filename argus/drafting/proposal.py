from __future__ import annotations

import json
import re

from .draft import (
    Binding, OperationSelection, ReplyPresence, _binding_schema, _object_schema, _unsupported,
)
from .openapi import OperationCatalog, pointer_child


OUTPUT_LIMIT_BYTES = 16 * 1024


class ProposalError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _reference_index(catalog):
    index = {}
    for op in catalog.operations:
        roles = {"prompt": {}, "reply": {}, "completion": {}}
        index[op.id] = roles
        if op.method != "POST" or _unsupported(op.data) or op.data.get("callbacks"):
            continue
        schemas = []
        request = op.data.get("requestBody", {})
        schema = _object_schema(request.get("content")) if isinstance(request, dict) else None
        if schema:
            schemas.append(("prompt", schema, op.pointer + "/requestBody/content/application~1json/schema/properties"))
        responses = op.data.get("responses", {})
        statuses = [str(k) for k in responses if re.fullmatch(r"2\d\d", str(k))] if isinstance(responses, dict) else []
        if len(statuses) == 1 and statuses[0] != "202":
            response = responses[statuses[0]]
            schema = _object_schema(response.get("content")) if isinstance(response, dict) else None
            if schema:
                prefix = op.pointer + "/responses/" + statuses[0] + "/content/application~1json/schema/properties"
                schemas.extend((role, schema, prefix) for role in ("reply", "completion"))
        for role, schema, prefix in schemas:
            for name, field in schema["properties"].items():
                if re.search(r"key|token|password|secret|auth|credential", name, re.I):
                    continue
                values = field.get("enum") if isinstance(field, dict) else None
                if role == "prompt" and values:
                    continue
                if role == "completion" and not (isinstance(values, list) and len(values) == 1 and isinstance(values[0], str)):
                    continue
                binding = Binding(name, pointer_child(prefix, name), value=values[0] if role == "completion" else None)
                try:
                    _binding_schema(catalog, op, binding, role)
                except (ValueError, TypeError):
                    continue
                roles[role][binding.pointer] = binding
    return index


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProposalError("model_output_invalid")
        result[key] = value
    return result


def parse_proposal(text: str, catalog: OperationCatalog) -> OperationSelection:
    if not isinstance(text, str) or len(text.encode("utf-8")) > OUTPUT_LIMIT_BYTES:
        raise ProposalError("model_output_invalid")
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        raise ProposalError("model_output_invalid") from None
    if (not isinstance(data, dict) or set(data) != {"operation", "prompt", "reply", "completion"}
            or any(not isinstance(data[key], str) or not data[key] for key in ("operation", "prompt", "reply"))
            or data["completion"] is not None and not isinstance(data["completion"], str)):
        raise ProposalError("model_output_invalid")
    index = _reference_index(catalog)
    if data["operation"] not in index:
        raise ProposalError("model_operation_unknown")
    roles = index[data["operation"]]
    if any(data[role] not in roles[role] for role in ("prompt", "reply")):
        raise ProposalError("model_field_unknown")
    completion = data["completion"]
    if completion is not None and completion not in roles["completion"]:
        raise ProposalError("model_field_unknown")
    return OperationSelection(data["operation"], roles["prompt"][data["prompt"]], roles["reply"][data["reply"]],
                              roles["completion"][completion] if completion is not None else ReplyPresence())
