"""HTTP+JSON 1.0 transformations with no network I/O."""
from __future__ import annotations

import hashlib
import re
from http import HTTPStatus
import json
from dataclasses import dataclass

CONTENT_TYPE = 'application/a2a+json'
FIELDS = ('invoiceId', 'batchId', 'amountMinor', 'currency', 'qty', 'payee', 'approvalId', 'recordRef', 'requestRef', 'customerTaxId')
TERMINAL_STATES = frozenset('TASK_STATE_'+name for name in ('COMPLETED','FAILED','CANCELED','REJECTED'))


class WireError(Exception):
    def __init__(self, status: int, code: str = 'InvalidArgumentError'):
        self.status, self.code = status, code
        super().__init__(code)


@dataclass(frozen=True)
class SendRequest:
    message: dict
    configuration: dict


def version_ok(headers, query) -> bool:
    return headers.get('a2a-version', headers.get('A2A-Version')) == '1.0' or query.get('A2A-Version') == '1.0'


def parse_send(body: object) -> SendRequest:
    if not isinstance(body,dict) or not isinstance(body.get('message'),dict):
        raise WireError(400)
    message=body['message']
    if not isinstance(message.get('messageId'),str) or not message['messageId'] or message.get('role')!='ROLE_USER':
        raise WireError(400)
    parts=message.get('parts')
    if not isinstance(parts,list) or not parts:
        raise WireError(400)
    for part in parts:
        if not isinstance(part,dict) or sum(name in part for name in ('text','data','url','raw'))!=1:
            raise WireError(400)
        if any(name in part and not isinstance(part[name],str) for name in ('text','url','raw')):
            raise WireError(400)
    for key in ('taskId','contextId'):
        if key in message and not isinstance(message[key],str):raise WireError(400)
    configuration=body.get('configuration',{})
    if not isinstance(configuration,dict):raise WireError(400)
    return SendRequest(message,configuration)


def task_json(task_id: str, context_id: str, *, state: str='TASK_STATE_COMPLETED', parts: list | None=None, text: str='') -> dict:
    task={'id':task_id,'contextId':context_id,'status':{'state':state}}
    if text:task['status']['message']={'messageId':task_id+'-status','role':'ROLE_AGENT','parts':[{'text':text}]}
    if parts:task['artifacts']=[{'artifactId':task_id+'-record','parts':parts}]
    return task


def card_json(root: str, *, name: str='Invoice Worker', description: str='Processes invoice batches.', skill: str='invoice_submit') -> dict:
    return {'name':name,'description':description,'supportedInterfaces':[{'url':root,'protocolBinding':'HTTP+JSON','protocolVersion':'1.0'}],
            'version':'1','capabilities':{'streaming':False,'pushNotifications':False},'defaultInputModes':['application/json'],
            'defaultOutputModes':['application/json'],'skills':[{'id':skill,'name':name,'description':description,'tags':['invoice']}]}


def error_json(code_name: str, http_status: int) -> dict:
    return {'code':code_name,'status':http_status}


def protocol_error_json(code_name: str, http_status: int) -> dict:
    statuses = {
        400: "INVALID_ARGUMENT",
        401: "UNAUTHENTICATED",
        403: "PERMISSION_DENIED",
        404: "NOT_FOUND",
        409: "ABORTED",
        413: "RESOURCE_EXHAUSTED",
        429: "RESOURCE_EXHAUSTED",
        500: "INTERNAL",
        503: "UNAVAILABLE",
    }
    details = []
    if code_name.endswith("Error"):
        reason = re.sub(
            r"(?<!^)(?=[A-Z])", "_", code_name.removesuffix("Error")
        ).upper()
        details.append(
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": reason,
                "domain": "a2a-protocol.org",
            }
        )
    return {
        "error": {
            "code": http_status,
            "status": statuses.get(http_status, "UNKNOWN"),
            "message": HTTPStatus(http_status).phrase,
            "details": details,
        }
    }


def digest(message: dict) -> str:
    return 'sha256:'+hashlib.sha256(json.dumps(message,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def extract(message_or_body: object, session_refs: set[str], canaries: dict[str,str]) -> tuple[dict,list[str],list[str]]:
    fields={}
    if isinstance(message_or_body,dict):
        message=message_or_body.get('message',message_or_body)
        if isinstance(message,dict) and 'parts' in message:
            for part in message.get('parts',[]):
                if isinstance(part,dict) and isinstance(part.get('data'),dict):
                    fields.update({key:part['data'][key] for key in FIELDS if key in part['data']})
        else:fields={key:message[key] for key in FIELDS if key in message}
    for name in ('amountMinor','qty'):
        if name in fields and type(fields[name]) is not int:raise WireError(400)
    if any(isinstance(value,(dict,list)) for value in fields.values()):raise WireError(400)
    try:raw=json.dumps(message_or_body,sort_keys=True,allow_nan=False)
    except (TypeError,ValueError):raise WireError(400) from None
    refs=sorted(ref for ref in session_refs if ref in raw)
    markers=sorted(value for value in canaries.values() if value in raw)
    return fields,refs,markers
