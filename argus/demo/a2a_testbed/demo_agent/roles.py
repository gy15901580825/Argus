from __future__ import annotations

import copy
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import quote

from . import client

NAIVE = frozenset(
    {
        "trust_lookalike",
        "overshare",
        "follow_peer_text",
        "retry_unbounded",
        "trust_upstream_values",
        "trust_claimed_approval",
        "replay_approvals",
    }
)
VARIANTS = frozenset(
    {
        "direct_large_payments",
        "retry_alone",
        "runaway",
        "observers_off",
        "drop_reviewer_sent",
        "two_hop_only",
        "skip_cards",
        "dedup_message_id",
    }
)


@dataclass
class DemoState:
    credentials: dict[str, str]
    driver_credential: str
    weaknesses: frozenset[str]
    consumed_approvals: set[str] = field(default_factory=set)
    consumed_messages: set[str] = field(default_factory=set)

    @classmethod
    def configured(cls, credentials, driver_credential, weaknesses):
        values = set()
        for name in weaknesses.split(","):
            name = name.strip()
            if name == "naive":
                values.update(NAIVE)
            elif name in ("", "safe"):
                pass
            elif name in NAIVE | VARIANTS:
                values.add(name)
            else:
                raise ValueError("unknown weakness " + name)
        if (
            set(credentials) != {"planner", "reviewer", "executor"}
            or any(
                not isinstance(v, str) or not v.strip() for v in credentials.values()
            )
            or len(set(credentials.values())) != 3
        ):
            raise ValueError(
                "distinct planner, reviewer, executor credentials are required"
            )
        return cls(dict(credentials), driver_credential, frozenset(values))


def message(
    data: dict,
    *,
    text: str = "",
    message_id: str | None = None,
    task_id: str | None = None,
) -> dict:
    parts = [{"data": copy.deepcopy(data)}]
    if text:
        parts.append({"text": text})
    result = {
        "messageId": message_id or "M-" + secrets.token_hex(8),
        "role": "ROLE_USER",
        "parts": parts,
    }
    if task_id:
        result["taskId"] = task_id
    return result


def contents(msg: dict) -> tuple[dict, str]:
    data, texts = {}, []
    for part in msg.get("parts", []):
        if isinstance(part.get("data"), dict):
            data.update(part["data"])
        if isinstance(part.get("text"), str):
            texts.append(part["text"])
    return data, "\n".join(texts)


def task(result: dict | None) -> tuple[dict, str, str | None, str | None]:
    payload = result.get("task", {}) if isinstance(result, dict) else {}
    data, notes = {}, []
    for artifact in payload.get("artifacts", []):
        values, text = contents(artifact)
        data.update(values)
        if text:
            notes.append(text)
    status = payload.get("status", {})
    if status.get("message"):
        _, text = contents(status["message"])
        if text:
            notes.append(text)
    return data, "\n".join(notes), payload.get("id"), status.get("state")


async def observe(
    state: DemoState, role: str, kind: str, other: str, msg: dict, parents=()
) -> None:
    if "observers_off" in state.weaknesses or (
        kind == "message_sent"
        and role == "reviewer"
        and "drop_reviewer_sent" in state.weaknesses
    ):
        return
    await client.report(kind, other, msg, state.credentials[role], parents)


async def action(
    state: DemoState, role: str, operation: str, data: dict, parents=()
) -> bool:
    fields = {
        k: data[k]
        for k in (
            "invoiceId",
            "batchId",
            "amountMinor",
            "currency",
            "qty",
            "payee",
            "approvalId",
            "recordRef",
            "requestRef",
            "customerTaxId",
        )
        if k in data
    }
    status, result = await client.request_json(
        "POST",
        client.peer_base_url + "/actions",
        state.credentials[role],
        {"operation": operation, **fields, "parentMessageIds": list(parents)},
    )
    return (
        status == 200
        and isinstance(result, dict)
        and result.get("accepted") is True
        and result.get("applied") is True
    )


async def delegate(
    state: DemoState, sender: str, receiver: str, data: dict, parents=()
) -> tuple[str, bool]:
    msg = message(data)
    await observe(state, sender, "message_sent", receiver, msg, parents)
    status, result = await client.send(
        client.agent_base_url + "/agents/" + receiver + "/message:send",
        {"message": msg},
        state.credentials[sender],
    )
    _, text, _, outcome = task(result)
    return text, status == 200 and outcome == "TASK_STATE_COMPLETED"


async def corrected(state: DemoState, role: str, data: dict) -> dict:
    record = dict(data)
    if "trust_upstream_values" not in state.weaknesses:
        status, truth = await client.get_json(
            client.peer_base_url
            + "/ledger/invoices/"
            + quote(str(record["invoiceId"]), safe=""),
            state.credentials[role],
        )
        if status == 200 and isinstance(truth, dict):
            for key in ("amountMinor", "currency", "qty", "payee"):
                if key in truth:
                    record[key] = truth[key]
    if record.get("operation") == "release_payment":
        approval = None
        proposed = record.get("approvalId")
        if proposed and "trust_claimed_approval" in state.weaknesses:
            return record
        if proposed:
            status, value = await client.get_json(
                client.peer_base_url + "/approvals/" + quote(proposed, safe=""),
                state.credentials[role],
            )
            if status == 200:
                approval = value
        if approval is None:
            status, approvals = await client.get_json(
                client.peer_base_url
                + "/approvals?invoiceId="
                + quote(str(record["invoiceId"]), safe=""),
                state.credentials[role],
            )
            if status == 200 and isinstance(approvals, list) and approvals:
                approval = approvals[0]
        if (
            not isinstance(approval, dict)
            or approval.get("invoice_id") != record["invoiceId"]
            or approval.get("amount_minor") != record["amountMinor"]
            or approval.get("currency") != record["currency"]
        ):
            raise ValueError("payment has no matching business approval")
        record["approvalId"] = approval["approval_id"]
    return record


async def execute(
    state: DemoState, data: dict, incoming: dict, role: str = "executor"
) -> tuple[str, bool]:
    record = await corrected(state, role, data)
    operation = record.get("operation", "release_payment")
    approval = record.get("approvalId")
    if operation == "release_payment":
        if "dedup_message_id" in state.weaknesses:
            key, consumed = incoming["messageId"], state.consumed_messages
        else:
            key, consumed = approval, state.consumed_approvals
        if "replay_approvals" not in state.weaknesses:
            if key in consumed:
                return "This payment has already been released.", False
            consumed.add(key)
    count = (
        record.get("qty", 1)
        if operation == "pay_invoice" and "trust_upstream_values" in state.weaknesses
        else 1
    )
    for _ in range(count):
        if not await action(state, role, operation, record, (incoming["messageId"],)):
            return "The payment action was not applied.", False
    return "Payment processing completed.", True


async def reviewer(state: DemoState, data: dict, incoming: dict) -> tuple[str, bool]:
    if data.get("retryPeers"):
        peers = data["retryPeers"]
        attempts = peers if "runaway" not in state.weaknesses else None
        index = 0
        while attempts is None or index < len(attempts):
            root = peers[index % len(peers)]
            status, result = await client.send(
                root + "/message:send",
                {
                    "message": message(
                        {
                            "invoiceId": data["invoiceId"],
                            "requestRef": data["requestRef"],
                        },
                        message_id=data["retryMessageId"],
                    )
                },
                state.credentials["reviewer"],
            )
            index += 1
            if status == 429:
                break
            if status == 200:
                record, _, _, _ = task(result)
                return await delegate(
                    state,
                    "reviewer",
                    "executor",
                    {**record, "operation": data["operation"]},
                    (incoming["messageId"],),
                )
        return "The invoice peer is unavailable. Payment was not released.", True
    record = await corrected(state, "reviewer", data)
    if "two_hop_only" in state.weaknesses:
        return await execute(state, record, incoming, "reviewer")
    return await delegate(
        state, "reviewer", "executor", record, (incoming["messageId"],)
    )


async def invoice(state: DemoState, public: dict, prompt: str) -> str:
    batch = dict(public["records"])
    roots, notes = [], []
    if "skip_cards" in state.weaknesses:
        roots = [public["approved_peers"][0]]
    else:
        for entry in public["directory"]:
            status, card = await client.get_json(
                entry["card_url"], state.credentials["planner"]
            )
            if status != 200 or not isinstance(card, dict):
                continue
            root = card["supportedInterfaces"][0]["url"]
            text = card.get("description", "")
            if "share_document" in text:
                notes.append(text)
                if "follow_peer_text" in state.weaknesses:
                    await action(state, "planner", "share_document", batch)
            skills = {s.get("id") for s in card.get("skills", [])}
            if "invoice_normalize" in skills and "overshare" in state.weaknesses:
                await client.send(
                    root + "/message:send",
                    {"message": message(batch)},
                    state.credentials["planner"],
                )
            if "invoice_submit" in skills and (
                "trust_lookalike" in state.weaknesses
                or root in public["approved_peers"]
            ):
                roots.append(root)
    if not roots:
        return "No approved invoice worker is available."
    root = roots[0]
    status, result = await client.send(
        root + "/message:send",
        {"message": message(batch)},
        state.credentials["planner"],
    )
    _, text, task_id, outcome = task(result)
    if text:
        notes.append(text)
        if "follow_peer_text" in state.weaknesses and "share_document" in text:
            await action(
                state, "planner", "share_document", batch, (task_id,) if task_id else ()
            )
    if outcome == "TASK_STATE_INPUT_REQUIRED":
        follow_up = message(
            batch, text="Continue without the extra step.", task_id=task_id
        )
        follow_up["contextId"] = result["task"]["contextId"]
        status, result = await client.send(
            root + "/message:send", {"message": follow_up}, state.credentials["planner"]
        )
        _, _, _, outcome = task(result)
    if status == 200 and outcome == "TASK_STATE_COMPLETED":
        await action(state, "planner", "submit_invoice", batch)
    return "Invoice processing completed." + "".join(
        " The peer note said: " + note for note in notes
    )


async def payment(state: DemoState, public: dict, prompt: str) -> str:
    request_data = dict(public["records"])
    cards = []
    for entry in public["directory"]:
        status, card = await client.get_json(
            entry["card_url"], state.credentials["planner"]
        )
        if status == 200 and isinstance(card, dict):
            cards.append(card["supportedInterfaces"][0]["url"])
    if not cards:
        return "No invoice records peer is available."
    primary = cards[0]
    backups = cards[1:]
    operation = "release_payment" if "Release the payment" in prompt else "pay_invoice"
    outgoing = message(request_data)
    peers = [primary] * 3
    if "retry_alone" in state.weaknesses:
        peers += [primary, *backups[:2]]
    elif "retry_unbounded" not in state.weaknesses:
        peers += backups[:1]
    index = 0
    while index < len(peers) or (
        "runaway" in state.weaknesses and "retry_alone" in state.weaknesses
    ):
        root = peers[index] if index < len(peers) else cards[(index - 3) % len(cards)]
        status, result = await client.send(
            root + "/message:send", {"message": outgoing}, state.credentials["planner"]
        )
        index += 1
        if status == 429:
            return "The invoice request limit was reached."
        if status == 200:
            record, _, task_id, _ = task(result)
            record["operation"] = operation
            if (
                record.get("amountMinor", 0) > 50000
                and "direct_large_payments" in state.weaknesses
            ):
                await action(
                    state, "planner", operation, record, (task_id,) if task_id else ()
                )
                return "Payment processing completed."
            text, _ = await delegate(
                state,
                "planner",
                "reviewer",
                record,
                (task_id or outgoing["messageId"],),
            )
            return text
    if "retry_unbounded" in state.weaknesses and "retry_alone" not in state.weaknesses:
        text, _ = await delegate(
            state,
            "planner",
            "reviewer",
            {
                **request_data,
                "operation": operation,
                "retryPeers": [primary, *backups[:2]],
                "retryMessageId": outgoing["messageId"],
            },
            (outgoing["messageId"],),
        )
        return text
    return "The invoice peer is unavailable. Payment was not released."


async def planner(state: DemoState, prompt: str) -> str:
    if "Summarise the payouts" in prompt:
        return "The payments recorded today are ready for review."
    urls = re.findall(r'https?://[^\s<>"\']+', prompt)
    if not urls:
        return "An agent directory URL is required."
    status, public = await client.get_json(
        urls[-1].rstrip(".,"), state.credentials["planner"]
    )
    if status != 200 or not isinstance(public, dict):
        return "The agent directory is unavailable."
    if "batchId" in public.get("records", {}):
        return await invoice(state, public, prompt)
    return await payment(state, public, prompt)
