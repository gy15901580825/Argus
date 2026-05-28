"""SMTP email alert for cost-meter threshold crossings.

Reads SMTP credentials from env (mounted from Azure Key Vault). One alert per
threshold crossing, with cooldown enforced by the caller (CostMeter._maybe_alert).
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage

logger = logging.getLogger(__name__)


class EmailAlertError(RuntimeError):
    pass


def send_daily_alert(spent_usd: float, cap_usd: float) -> None:
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    recipient = os.environ.get("COST_ALERT_RECIPIENT", "<contact@example.com>")

    if not smtp_host:
        raise EmailAlertError("SMTP_HOST not configured")
    if not smtp_user or not smtp_password:
        raise EmailAlertError("SMTP_USER / SMTP_PASSWORD not configured")

    pct = (spent_usd / cap_usd * 100.0) if cap_usd > 0 else 0.0
    msg = EmailMessage()
    msg["Subject"] = f"[Argus] Daily LLM cost at {pct:.0f}% — ${spent_usd:.2f} of ${cap_usd:.2f}"
    msg["From"] = os.environ.get("EMAIL_FROM", smtp_user)
    msg["To"] = recipient
    msg.set_content(
        f"Daily LLM spend has crossed the {pct:.0f}% threshold of the configured cap.\n\n"
        f"Spent today:  ${spent_usd:.2f}\n"
        f"Daily cap:    ${cap_usd:.2f}\n\n"
        f"If this looks unexpected, check recent runs at https://www.example.com (dashboard placeholder).\n"
        f"--\n"
        f"Argus cost-meter\n"
    )

    smtp_port = int(os.environ.get("SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as smtp:
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(msg)
    logger.info("Cost alert sent to %s (spent=%.2f cap=%.2f)", recipient, spent_usd, cap_usd)
