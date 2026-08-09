from __future__ import annotations
import os
from unittest.mock import patch, MagicMock
import pytest
from orchestrator.email_alert import send_daily_alert, EmailAlertError


def test_send_daily_alert_uses_env_secrets(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "u")
    monkeypatch.setenv("SMTP_PASSWORD", "p")
    monkeypatch.setenv("COST_ALERT_RECIPIENT", "contact@example.com")
    with patch("orchestrator.email_alert.smtplib.SMTP_SSL") as SMTP:
        smtp_inst = MagicMock()
        SMTP.return_value.__enter__.return_value = smtp_inst
        send_daily_alert(spent_usd=10.80, cap_usd=13.50)
        SMTP.assert_called_once_with("smtp.example.com", 465, timeout=15)
        smtp_inst.login.assert_called_once_with("u", "p")
        smtp_inst.send_message.assert_called_once()
        msg = smtp_inst.send_message.call_args[0][0]
        # 80% threshold visible in subject (either as %, or as $X / $Y)
        assert "80%" in msg["Subject"] or "$10.80" in msg["Subject"]
        assert msg["To"] == "contact@example.com"


def test_send_daily_alert_no_smtp_host_raises(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    with pytest.raises(EmailAlertError, match="SMTP_HOST"):
        send_daily_alert(spent_usd=10.80, cap_usd=13.50)


def test_send_daily_alert_no_creds_raises(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    with pytest.raises(EmailAlertError, match="SMTP_USER|SMTP_PASSWORD"):
        send_daily_alert(spent_usd=10.80, cap_usd=13.50)


def test_send_daily_alert_uses_default_recipient_when_unset(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "u")
    monkeypatch.setenv("SMTP_PASSWORD", "p")
    monkeypatch.delenv("COST_ALERT_RECIPIENT", raising=False)
    with patch("orchestrator.email_alert.smtplib.SMTP_SSL") as SMTP:
        smtp_inst = MagicMock()
        SMTP.return_value.__enter__.return_value = smtp_inst
        send_daily_alert(spent_usd=10.80, cap_usd=13.50)
        msg = smtp_inst.send_message.call_args[0][0]
        assert msg["To"] == "contact@example.com"  # default recipient


def test_send_daily_alert_custom_smtp_port(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "u")
    monkeypatch.setenv("SMTP_PASSWORD", "p")
    with patch("orchestrator.email_alert.smtplib.SMTP_SSL") as SMTP:
        smtp_inst = MagicMock()
        SMTP.return_value.__enter__.return_value = smtp_inst
        send_daily_alert(spent_usd=5.0, cap_usd=10.0)
        SMTP.assert_called_once_with("smtp.example.com", 587, timeout=15)


def test_send_daily_alert_from_defaults_to_smtp_user(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "contact@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "p")
    monkeypatch.delenv("EMAIL_FROM", raising=False)
    with patch("orchestrator.email_alert.smtplib.SMTP_SSL") as SMTP:
        smtp_inst = MagicMock()
        SMTP.return_value.__enter__.return_value = smtp_inst
        send_daily_alert(spent_usd=5.0, cap_usd=10.0)
        msg = smtp_inst.send_message.call_args[0][0]
        # No EMAIL_FROM override → From: falls back to SMTP_USER (avoids
        # SPF/DKIM mismatch when SMTP relay is on a different domain)
        assert msg["From"] == "contact@example.com"


def test_send_daily_alert_from_overridden_by_env(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "contact@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "p")
    monkeypatch.setenv("EMAIL_FROM", "noreply@example.com")
    with patch("orchestrator.email_alert.smtplib.SMTP_SSL") as SMTP:
        smtp_inst = MagicMock()
        SMTP.return_value.__enter__.return_value = smtp_inst
        send_daily_alert(spent_usd=5.0, cap_usd=10.0)
        msg = smtp_inst.send_message.call_args[0][0]
        assert msg["From"] == "noreply@example.com"
