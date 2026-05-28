"""Stripe configuration and helpers."""

import os
import stripe

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")

stripe.api_key = STRIPE_SECRET_KEY

# Price IDs for each plan (set via env or use defaults from Stripe dashboard)
PRICE_ID_MAP = {
    "starter": os.getenv("STRIPE_STARTER_PRICE_ID", "price_1TJpVG2WSicPxKeNUyudap72"),
    "pro": os.getenv("STRIPE_PRO_PRICE_ID", "price_1TJpVG2WSicPxKeNND8RerIX"),
    "enterprise": os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "price_1TJpVS2WSicPxKeNg1kG8loA"),
}

# Enterprise per-case price in USD (for display; actual billing via Stripe metered price)
ENTERPRISE_PRICE_PER_CASE_USD = float(os.getenv("ENTERPRISE_PRICE_PER_CASE", "0.60"))

# Model cost per 1K tokens (USD) — update as pricing changes
MODEL_PRICING = {
    "gpt-5-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-5.1-codex": {"input": 0.001, "output": 0.004},
    "gpt-5.3-chat": {"input": 0.00175, "output": 0.014},
    "gpt-5.3-codex": {"input": 0.00175, "output": 0.014},
    "gpt-5.4-mini": {"input": 0.00075, "output": 0.0045},
    "gpt-4.1-mini": {"input": 0.0001, "output": 0.0004},
    "gemini-3.1-pro": {"input": 0.00125, "output": 0.005},
    "claude-opus-4.6": {"input": 0.015, "output": 0.075},
}

SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", "https://www.example.com/dashboard?subscription=success")
CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", "https://www.example.com/pricing")
