"""Prompt-injection guardrail wrapper — runtime defense for inbound prompts.

Wraps a HuggingFace sequence-classification model that scores whether a
user-supplied prompt is a prompt-injection / jailbreak attempt. Two
backends are supported:

- ``protectai/deberta-v3-base-prompt-injection-v2`` (default, open access,
  ~180M params, binary ``SAFE`` / ``INJECTION`` output).
- ``meta-llama/Llama-Prompt-Guard-2-86M`` (gated; requires
  ``huggingface-cli login`` and accepted Meta usage policy; ~86M params,
  ternary ``BENIGN`` / ``INJECTION`` / ``JAILBREAK`` output).

The wrapper exposes a single ``classify(text)`` method that normalises
both backends to a unified verdict. Pick the backend via ``model_name``
or the ``ARGUS_PROMPT_GUARD_MODEL`` environment variable.

Usage:

    from orchestrator.guardrails.prompt_guard import PromptGuard

    guard = PromptGuard()          # lazy model load on first use
    verdict = guard.classify(prompt)
    if verdict.blocked:
        return BLOCKED_BY_GUARDRAIL

This module is an OPTIONAL dependency. The orchestrator and the Argus CLI
both work without it. To enable, install:

    pip install argus-probe[guardrails]

which pulls in ``torch`` and ``transformers``.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class GuardVerdict:
    """Output of a single Prompt Guard classification."""

    label: str  # "BENIGN" | "SAFE" | "INJECTION" | "JAILBREAK"
    confidence: float  # softmax prob of the chosen label, in [0, 1]
    probabilities: dict[str, float]  # full softmax vector
    latency_ms: float

    @property
    def blocked(self) -> bool:
        return self.label in ("INJECTION", "JAILBREAK")


class PromptGuard:
    """Lazy-loaded wrapper around an HF prompt-injection classifier.

    Supports both ProtectAI (open) and Meta (gated) backends; the model
    is loaded on first ``classify()`` call (saves ~3 s startup cost when
    the guardrail is not actually used).

    Model cards:
    - https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
    - https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
    """

    DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
    # Universe of labels we may emit (depends on backend).
    LABELS = ("BENIGN", "SAFE", "INJECTION", "JAILBREAK")
    # Labels that should be treated as "blocked / non-benign".
    BLOCK_LABELS = ("INJECTION", "JAILBREAK")

    def __init__(
        self,
        model_name: Optional[str] = None,
        threshold: float = 0.5,
        device: Optional[str] = None,
    ):
        self.model_name = model_name or os.environ.get(
            "ARGUS_PROMPT_GUARD_MODEL", self.DEFAULT_MODEL
        )
        self.threshold = threshold
        self._device = device
        self._tokenizer = None
        self._model = None

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        try:
            import torch  # noqa: F401
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:
            raise RuntimeError(
                "Prompt Guard requires `torch` and `transformers`. "
                "Install with: pip install argus-probe[guardrails]"
            ) from e

        import torch

        logger.info("Loading Prompt Guard model %s ...", self.model_name)
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
        if self._device is None:
            self._device = "cuda" if torch.cuda.is_available() else "cpu"
        self._model.to(self._device)
        self._model.eval()
        logger.info("Prompt Guard ready on device=%s", self._device)

    def classify(self, text: str) -> GuardVerdict:
        """Return a verdict for ``text``.

        ``text`` can be a single user message or the concatenation of a
        multi-turn conversation; the model is non-causal and accepts the
        full sequence up to 512 tokens (truncation past that).
        """
        self._ensure_loaded()
        import torch

        t0 = time.perf_counter()
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(self._device)
        with torch.no_grad():
            logits = self._model(**inputs).logits  # shape (1, num_labels)
            probs = torch.softmax(logits, dim=-1).squeeze(0).tolist()

        # Read label names from the model config (works for both ProtectAI
        # and Meta backends; ProtectAI uses {0: "SAFE", 1: "INJECTION"},
        # Meta v2 uses {0: "BENIGN", 1: "INJECTION", 2: "JAILBREAK"}).
        id2label = getattr(self._model.config, "id2label", None) or {}
        if id2label:
            mapped = {id2label[i]: probs[i] for i in range(len(probs))}
        else:
            mapped = {self.LABELS[i]: probs[i] for i in range(len(probs))}

        # Normalize label keys to upper case for consistent downstream use.
        mapped = {k.upper(): v for k, v in mapped.items()}

        label = max(mapped, key=mapped.get)
        # Apply threshold: a "block" label only sticks if it crosses the
        # confidence threshold; otherwise we treat it as benign.
        if label in self.BLOCK_LABELS and mapped[label] < self.threshold:
            # Pick the highest-probability non-block label, or fall back to
            # the literal string "BENIGN" if none exists.
            non_block = {k: v for k, v in mapped.items() if k not in self.BLOCK_LABELS}
            label = max(non_block, key=non_block.get) if non_block else "BENIGN"

        return GuardVerdict(
            label=label,
            confidence=mapped[label],
            probabilities=mapped,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )


__all__ = ["PromptGuard", "GuardVerdict"]
