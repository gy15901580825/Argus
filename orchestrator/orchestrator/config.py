import os
from dotenv import load_dotenv

load_dotenv()

# Shared Configuration Constants

# LLM provider: "gemini" or "azure"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "azure")

# Azure OpenAI model (used when LLM_PROVIDER=azure)
AZURE_OPENAI_MODEL = os.getenv("AZURE_OPENAI_MODEL", "gpt-5.4-mini")

# Gemini models (used when LLM_PROVIDER=gemini)
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-3-pro-preview")
GEMINI_FLASH_MODEL = os.getenv("GEMINI_FLASH_MODEL", "gemini-2.0-flash")


def get_llm_model(role: str = "main"):
    """Return the model for Google ADK LlmAgent.

    For Azure OpenAI, returns a LiteLlm instance (BaseLlm subclass).
    For Gemini, returns the model name string (resolved by ADK's built-in Gemini support).

    Args:
        role: 'main' for the primary model, 'fast' for the lighter/faster model.
    """
    if LLM_PROVIDER == "azure":
        from google.adk.models.lite_llm import LiteLlm
        return LiteLlm(model=f"azure/{AZURE_OPENAI_MODEL}")
    else:
        return GEMINI_MODEL_NAME if role == "main" else GEMINI_FLASH_MODEL

# Planner Configuration
PLANNER_MODEL_PROVIDER = os.getenv("PLANNER_MODEL_PROVIDER", "anthropic")
PLANNER_MODEL          = os.getenv("PLANNER_MODEL", "claude-opus-4-7")
PLANNER_FALLBACK_MODEL = os.getenv("PLANNER_FALLBACK_MODEL", "gpt-5.4-mini")
PLANNER_MAX_STEPS      = int(os.getenv("PLANNER_MAX_STEPS", "15"))
PLANNER_HISTORY_LIMIT  = int(os.getenv("PLANNER_HISTORY_LIMIT", "5"))
PLANNER_ASK_USER_CAP   = int(os.getenv("PLANNER_ASK_USER_CAP", "2"))

# Wizard (option-picker) config — Phase 2 rollout
WIZARD_MODE_ENABLED    = os.getenv("WIZARD_MODE_ENABLED", "false").lower() == "true"
WIZARD_MAX_ROUNDS      = int(os.getenv("WIZARD_MAX_ROUNDS", "9"))

ANTHROPIC_API_KEY      = os.getenv("ANTHROPIC_API_KEY", "")

# App Configuration
APP_NAME = "argus"
USER_ID = "educator_001"
SESSION_ID = "content_session_001"

# Service URLs
API_TESTING_SERVICE_URL = os.getenv("API_TESTING_SERVICE_URL", "http://localhost:8000/sse")
WEB_UI_TESTING_SERVICE_URL = os.getenv("WEB_UI_TESTING_SERVICE_URL", "http://localhost:8002/sse")
API_SERVICE_BASE_URL = os.getenv("API_SERVICE_BASE_URL") or os.getenv("API_SERVICE_URL", "http://argus-api-service:8881")
ORCHESTRATOR_SECRET = os.getenv("ORCHESTRATOR_SECRET", "default_secret_change_me")
