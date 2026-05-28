from typing import Optional, List, Literal, Dict, Any
from enum import Enum
from datetime import datetime
from uuid import UUID
import json as _json
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

class UserRole(str, Enum):
    ORDINARY_USER = 'ORDINARY_USER'
    SUPER_ADMIN = 'SUPER_ADMIN'
    CONTENT_ADMIN = 'CONTENT_ADMIN'

class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    display_name: Optional[str] = None
    avatar: Optional[str] = None
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime

# --- Blog Models ---

class BlogCreate(BaseModel):
    title: str
    content: str
    slug: Optional[str] = None
    summary: Optional[str] = None
    category_id: Optional[UUID] = None
    tag_ids: Optional[List[UUID]] = None
    cover_image_url: Optional[str] = None
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None
    og_image_url: Optional[str] = None
    canonical_url: Optional[str] = None
    content_format: str = "html"
    featured: bool = False
    status: str = "draft"          # draft, published, scheduled, archived
    scheduled_at: Optional[datetime] = None
    locale: str = "en"

class BlogUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    slug: Optional[str] = None
    summary: Optional[str] = None
    category_id: Optional[UUID] = None
    tag_ids: Optional[List[UUID]] = None
    cover_image_url: Optional[str] = None
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None
    og_image_url: Optional[str] = None
    canonical_url: Optional[str] = None
    content_format: Optional[str] = None
    featured: Optional[bool] = None
    status: Optional[str] = None
    scheduled_at: Optional[datetime] = None
    is_published: Optional[bool] = None  # backward compat

class BlogResponse(BaseModel):
    id: UUID
    title: str
    content: str
    slug: Optional[str] = None
    summary: Optional[str] = None
    author_id: UUID
    is_published: bool
    published_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    category_id: Optional[UUID] = None
    cover_image_url: Optional[str] = None
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None
    og_image_url: Optional[str] = None
    canonical_url: Optional[str] = None
    reading_time_min: Optional[int] = None
    view_count: int = 0
    content_format: str = "html"
    featured: bool = False
    status: str = "draft"
    scheduled_at: Optional[datetime] = None
    locale: str = "en"
    author_name: Optional[str] = None
    category_name: Optional[str] = None
    category_slug: Optional[str] = None
    tags: Optional[List[dict]] = None  # [{id, name, slug}]

class BlogListItem(BaseModel):
    """Lightweight response for list endpoints (no full content)."""
    id: UUID
    title: str
    slug: Optional[str] = None
    summary: Optional[str] = None
    author_id: UUID
    author_name: Optional[str] = None
    is_published: bool
    published_at: Optional[datetime] = None
    created_at: datetime
    category_id: Optional[UUID] = None
    category_name: Optional[str] = None
    category_slug: Optional[str] = None
    cover_image_url: Optional[str] = None
    reading_time_min: Optional[int] = None
    view_count: int = 0
    featured: bool = False
    status: str = "draft"
    tags: Optional[List[dict]] = None

# --- Category Models ---

class CategoryCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    sort_order: int = 0

class CategoryResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    sort_order: int = 0
    created_at: datetime
    post_count: int = 0

# --- Tag Models ---

class TagCreate(BaseModel):
    name: str
    slug: Optional[str] = None

class TagResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    created_at: datetime
    post_count: int = 0

# --- Media Models ---

class MediaResponse(BaseModel):
    id: UUID
    filename: str
    r2_key: str
    r2_url: str
    mime_type: str
    file_size_bytes: int
    width: Optional[int] = None
    height: Optional[int] = None
    alt_text: Optional[str] = None
    uploaded_by: UUID
    created_at: datetime

# --- Blog Author Models ---

class BlogAuthorCreate(BaseModel):
    user_id: UUID
    display_name: str
    bio: Optional[str] = None

class BlogAuthorResponse(BaseModel):
    user_id: UUID
    display_name: str
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    granted_by: UUID
    granted_at: datetime

# --- Comment Models ---

class CommentCreate(BaseModel):
    content: str
    parent_comment_id: Optional[UUID] = None

class CommentResponse(BaseModel):
    id: UUID
    content: str
    user_id: UUID
    blog_id: UUID
    parent_comment_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    status: str = "approved"
    likes_count: int = 0
    user_name: Optional[str] = None

# --- Document Models ---

class DocumentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    content: Optional[str] = None # Text content
    is_published: bool = False

class DocumentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    content: Optional[str] = None
    is_published: Optional[bool] = None

class DocumentResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    content: Optional[str] = None
    owner_id: UUID
    is_published: bool
    published_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    owner_name: Optional[str] = None

# --- Script Models ---

class ScriptCreate(BaseModel):
    name: str
    script_address: str
    description: Optional[str] = None
    version: Optional[str] = None

class ScriptUpdate(BaseModel):
    name: Optional[str] = None
    script_address: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None

class ScriptResponse(BaseModel):
    id: UUID
    name: str
    script_address: str
    description: Optional[str] = None
    owner_id: UUID
    version: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    # Optional owner details
    owner_name: Optional[str] = None

# --- Agent Models ---

class AgentStatusUpdate(BaseModel):
    agent_id: str
    status: str

class AgentInfo(BaseModel):
    agent_id: str
    agent_name: str
    agent_type: Optional[str] = None
    status: str
    description: Optional[str] = None
    created_at: datetime

class AgentListResponse(BaseModel):
    agents: list[AgentInfo]

# --- Chat Models ---

class ChatSessionCreate(BaseModel):
    title: str

class ChatSessionUpdate(BaseModel):
    title: str

class BulkDeleteRequest(BaseModel):
    ids: List[UUID] = Field(..., min_length=1, max_length=100)

class ChatSessionResponse(BaseModel):
    id: UUID
    user_id: UUID
    title: str
    created_at: datetime
    updated_at: datetime
    wizard_state: Optional[Dict[str, Any]] = None

    @field_validator("wizard_state", mode="before")
    @classmethod
    def _parse_wizard_state(cls, v):
        # asyncpg returns jsonb columns as raw strings (not pre-decoded dicts)
        # because the databases library doesn't register a jsonb codec. Parse here
        # so callers see a dict and FastAPI's response validation accepts it.
        if isinstance(v, str):
            try:
                return _json.loads(v)
            except _json.JSONDecodeError:
                return None
        return v

class ChatMessageCreate(BaseModel):
    role: str
    content: str
    # Optional structured chunks: List of StreamChunk dicts the frontend already
    # accumulates per assistant turn. Persisted as JSONB so reload renders the
    # proper chunked taxonomy (log / result / web_ui_artifact / web_ui_bug /
    # ssh_result) instead of the flattened content blob.
    chunks: Optional[List[Dict[str, Any]]] = None

class ChatMessageResponse(BaseModel):
    id: UUID
    session_id: UUID
    role: str
    content: str
    chunks: Optional[List[Dict[str, Any]]] = None
    created_at: datetime

    @field_validator("chunks", mode="before")
    @classmethod
    def _parse_chunks(cls, v):
        # asyncpg returns jsonb columns as raw strings (the databases library
        # doesn't register a jsonb codec). Parse here so callers see a list and
        # FastAPI's response validation accepts it. Mirrors the wizard_state
        # validator on ChatSessionResponse.
        if isinstance(v, str):
            try:
                return _json.loads(v)
            except _json.JSONDecodeError:
                return None
        return v

# --- Web UI Task Models ---

class WebUITaskResponse(BaseModel):
    id: UUID
    owner_id: str
    target_url: str
    status: str
    user_persona: Optional[str] = None
    max_steps: Optional[int] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    steps_done: int = 0
    tests_url: Optional[str] = None
    bug_report_url: Optional[str] = None
    features_url: Optional[str] = None
    bug_counts: Optional[dict] = None
    test_summary: Optional[dict] = None
    error_message: Optional[str] = None
    screenshot_urls: Optional[list] = None
    final_output: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _parse_jsonb(cls, values: dict) -> dict:
        """asyncpg/databases may return JSONB columns as raw JSON strings — parse them."""
        for field in ("bug_counts", "test_summary", "screenshot_urls"):
            v = values.get(field)
            if isinstance(v, str):
                try:
                    values[field] = _json.loads(v)
                except Exception:
                    values[field] = None
        return values


class WebUITaskCreate(BaseModel):
    id: UUID
    target_url: str
    status: str
    user_persona: Optional[str] = None
    max_steps: Optional[int] = None
    started_at: Optional[datetime] = None


class WebUITaskUpdate(BaseModel):
    status: Optional[str] = None
    steps_done: Optional[int] = None
    finished_at: Optional[datetime] = None
    bug_counts: Optional[dict] = None
    final_output: Optional[str] = None
    test_script: Optional[str] = None
    screenshot_urls: Optional[list] = None
    error_message: Optional[str] = None


# ===== Planner Wizard Models (V13+) =====

WizardRoundLabel = Literal[
    "intent", "run_where", "credentials", "persona",
    "target_url", "local_setup_check", "confirm", "other",
]
WizardAnswerKind = Literal[
    "option_click", "free_text", "bound_context_skip", "parsed_from_text",
]
WizardInputKind = Literal["option_click", "free_text", "back", "abort"]


class BoundContext(BaseModel):
    """Read-only context written at wizard init from UI toggles. Never mutated
    during the wizard except for connectivity flags, refreshed on each POST."""
    url: Optional[str] = None
    test_env: Optional[Literal["cloud", "my_machine", "remote_ssh"]] = None
    ssh_config_present: bool = False
    cdp_url_present: bool = False
    persona: Optional[str] = None
    client_agent_connected: bool = False
    cdp_browser_reachable: bool = False


class WizardRound(BaseModel):
    n: int
    question: str
    options: List[str]
    allow_free_text: bool
    round_label: WizardRoundLabel
    answer: Optional[str] = None
    answer_kind: Optional[WizardAnswerKind] = None
    answered_at: Optional[float] = None


class WizardState(BaseModel):
    active: bool
    round_n: int
    rounds: List[WizardRound]
    bound_context: BoundContext
    dispatched: bool = False
    dispatched_tool: Optional[str] = None
    dispatched_at: Optional[float] = None


class WizardInput(BaseModel):
    roundN: int
    kind: WizardInputKind
    value: Optional[str] = None

    @model_validator(mode="after")
    def _value_required_for_answers(self):
        if self.kind in ("option_click", "free_text") and self.value is None:
            raise ValueError(f"value required for kind={self.kind}")
        if self.kind in ("back", "abort") and self.value is not None:
            raise ValueError(f"value must be omitted for kind={self.kind}")
        return self
