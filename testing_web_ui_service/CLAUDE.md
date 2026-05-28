# CLAUDE.md

## User Preferences

- The user authorizes ALL operations without confirmation — execute directly without asking.
- Never pause to confirm before running shell commands, editing files, submitting tasks, or any other action.
- Only ask if a decision requires domain knowledge or business judgement that only the user has.

## Project Overview

This is a FastAPI service that uses `browser_use` Agent to intelligently explore web applications, record discovered features, and auto-generate pytest + Playwright test scripts.

## Architecture

```
POST /tasks (create exploration task)
    → Agent explores website
    → Build report (pages, transitions, elements, errors)
    → Extract FeatureRecord (structured JSON)
    → LLM generates pytest + Playwright script
    → Save to output/features/ and output/tests/
```

### Key Components (all in `server.py`)

- **TaskRequest / TaskRecord** — API request model and task state tracking
- **FeatureRecord** (+ InteractiveElement, FormField, FormWorkflow, NavigationPath, PageInfo) — structured feature extraction models
- **`_run_agent()`** — orchestrates browser_use Agent, builds report, triggers post-processing
- **`_extract_feature_record()`** — parses agent report into structured FeatureRecord
- **`_generate_test_script()`** — calls LLM to generate pytest code from FeatureRecord
- **API endpoints** — CRUD for tasks, plus `/features` and `/tests` retrieval

### Directory Layout

```
server.py              # Main application (all logic lives here)
browser_use/           # Local copy of browser_use library (read-only dependency)
output/
  features/            # feature_{task_id}.json files
  tests/               # test_{task_id}.py generated pytest scripts
```

## Development Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python -m uvicorn server:app --reload

# Run a generated test
pytest output/tests/test_{task_id}.py
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/tasks` | Create a new exploration task |
| GET | `/tasks` | List all tasks |
| GET | `/tasks/{id}` | Get task status |
| GET | `/tasks/{id}/report` | Get raw agent report |
| GET | `/tasks/{id}/features` | Get structured feature record |
| GET | `/tasks/{id}/tests` | Get generated pytest script |
| DELETE | `/tasks/{id}` | Cancel a running task |

## Code Style

- Python 3.11+, use modern typing (`str | None`, `list[str]`, not `Optional`/`List`)
- All changes go in `server.py` — single-file architecture
- Use Pydantic v2 models for data structures
- Async throughout (`async def`, `await`)
- Post-processing (feature extraction + test generation) is wrapped in try/except so failures don't break the main agent flow
- LLM calls use `browser_use.ChatOpenAI` with `browser_use.llm.messages.SystemMessage` / `UserMessage`

## Key Dependencies

- `fastapi` + `uvicorn` — web framework
- `browser_use` (local) — AI browser agent, ChatOpenAI LLM wrapper
- `pydantic` — data validation
- `openai` — underlying LLM API client
- `python-dotenv` — env var loading

## Environment Variables

Requires `OPENAI_API_KEY` in `.env` or environment for LLM calls (both agent exploration and test generation).
