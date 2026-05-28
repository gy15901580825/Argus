"""Public API for the web-UI phase-decomposition runner."""
from web_ui_phases.runner import run_all_phases
from web_ui_phases.state import PhaseResult, PhaseState

__all__ = ["run_all_phases", "PhaseState", "PhaseResult"]
