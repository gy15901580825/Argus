"""Pure verdicts over A2A response facts, never error-message prose."""
from typing import Literal
Outcome = Literal['pass', 'fail', 'warn', 'skipped', 'error']
_DECIDERS = {}

def decide(name: str, evidence: dict) -> tuple[Outcome, str]:
    if name != evidence.get('check'):
        return 'error', 'evidence check does not match assertion'
    precondition = evidence.get('precondition', {})
    if 'error' in precondition:
        return 'error', precondition['error']
    if 'skip' in precondition:
        return 'skipped', precondition['skip']
    if name not in _DECIDERS:
        return 'error', 'no decider for '+name
    return _DECIDERS[name](evidence)
