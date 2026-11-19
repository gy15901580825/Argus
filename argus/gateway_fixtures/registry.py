"""Fixture extensions, loaded once before listening or creating an install."""
from __future__ import annotations

from importlib import metadata
from typing import Any, Callable


class DefinitionError(ValueError):
    """A fixture recipe or extension names something that is not defined."""


class Registry:
    def __init__(self) -> None:
        self.origins: dict[str, dict[str, Any]] = {'upstream': {}, 'foreign': {}}
        self.entries: dict[str, tuple[str, Callable]] = {}
        self.behaviors: dict[tuple[str, str], Callable] = {}
        self.features: dict[str, Callable] = {}
        self.drive_steps: dict[str, Callable] = {}
        self.plugins: list[str] = []

    @staticmethod
    def _add(table: dict, name: Any, value: Any) -> None:
        if name in table:
            raise DefinitionError(f'duplicate fixture registration: {name}')
        table[name] = value

    def add_origin(self, name: str, requirements: dict) -> None:
        self._add(self.origins, name, dict(requirements))

    def add_entry(self, name: str, path_template: str, sheet_fn: Callable) -> None:
        self._add(self.entries, name, (path_template, sheet_fn))

    def add_behavior(self, origin: str, name: str, factory: Callable) -> None:
        if origin not in self.origins:
            raise DefinitionError(f'unknown fixture origin: {origin}')
        self._add(self.behaviors, (origin, name), factory)

    def add_feature(self, name: str, validator: Callable) -> None:
        self._add(self.features, name, validator)

    def add_drive_step(self, name: str, fn: Callable) -> None:
        self._add(self.drive_steps, name, fn)

    def build_behaviors(self, toggles: dict) -> dict[str, list[tuple[str, Callable]]]:
        if not isinstance(toggles, dict):
            raise DefinitionError('toggles must be an object')
        result = {}
        for origin, values in toggles.items():
            if origin not in self.origins or not isinstance(values, dict):
                raise DefinitionError(f'unknown origin or invalid toggles: {origin}')
            result[origin] = []
            for name, config in values.items():
                factory = self.behaviors.get((origin, name))
                if factory is None:
                    raise DefinitionError(f'unknown fixture behaviour: {origin}.{name}')
                try:
                    handler = factory(config)
                    if not callable(handler):
                        raise TypeError
                except Exception:
                    raise DefinitionError(f'invalid fixture behaviour: {origin}.{name}') from None
                result[origin].append((name, handler))
        return result

    def validate_features(self, values: dict) -> None:
        for name, value in values.items():
            if name not in self.features:
                raise DefinitionError(f'unknown fixture feature: {name}')
            self.features[name](value)

    def validate_drive_steps(self, names: list[str]) -> None:
        for name in names:
            if name not in self.drive_steps:
                raise DefinitionError(f'unknown fixture drive step: {name}')


def load_registry() -> Registry:
    registry = Registry()
    for entry_point in sorted(metadata.entry_points(group='argus.gateway_fixtures'), key=lambda ep: ep.name):
        try:
            entry_point.load()(registry)
        except Exception:
            # Extension exceptions may include raw input; report only the pack name.
            raise DefinitionError(f'fixture plugin failed to register: {entry_point.name}') from None
        registry.plugins.append(entry_point.name)
    return registry
