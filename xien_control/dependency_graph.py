from __future__ import annotations

from .models import JarScanResult


DEPENDENCY_KEYS = {"depends", "recommends", "suggests", "dependencies"}
CONFLICT_KEYS = {"breaks", "conflicts"}
PROVIDE_KEYS = {"provides"}


def collect_dependency_metadata(result: JarScanResult, data: object) -> None:
    """Extract declared mod dependency identity without treating it as risk evidence."""
    if isinstance(data, list):
        for item in data:
            collect_dependency_metadata(result, item)
        return
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        key_l = str(key).lower()
        if key_l in DEPENDENCY_KEYS:
            result.declared_dependencies.update(_flatten_ids(value))
        elif key_l in CONFLICT_KEYS:
            result.conflicting_ids.update(_flatten_ids(value))
        elif key_l in PROVIDE_KEYS:
            result.provided_ids.update(_flatten_ids(value))
        elif isinstance(value, (dict, list)):
            collect_dependency_metadata(result, value)


def _flatten_ids(value: object) -> set[str]:
    out: set[str] = set()
    if isinstance(value, str):
        out.add(value.lower())
    elif isinstance(value, dict):
        for key, nested in value.items():
            out.add(str(key).lower())
            out.update(_flatten_ids(nested))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                for wanted in ("modId", "modid", "id"):
                    raw = item.get(wanted)
                    if raw:
                        out.add(str(raw).lower())
                out.update(_flatten_ids(item))
            else:
                out.update(_flatten_ids(item))
    return {item.strip() for item in out if item and item.strip()}
