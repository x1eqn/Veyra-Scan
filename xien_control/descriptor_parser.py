from __future__ import annotations

import re

from .mapping_hints import MappingHints


def descriptor_contexts(descriptors: set[str], mappings: MappingHints) -> dict[str, int]:
    counts = {
        "entity_descriptor_refs": 0,
        "player_descriptor_refs": 0,
        "render_descriptor_refs": 0,
        "input_descriptor_refs": 0,
        "network_descriptor_refs": 0,
    }
    for descriptor in descriptors:
        refs = re.findall(r"L([^;]+);", descriptor)
        text = " ".join(refs + [descriptor])
        contexts = mappings.contexts_for_text(text)
        if contexts.intersection({"entity", "entityhitresult", "livingentity"}):
            counts["entity_descriptor_refs"] += 1
        if contexts.intersection({"player", "playerentity", "clientplayerentity"}):
            counts["player_descriptor_refs"] += 1
        if contexts.intersection({"render", "gamerenderer", "camera"}):
            counts["render_descriptor_refs"] += 1
        if contexts.intersection({"input", "mouse", "keyboard", "keybinding"}):
            counts["input_descriptor_refs"] += 1
        if contexts.intersection({"network", "clientconnection", "packet"}):
            counts["network_descriptor_refs"] += 1
    return counts
