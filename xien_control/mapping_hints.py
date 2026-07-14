from __future__ import annotations

from pathlib import Path

from .class_strings import tokens_for_text


BUILTIN_MAPPING_HINTS = {
    "class_310": "minecraftclient",
    "class_746": "clientplayerentity",
    "class_1657": "playerentity",
    "class_1309": "livingentity",
    "class_1297": "entity",
    "class_4184": "camera",
    "class_757": "gamerenderer",
    "class_638": "clientworld",
    "class_636": "clientplayerinteractionmanager",
    "class_239": "hitresult",
    "class_3966": "entityhitresult",
    "class_3675": "keyboard",
    "class_312": "mouse",
    # Minecraft 1.21.11 official namespace aliases used by behavior matching.
    "hio": "clientplayerinteractionmanager",
    "hnh": "clientplayerentity",
    "ddm": "playerentity",
    "cgk": "entity",
    "ftk": "hitresult",
    "chl": "livingentity",
    "cdb": "hand",
}

CONTEXT_GROUPS = {
    "entity": {"entity", "hitresult", "entityhitresult", "livingentity", "playerentity", "clientplayerentity"},
    "player": {"playerentity", "clientplayerentity"},
    "render": {"gamerenderer", "camera", "worldrenderer", "entityrenderer", "matrixstack"},
    "input": {"mouse", "keyboard", "keybinding"},
    "network": {"clientconnection", "clientplaynetworkhandler", "packet"},
}


class MappingHints:
    def __init__(self, roots: list[Path] | None = None):
        self.hints = dict(BUILTIN_MAPPING_HINTS)
        for root in roots or []:
            self._load_dir(root / "mappings")

    def contexts_for_text(self, text: str) -> set[str]:
        compact = "".join(tokens_for_text(text))
        contexts: set[str] = set()
        for needle, mapped in self.hints.items():
            if needle in compact or mapped in compact:
                contexts.add(mapped)
        for group, values in CONTEXT_GROUPS.items():
            if contexts.intersection(values) or any(value in compact for value in values):
                contexts.add(group)
        return contexts

    def _load_dir(self, path: Path) -> None:
        if not path.exists() or not path.is_dir():
            return
        for item in path.iterdir():
            if item.is_file() and item.suffix.lower() in {".tiny", ".mapping", ".mappings", ".txt"}:
                self._load_file(item)

    def _load_file(self, path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return
        for line in lines[:20000]:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            if parts[0] in {"CLASS", "c"}:
                left = parts[1].replace("/", "").replace(".", "").lower()
                right = parts[-1].replace("/", "").replace(".", "").lower()
                if left and right:
                    self.hints[left] = right
