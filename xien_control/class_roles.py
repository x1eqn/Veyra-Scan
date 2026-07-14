from __future__ import annotations

from .class_strings import tokens_for_text


def classify_class_role(class_name: str, refs: set[str], strings: list[str], annotations: set[str]) -> str:
    text = " ".join([class_name, *refs, *strings[:80], *annotations])
    tokens = set(tokens_for_text(text))
    compact = "".join(tokens)
    if tokens.intersection({"screen", "widget", "button", "slider", "checkbox", "dropdown", "panel", "modulebutton", "settingcomponent"}):
        return "CONFIG_SCREEN"
    if tokens.intersection({"setting", "booleansetting", "numbersetting", "modesetting", "keybindsetting", "option", "toggle"}):
        return "SETTING_CLASS"
    if tokens.intersection({"packet", "clientconnection", "networkhandler"}):
        return "PACKET_HANDLER"
    if tokens.intersection({"mouse", "keyboard", "keybinding", "click"}):
        return "INPUT_HANDLER"
    if tokens.intersection({"render", "worldrenderer", "entityrenderer", "matrixstack", "gamerenderer"}):
        return "RENDER_HANDLER"
    if tokens.intersection({"tick", "ontick", "clienttickevents", "update", "onupdate"}):
        return "TICK_HANDLER"
    if tokens.intersection({"module", "combat", "movement", "category"}) or "module" in compact:
        return "MODULE_CLASS"
    if len(tokens) <= 3:
        return "DATA_ONLY"
    return "UNKNOWN"
