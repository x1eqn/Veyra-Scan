from __future__ import annotations

import json
from pathlib import Path

from .models import Rule


RULES: tuple[Rule, ...] = (
    Rule(
        "COMBAT_TRIGGERBOT",
        "TriggerBot indicators",
        "Combat",
        "critical",
        ("triggerbot", "trigger bot", "auto aim click", "autoaimclick"),
        "Automated aiming/clicking combat feature names were found.",
        1.0,
    ),
    Rule(
        "COMBAT_KILLAURA",
        "KillAura indicators",
        "Combat",
        "critical",
        ("killaura", "kill aura", "aura module", "auramodule"),
        "KillAura style combat feature names were found.",
        1.0,
    ),
    Rule(
        "COMBAT_AIM",
        "Aim assist / aimbot indicators",
        "Combat",
        "critical",
        ("aimassist", "aim assist", "aimbot", "silent aim", "silentaim"),
        "Aim assist or silent aim feature names were found.",
        0.95,
    ),
    Rule(
        "COMBAT_REACH",
        "Reach indicators",
        "Combat",
        "high",
        ("reach", "extended reach", "reach module", "reachmod"),
        "Extended reach feature names were found.",
        0.85,
    ),
    Rule(
        "COMBAT_AUTOCLICKER",
        "AutoClicker indicators",
        "Combat",
        "high",
        ("autoclicker", "auto clicker", "cps boost", "cpsbooster", "clicker module"),
        "Auto clicker or CPS boost feature names were found.",
        0.85,
    ),
    Rule(
        "COMBAT_VELOCITY",
        "Velocity / knockback indicators",
        "Combat",
        "high",
        ("velocity", "antikb", "anti kb", "anti knockback", "knockback reducer"),
        "Velocity or knockback modification feature names were found.",
        0.8,
    ),
    Rule(
        "COMBAT_CRYSTAL",
        "Crystal PvP automation indicators",
        "Combat",
        "high",
        ("autocrystal", "auto crystal", "crystalaura", "crystal aura", "anchor aura", "anchoraura"),
        "Crystal or anchor combat automation feature names were found.",
        0.85,
    ),
    Rule(
        "COMBAT_CRITICALS",
        "Criticals indicators",
        "Combat",
        "medium",
        ("criticals", "critical hits", "packet criticals"),
        "Critical hit manipulation feature names were found.",
        0.65,
    ),
    Rule(
        "RENDER_XRAY",
        "XRay indicators",
        "Render",
        "high",
        ("xray", "x-ray", "x ray", "ore esp", "oreesp"),
        "XRay or ore visibility feature names were found.",
        0.8,
    ),
    Rule(
        "RENDER_ESP",
        "ESP indicators",
        "Render",
        "high",
        ("esp", "playeresp", "chestesp", "storageesp", "mobesp", "tracers", "wallhack"),
        "ESP, tracers, or wallhack style render feature names were found.",
        0.8,
    ),
    Rule(
        "RENDER_NAMETAGS_FULLBRIGHT",
        "Nametag / fullbright indicators",
        "Render",
        "low",
        ("nametags", "name tags", "fullbright"),
        "Player visibility or fullbright feature names were found.",
        0.55,
    ),
    Rule(
        "COMBAT_HURTCAM_MANIPULATION",
        "HurtCam manipulation indicators",
        "Combat Visual",
        "low",
        (
            "betterhurtcam",
            "better hurt cam",
            "nohurtcam",
            "no hurt cam",
            "disablehurtcam",
            "disable hurt cam",
            "changehurtcamtype",
            "change hurt cam type",
            "hurtcam multiplier",
            "tiltviewwhenhurt",
            "tilt view when hurt",
            "getdamagetiltyaw",
            "damage tilt yaw",
        ),
        "Hurt camera removal or manipulation indicators were found. This can be a competitive visual advantage depending on server rules.",
        0.45,
        "HurtCam mods are not malware; they are flagged because many PvP servers treat hurtcam manipulation as disallowed.",
    ),
    Rule(
        "MOVEMENT_FLY_SPEED",
        "Fly / speed indicators",
        "Movement",
        "high",
        ("flyhack", "fly hack", "flighthack", "speedhack", "speed module", "bhop", "bunnyhop"),
        "Flight, speed, or bunnyhop movement feature names were found.",
        0.8,
    ),
    Rule(
        "MOVEMENT_PHASE_NOCLIP",
        "Phase / noclip indicators",
        "Movement",
        "high",
        ("phase", "noclip", "no clip", "packetfly", "packet fly"),
        "Phase, noclip, or packet fly feature names were found.",
        0.75,
    ),
    Rule(
        "MOVEMENT_SCAFFOLD",
        "Scaffold / tower indicators",
        "Movement",
        "high",
        ("scaffold", "tower", "scaffoldwalk"),
        "Scaffold or tower movement/build feature names were found.",
        0.75,
    ),
    Rule(
        "MOVEMENT_MISC",
        "Other movement indicators",
        "Movement",
        "medium",
        ("jesus", "longjump", "long jump", "spider"),
        "Other movement bypass feature names were found.",
        0.6,
    ),
    Rule(
        "AUTOMATION_BARITONE",
        "Baritone indicators",
        "Automation",
        "medium",
        ("baritone", "baritone-api", "baritoneapi"),
        "Baritone automation was found. It may be allowed or disallowed depending on server rules.",
        0.55,
        "Baritone is not automatically malicious; server rules decide.",
    ),
    Rule(
        "AUTOMATION_NUKER_MINE",
        "Nuker / auto mine indicators",
        "Automation",
        "high",
        ("nuker", "auto mine", "automine", "auto tool", "autotool", "fastplace", "fast break", "fastbreak"),
        "Block automation or nuker feature names were found.",
        0.75,
    ),
    Rule(
        "CLIENT_SELF_DESTRUCT",
        "Self destruct / panic indicators",
        "Client",
        "critical",
        ("selfdestruct", "self destruct", "panic", "hide client", "ghost client", "ghostclient"),
        "Ghost client hiding or panic feature names were found.",
        1.0,
    ),
    Rule(
        "CLIENT_MENU_MODULES",
        "Client menu / module indicators",
        "Client",
        "medium",
        ("clickgui", "hudeditor", "hud editor", "modulemanager", "module manager", "clientbase", "hacked client", "hackclient"),
        "Client menu, module manager, or hacked client base names were found.",
        0.6,
    ),
    Rule(
        "CLIENT_BYPASS",
        "Bypass indicators",
        "Client",
        "high",
        ("bypass", "anticheat bypass", "anti cheat bypass", "mixin combat"),
        "Anti-cheat bypass or combat mixin terms were found.",
        0.75,
    ),
    Rule(
        "CLIENT_INJECTION_REFERENCE",
        "Injection reference",
        "Client",
        "info",
        ("inject", "injector", "mixin injection"),
        "Injection-related words were found inside a Minecraft jar.",
        0.25,
        "Mixin injection is normal in many Fabric/Forge mods; context matters.",
    ),
    Rule(
        "CLIENT_KNOWN_HACK_CLIENT",
        "Known hacked client identifiers",
        "Client",
        "critical",
        (
            "meteordevelopment/meteorclient",
            "meteorclient",
            "net/wurstclient",
            "liquidbounce",
            "ccbluex/liquidbounce",
            "rusherhack",
            "futureclient",
            "vapeclient",
            "entropy/client",
            "ravenbplus",
            "dripclient",
            "whiteout/client",
            "dreamclient",
            "riseclient",
            "sigmajello",
            "bleachhack",
            "forgehax",
            "earthhack",
            "phobos/client",
            "salhack",
            "konas/client",
            "gamesense/client",
            "thunderhack",
            "mathax/client",
            "redlotus",
            "slinky/client",
            "dopeclient",
            "novoline",
            "tenacity/client",
            "fdpclient",
            "zeroday",
        ),
        "Known hacked client package or string identifiers were found.",
        1.0,
    ),
    Rule(
        "CONFIG_SUSPICIOUS_SETTINGS",
        "Suspicious default settings",
        "Config",
        "medium",
        (
            "reachdistance",
            "reach distance",
            "attackrange",
            "attack range",
            "mincps",
            "maxcps",
            "aimspeed",
            "aim speed",
            "targetrange",
            "target range",
            "throughwalls",
            "through walls",
            "showinvisible",
            "show invisible",
            "velocitymode",
            "velocity mode",
            "autoblock",
            "auto block",
            "onlycritical",
            "only critical",
            "weapononly",
            "weapon only",
            "playersonly",
            "players only",
        ),
        "Suspicious combat/render configuration names were found inside jar metadata or bundled config files.",
        0.62,
        "Config-style words should be reviewed with nearby feature names.",
    ),
    Rule(
        "CLIENT_ANTICHEAT_REFERENCE",
        "Anticheat reference",
        "Client",
        "info",
        ("anticheat", "anti cheat"),
        "The jar references anti-cheat terms. This is a weak signal by itself.",
        0.2,
        "The word anticheat alone is not a cheating proof.",
    ),
)

RULE_BY_ID = {rule.rule_id: rule for rule in RULES}


def load_rules(search_roots: list[Path] | None = None) -> tuple[Rule, ...]:
    """Load built-in rules plus optional local rules.json overrides/additions."""
    rules_by_id = {rule.rule_id: rule for rule in RULES}
    for root in search_roots or [Path.cwd()]:
        path = root / "rules.json"
        if not path.exists() or not path.is_file():
            continue
        for rule in _read_rules_json(path):
            rules_by_id[rule.rule_id] = rule
    return tuple(rules_by_id.values())


def _read_rules_json(path: Path) -> list[Rule]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw_rules = data.get("rules", data) if isinstance(data, dict) else data
    if not isinstance(raw_rules, list):
        return []
    out: list[Rule] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            continue
        try:
            keywords = item.get("keywords", ())
            if isinstance(keywords, str):
                keywords = [keywords]
            rule = Rule(
                rule_id=str(item["rule_id"]),
                name=str(item.get("name") or item["rule_id"]),
                category=str(item.get("category") or "External"),
                severity=str(item.get("severity") or "low").lower(),
                keywords=tuple(str(value) for value in keywords if str(value).strip()),
                description=str(item.get("description") or "External rule indicator matched."),
                confidence_weight=float(item.get("confidence_weight", 0.6)),
                false_positive_note=str(item.get("false_positive_note") or ""),
            )
        except (KeyError, TypeError, ValueError):
            continue
        if rule.rule_id and rule.keywords:
            out.append(rule)
    return out
