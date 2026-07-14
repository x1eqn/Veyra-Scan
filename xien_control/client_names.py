from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher


CLIENT_NAMES = (
    "3arthh4ck", "aoba", "aristois", "astolfo", "augustus", "azura", "blackout",
    "bleachhack", "bloodyclient", "bluezenith", "boze", "breeze", "catlean",
    "cheetoclient", "chungushook", "corrosion", "crosssine", "crystalware", "diablo",
    "doomsday", "dopeclient", "dortware", "driplite", "dripx", "earthhack", "elementars",
    "entropyclient", "eternalclient", "exhibition", "explicitclient", "faxhax", "fdpclient",
    "forgehax", "fusionx", "gamesense", "ghostclient", "gucciclient", "hanabi", "hthclient",
    "huzuni", "impactplus", "inertiaclient", "iridiumclient", "itamiclient", "jexclient",
    "jigsawclient", "juulclient", "kamiblue", "karmaclient", "konasclient", "kuraclient",
    "limeclient", "liquidbounce", "liquidsense", "lowkeyclient", "memeware", "mioclient",
    "monsoon", "moonclient", "myauclient", "nhack", "nightx", "nodus", "novoline",
    "nullpoint", "nursultan", "oyvey", "pandaware", "phantomclient", "phobos", "ploow",
    "postmanclient", "prestigeclient", "pulsive", "pyroclient", "raion", "ravenb", "ravenbplus",
    "ravenbplusplus", "ravenclient", "remixclient", "resolute", "riseclient", "rootnet",
    "rusherhack", "salhack", "seppuku", "shoreline", "sigmajello", "sightclient", "skillclient",
    "skilledclient", "slinkyclient", "smokex", "sniperware", "spicyclient", "stitchclient",
    "strifeclient", "sumoclient", "tenacity", "thunderhack", "thunderware", "tiredclient",
    "trollsense", "vapeclient", "vapelite", "vestige", "vethack", "weepcraft", "whiteoutclient",
    "windhook", "wolframclient", "wurst", "wurstclient", "wurstplus", "xanax", "xatz", "xulu", "zeroday",
)

# These are real client names but also common programming/game words. They are
# only accepted when joined to an explicit client/hack identifier.
AMBIGUOUS_NAMES = {
    "alien", "ares", "coffee", "dream", "drip", "flux", "future", "grim", "impact", "kura",
    "meteor", "melon", "nova", "prestige", "rise", "rose", "sigma", "velocity", "vape",
}

# ``wurst`` is a real client name, but it is also used as an ordinary class,
# namespace, or sample word.  Only the explicit client forms are strong on
# their own; a bare structural token must carry client/hack context.
CONTEXT_REQUIRED_NAMES = {"wurst"}
CLIENT_CONTEXT_TOKENS = {
    "client", "hack", "hacks", "cheat", "cheats", "ghost", "module",
    "modules", "clickgui", "injector", "loader", "wurstclient", "wurstplus",
}


@dataclass(frozen=True)
class ClientNameMatch:
    family: str
    candidate: str
    kind: str
    similarity: float


def find_client_name_matches(values: list[str], allow_fuzzy: bool = True, strict_context: bool = False) -> list[ClientNameMatch]:
    aliases = {_normalize(item): item for item in CLIENT_NAMES}
    matches: list[ClientNameMatch] = []
    seen: set[str] = set()
    for value in values:
        for candidate in _candidates(value):
            if candidate in seen or len(candidate) < 5:
                continue
            seen.add(candidate)
            if candidate in aliases:
                if strict_context and candidate in CONTEXT_REQUIRED_NAMES and not _has_client_context(value):
                    continue
                matches.append(ClientNameMatch(aliases[candidate], candidate, "exact", 1.0))
                continue
            ambiguous = _ambiguous_family(candidate)
            if ambiguous:
                matches.append(ClientNameMatch(ambiguous, candidate, "exact-client-context", 1.0))
                continue
            if not allow_fuzzy:
                continue
            for normalized, family in aliases.items():
                if len(normalized) < 7 or abs(len(candidate) - len(normalized)) > 1 or candidate[0] != normalized[0]:
                    continue
                similarity = SequenceMatcher(None, candidate, normalized).ratio()
                if similarity >= 0.87:
                    matches.append(ClientNameMatch(family, candidate, "similar-name", similarity))
                    break
        if len(matches) >= 6:
            break
    return matches[:6]


def _has_client_context(value: str) -> bool:
    tokens = set(_candidates(value))
    return bool(tokens.intersection(CLIENT_CONTEXT_TOKENS))


def _ambiguous_family(candidate: str) -> str:
    for name in AMBIGUOUS_NAMES:
        if candidate in {f"{name}client", f"{name}hack", f"{name}hax"}:
            return f"{name} client"
    return ""


def _candidates(value: str) -> set[str]:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(value))
    pieces = [piece.lower() for piece in re.split(r"[^A-Za-z0-9+]+", value) if piece]
    output = {_normalize(piece) for piece in pieces}
    output.add(_normalize(value))
    for index in range(len(pieces) - 1):
        output.add(_normalize(pieces[index] + pieces[index + 1]))
    return {item for item in output if item}


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())
