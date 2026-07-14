from __future__ import annotations

from collections import Counter

from .class_strings import tokens_for_text
from .models import DetectionMatch, JarScanResult


SHADED_PREFIXES = {
    "com/google",
    "org/apache",
    "kotlin",
    "kotlinx",
    "com/mojang",
    "it/unimi",
    "com/github/oshi",
    "org/slf4j",
    "com/fasterxml",
}
LOADER_PREFIXES = {"net/fabricmc", "org/spongepowered", "net/minecraftforge", "org/quiltmc", "dev/architectury"}
MINECRAFT_PREFIXES = {"net/minecraft", "com/mojang"}


def classify_packages(result: JarScanResult) -> None:
    prefixes = Counter()
    class_names = result.class_references.keys() | result.class_feature_tokens.keys() | result.class_api_refs.keys() | result.class_roles.keys() | result.source_files.keys()
    for class_name in class_names:
        parts = class_name.split("/")
        if len(parts) >= 2:
            prefixes["/".join(parts[:2])] += 1
        if len(parts) >= 3:
            prefixes["/".join(parts[:3])] += 1
    entry_prefixes = {_prefix(item) for item in result.entrypoint_classes if item}
    metadata_tokens = set(tokens_for_text(" ".join([result.mod_id, result.mod_name, *result.build_metadata.values()])))
    for prefix, count in prefixes.items():
        role = "UNKNOWN"
        if any(prefix.startswith(item) for item in SHADED_PREFIXES):
            role = "SHADED_LIBRARY"
            result.shaded_library_prefixes.add(prefix)
        elif any(prefix.startswith(item) for item in LOADER_PREFIXES):
            role = "LOADER_LIBRARY"
        elif any(prefix.startswith(item) for item in MINECRAFT_PREFIXES):
            role = "MINECRAFT_API"
        elif prefix in entry_prefixes or set(tokens_for_text(prefix)).intersection(metadata_tokens) or count >= 3:
            role = "MOD_CODE"
            result.mod_owned_prefixes.add(prefix)
        result.package_classifications[prefix] = role
    for class_name in class_names:
        result.class_package_roles[class_name] = package_role_for_class(result, class_name)
    if any(role == "MOD_CODE" for role in result.class_package_roles.values()) and result.strong_evidence_count:
        _add_mod_owned_evidence(result)


def package_role_for_class(result: JarScanResult, class_name: str) -> str:
    parts = class_name.split("/")
    candidates = []
    if len(parts) >= 3:
        candidates.append("/".join(parts[:3]))
    if len(parts) >= 2:
        candidates.append("/".join(parts[:2]))
    for prefix in candidates:
        role = result.package_classifications.get(prefix)
        if role:
            return role
    return "UNKNOWN"


def _prefix(value: str) -> str:
    parts = value.split("/")
    return "/".join(parts[:3]) if len(parts) >= 3 else "/".join(parts[:2])


def _add_mod_owned_evidence(result: JarScanResult) -> None:
    if any(match.rule_id == "MOD_OWNED_FEATURE_EVIDENCE" for match in result.detections):
        return
    result.detections.append(
        DetectionMatch(
            rule_id="MOD_OWNED_FEATURE_EVIDENCE",
            rule_name="Mod-owned feature evidence",
            category="Ownership",
            severity="medium",
            confidence=0.72,
            matched_keyword="mod-owned package",
            source_type="ownership",
            evidence_preview="feature evidence appears in inferred mod-owned package, not shaded library code",
            explanation="Evidence is located in package prefixes inferred to belong to the mod itself rather than common shaded libraries.",
            context_type="package_ownership",
        )
    )
