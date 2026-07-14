from __future__ import annotations

from collections import defaultdict
import re

from .models import DetectionMatch, ExecutableScanResult, JarScanResult, RiskBreakdown
from .utils import clamp


SEVERITY_POINTS = {
    "info": 0,
    "low": 10,
    "medium": 25,
    "high": 50,
    "critical": 80,
}

VERDICT_THRESHOLDS = (
    (90, "CRITICAL"),
    (70, "HIGH_RISK"),
    (45, "SUSPICIOUS"),
    (20, "LOW_SIGNAL"),
    (0, "CLEAN"),
)

TRUSTED_MOD_PACKAGES = {
    "crash_assistant": ("dev/kostromdan/mods/crash_assistant",),
    "entityculling": ("dev/tr7zw/entityculling",),
    "fll": ("dev/x1eqn/fll",),
    "fzzy_config": ("me/fzzyhmstrs/fzzy_config",),
    "krypton": ("me/steinborn/krypton",),
    "lithium": ("net/caffeinemc/mods/lithium",),
    "nochatreports": ("com/aizistral/nochatreports",),
    "skyboxify": ("btw/lowercase/skyboxify",),
    "sodium-extra": ("me/flashyreese/mods/sodiumextra",),
    "sodium": ("net/caffeinemc/mods/sodium",),
    "moreculling": ("ca/fxco/moreculling",),
    "cloth-config": ("me/shedaniel/clothconfig2", "me/shedaniel/autoconfig"),
    "cloth_config": ("me/shedaniel/clothconfig2", "me/shedaniel/autoconfig"),
    "fabric-language-kotlin": ("net/fabricmc/language/kotlin", "org/jetbrains/kotlin"),
    "fabric_language_kotlin": ("net/fabricmc/language/kotlin", "org/jetbrains/kotlin"),
    "debugify": ("com/ishland/debugify", "dev/isxander/debugify"),
}


def verdict_for_score(score: int) -> str:
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return "CLEAN"


def calculate_jar_risk(result: JarScanResult) -> RiskBreakdown:
    if result.error:
        score = 25
        return RiskBreakdown(score=score, verdict=verdict_for_score(score), reasons=["Jar could not be fully read."])

    detections = result.detections
    if not detections:
        return RiskBreakdown(score=0, verdict="CLEAN", reasons=[])

    highest = max(SEVERITY_POINTS.get(item.severity, 0) for item in detections)
    score = highest
    reasons: list[str] = []

    unique_rules = {item.rule_id for item in detections}
    categories = {item.category for item in detections}
    source_by_rule: dict[str, set[str]] = defaultdict(set)
    severity_counts: dict[str, int] = defaultdict(int)

    for item in detections:
        source_by_rule[item.rule_id].add(item.source_type)
        severity_counts[item.severity] += 1

    if len(unique_rules) > 1:
        score += min(16, (len(unique_rules) - 1) * 4)
    if len(categories) > 1:
        score += min(10, (len(categories) - 1) * 3)
    strong_rule_ids = {item.rule_id for item in detections if item.severity in {"medium", "high", "critical"}}
    if any(rule_id in strong_rule_ids and {"class_path", "string"}.issubset(sources) for rule_id, sources in source_by_rule.items()):
        score += 10
        reasons.append("Same indicator appears in both class paths and readable strings.")
    if any({"class_path", "config"}.issubset(sources) or {"class_path", "translation"}.issubset(sources) for sources in source_by_rule.values()):
        score += 8
        reasons.append("Feature appears in both class paths and config/translation context.")
    if any(item.rule_id in {"MIXIN_TARGET_FEATURE_CONTEXT", "ACCESS_WIDENER_FEATURE_CONTEXT"} for item in detections):
        score += 12
        reasons.append("Feature indicator is tied to sensitive mixin/access-widener client targets.")
    if any(item.rule_id in {"ENTRYPOINT_NEAR_FEATURE", "ENTRYPOINT_MODULE_MANAGER_LINK", "MODULE_MANAGER_FEATURE_LINK"} for item in detections):
        score += 10
        reasons.append("Entrypoint/module graph connects to feature indicators.")
    if any(item.rule_id == "CLASS_GRAPH_FEATURE_CHAIN" for item in detections):
        score += 12
        reasons.append("Class dependency graph links entrypoint, module manager, feature, and client API context.")
    if any(item.rule_id == "NESTED_SUSPICIOUS_ARCHIVE" for item in detections):
        score += 14
        reasons.append("Suspicious indicators were found inside an embedded nested jar.")
    if any(item.rule_id == "MODULE_SYSTEM_SHAPE" and item.severity != "low" for item in detections):
        score += 6
        reasons.append("Module-system shape appears together with feature context.")
    if any(item.rule_id == "MOD_OWNED_FEATURE_EVIDENCE" for item in detections):
        score += 8
        reasons.append("Feature evidence appears in inferred mod-owned code rather than common shaded libraries.")
    if any(item.rule_id == "REACHABLE_FEATURE_CONTEXT" for item in detections):
        score += 8
        reasons.append("Feature-looking code is reachable from entrypoint or module manager context.")
    if any(item.rule_id in {"DESCRIPTOR_FEATURE_CONTEXT", "NUMERIC_FEATURE_CONTEXT", "ACTIVE_BYTECODE_FEATURE_CONTEXT"} for item in detections):
        score += 6
        reasons.append("Bytecode descriptor, numeric, or opcode context supports the feature finding.")
    if any(item.rule_id.startswith("TOKEN_VECTOR_") for item in detections):
        score += 5
        reasons.append("Token-vector density supports the feature category.")
    if result.correlation_notes and score >= 20:
        score += 5
        reasons.append("Related jar/fingerprint correlation increases review confidence.")
    if any(item.rule_id == "GUI_FEATURE_SETTING_CONTEXT" for item in detections):
        score += 6
        reasons.append("Feature appears in GUI/settings context.")
    if any(item.source_type == "heuristic" and item.rule_id == "RENAMED_SUSPICIOUS_JAR" for item in detections):
        score += 12
        reasons.append("File name looks harmless but internal content is suspicious.")
    if {"COMBAT_HURTCAM_MANIPULATION", "COMBO_HURTCAM_MANIPULATION"}.issubset(unique_rules):
        score += 8
        reasons.append("HurtCam manipulation appears in both direct strings and behavior context.")
    if {"BYTECODE_TBOT_AUTOMATION", "BYTECODE_JUMPRESET_BEHAVIOR"}.issubset(unique_rules):
        score += 12
        reasons.append("Bytecode shows both triggerbot-style combat automation and jump-reset behavior.")
    if "BYTECODE_SELF_RESTORE_OVERWRITE" in unique_rules:
        score += 8
        reasons.append("Bytecode can overwrite/restore its own jar from a remote source.")
    if "BYTECODE_TBOT_AUTOMATION" in unique_rules:
        score = max(score, 95)
        reasons.append("A same-class/method attack, target, swing, cooldown, and branch chain matches TriggerBot automation.")
    if result.obfuscation_ratio >= 0.45 and result.class_count >= 40:
        score += 8
        reasons.append("High density of very short class names.")
    if result.suspicious_package_hits >= 8:
        score += 5
        reasons.append("Suspicious package context appears repeatedly.")

    sources = {item.source_type for item in detections}
    if sources == {"filename"}:
        score = min(score, 20)
        reasons.append("Only the filename matched, so severity was downgraded.")
    if sources.issubset({"manifest"}) and not strong_rule_ids:
        score = min(score, 20)
        reasons.append("Only metadata text matched, so severity was downgraded.")
    if unique_rules == {"OBFUSCATED_RANDOM_CLASSES"}:
        score = min(score, 20)
        reasons.append("Only obfuscation density matched, so severity was downgraded.")
    if result.class_count <= 3 and not any(item.severity in {"high", "critical"} for item in detections):
        score = min(score, 20)
        reasons.append("Very small jar with weak evidence, so severity was downgraded.")
    support_only_sources = {"heuristic", "correlation", "vector", "numeric", "opcode", "descriptor", "signature", "zip", "version", "dependency", "ownership", "reachability", "graph"}
    material_sources = {
        item.source_type
        for item in detections
        if item.severity in {"medium", "high", "critical"}
    }
    if not material_sources:
        score = min(score, 19)
        reasons.append("Only informational/low-confidence observations matched, so no review verdict was produced.")
    strong_behavior_rules = {
        "BYTECODE_TBOT_AUTOMATION", "BYTECODE_SELF_RESTORE_OVERWRITE", "BYTECODE_SELF_DELETE",
        "BYTECODE_SELF_DESTRUCT_COMMAND", "BYTECODE_SELF_DESTRUCT_SHUTDOWN",
        "BYTECODE_ENCRYPTED_JAR_LOADER", "BYTECODE_REMOTE_PAYLOAD_LOADER", "BYTECODE_HWID_REMOTE_LOADER",
        "BYTECODE_AIMASSIST_BEHAVIOR", "BYTECODE_REACH_BEHAVIOR",
        "BYTECODE_VELOCITY_BEHAVIOR", "BYTECODE_AUTOCLICKER_BEHAVIOR",
        "BYTECODE_NATIVE_MEMORY_LOADER_BRIDGE", "BYTECODE_CONCEALED_AGENT_PAYLOAD_LOADER",
        "BYTECODE_CONNECTED_OPAQUE_LOADER_GRAPH",
        "DOOMSDAY_STRUCTURAL_FAMILY",
    }
    if material_sources and material_sources.issubset(support_only_sources) and not unique_rules.intersection(strong_behavior_rules):
        score = min(score, 25)
        reasons.append("Only support/context evidence matched, so severity was downgraded.")
    if result.feature_reachability == "ISOLATED" and score < 90:
        score = max(0, score - 12)
        reasons.append("Feature-looking class appears isolated from entrypoint/config/manager context.")
        active_sources = {"string", "config", "translation", "mixin", "access_widener", "descriptor", "numeric", "opcode", "reachability"}
        if not any(item.source_type in active_sources and item.severity in {"high", "critical"} for item in detections):
            score = min(score, 44)
            reasons.append("Isolated feature evidence was capped to avoid over-scoring unused/dead code.")
    if result.class_package_roles and result.shaded_library_prefixes:
        shaded_feature_classes = [
            name
            for name in result.class_feature_tokens
            if result.class_package_roles.get(name) == "SHADED_LIBRARY"
        ]
        if shaded_feature_classes and not result.mod_owned_prefixes and score < 70:
            score = max(0, score - 10)
            reasons.append("Feature-looking weak evidence is mostly in shaded library code.")
    if result.analysis_confidence == "Low" and score < 90:
        score = max(0, score - 12)
        reasons.append("Analysis confidence is low, so verdict was softened.")
    elif result.analysis_status == "PARTIAL_ANALYSIS" and score < 90:
        score = max(0, score - 6)
        reasons.append("Analysis was partial, so verdict was softened.")
    if result.known_hash_status == "clean":
        score = max(0, score - 20)
        reasons.append("Local known clean hash matched.")
    if result.allowlisted:
        score = max(0, score - 18)
        reasons.append("Local allowlist matched; finding was softened, not ignored.")

    mod_id_key = result.mod_id.lower().strip()
    expected_prefixes = TRUSTED_MOD_PACKAGES.get(mod_id_key, ())
    if not expected_prefixes:
        # Some Fabric metadata uses a loader-suffixed id (for example
        # ``moreculling-fabric``), while the jar filename remains the only
        # stable public identity. Resolve that suffix without trusting a
        # filename alone: the package-prefix check below is still required.
        identity_text = re.sub(r"[^a-z0-9]+", "", f"{result.file_name} {result.mod_name} {mod_id_key}")
        for trusted_key, prefixes in TRUSTED_MOD_PACKAGES.items():
            trusted_token = re.sub(r"[^a-z0-9]+", "", trusted_key)
            if trusted_token and trusted_token in identity_text:
                expected_prefixes = prefixes
                break
    class_names = set(result.class_references) | set(result.class_roles) | set(result.class_package_roles)
    # Some class parsers do not retain a class in the final reference index,
    # while the detection still has the exact class coordinate. Include those
    # coordinates so trusted-package recognition uses the same evidence the
    # user sees in the report (for example MoreCulling config.cloth classes).
    class_names.update(
        item.class_name
        for item in detections
        if getattr(item, "class_name", "")
    )
    # Class indexes can be emitted as JVM slash paths or Java dotted names.
    # Compare both forms identically so trusted public libraries are not
    # penalized merely because the parser chose a different representation.
    normalized_class_names = {
        str(name).replace("\\", "/").replace(".", "/").lower().lstrip("/")
        for name in class_names
    }
    normalized_prefixes = tuple(prefix.lower().replace("\\", "/").strip("/") for prefix in expected_prefixes)
    trusted_identity = bool(normalized_prefixes) and any(
        any(name == prefix or name.startswith(prefix + "/") for prefix in normalized_prefixes)
        for name in normalized_class_names
    )
    decisive_rules = {
        item.rule_id
        for item in detections
        if item.rule_id in strong_behavior_rules
        or item.rule_id in {"KNOWN_CLIENT_NAME_EXACT", "CLIENT_KNOWN_HACK_CLIENT", "CLIENT_SELF_DESTRUCT", "LOCAL_HASH_KNOWN_BLOCKED"}
    }
    if result.modrinth_verified and not decisive_rules:
        # An exact Modrinth file hash is a strong identity signal. Keep the local
        # analysis and all evidence in the report, but prevent ordinary library,
        # GUI, or obfuscation context from making a verified public mod appear as
        # a review item. Decisive runtime/client behavior remains visible.
        score = min(score, 19)
        reasons.append("Exact Modrinth file hash matched; non-behavioral context was downgraded.")
    if trusted_identity and not decisive_rules:
        score = min(score, 19)
        reasons.append("Known legitimate mod identity/package matched and no behavioral or exact client-family evidence was found.")

    if "DOOMSDAY_STRUCTURAL_FAMILY" in unique_rules:
        score = max(score, 99)
        reasons.insert(0, "Internal loader structure matches the Doomsday concealed-client family independently of the filename.")
    elif "BYTECODE_CONCEALED_AGENT_PAYLOAD_LOADER" in unique_rules:
        score = max(score, 96)
        reasons.insert(0, "Correlated Java-agent, opaque payload, direct class-loading, and native-memory behaviour is decisive.")
    elif "BYTECODE_CONNECTED_OPAQUE_LOADER_GRAPH" in unique_rules:
        score = max(score, 94)
        reasons.insert(0, "Entrypoint, opaque payload loader, raw transport, and native-memory classes form one connected executable graph.")

    if severity_counts.get("critical"):
        reasons.append(f"{severity_counts['critical']} critical indicator(s).")
    if severity_counts.get("high"):
        reasons.append(f"{severity_counts['high']} high indicator(s).")
    if severity_counts.get("medium"):
        reasons.append(f"{severity_counts['medium']} medium indicator(s).")

    score = clamp(score)
    return RiskBreakdown(score=score, verdict=verdict_for_score(score), reasons=reasons[:5])


def scan_status(results: list[JarScanResult], executables: list[ExecutableScanResult] | None = None) -> str:
    verdicts = {item.verdict for item in results}
    if executables:
        verdicts.update(item.verdict for item in executables)
    if verdicts.intersection({"CRITICAL", "HIGH_RISK", "HIGH_REVIEW", "CRITICAL_REVIEW"}):
        return "SUSPICIOUS_FOUND"
    if verdicts.intersection({"SUSPICIOUS", "REVIEW"}):
        return "REVIEW_NEEDED"
    return "CLEAN"


def detection_sort_key(match: DetectionMatch) -> tuple[int, str, str]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return (order.get(match.severity, 9), match.category, match.rule_name)
