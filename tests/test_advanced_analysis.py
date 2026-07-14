from __future__ import annotations

import datetime as dt
import io
import json
import zipfile

from xien_control.artifact_db import ArtifactDatabase
from xien_control.bytecode import BytecodeAnalysis, MethodBytecodeBehavior
from xien_control.jar_scanner import JarScanner
from xien_control.models import DetectionMatch, JarScanResult, LauncherLocation
from xien_control.risk import calculate_jar_risk


def test_nested_jar_detection(tmp_path):
    child = io.BytesIO()
    with zipfile.ZipFile(child, "w") as jar:
        jar.writestr("com/xien/modules/combat/KillAura.class", _class_bytes("KillAura", "module.combat.killaura.name"))
    parent = tmp_path / "fps_booster.jar"
    with zipfile.ZipFile(parent, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "fps_booster", "entrypoints": {"client": ["com.xien.Main"]}}))
        jar.writestr("META-INF/jars/core-helper.jar", child.getvalue())

    result = _scanner(tmp_path).scan(parent, _location(tmp_path))

    assert any(match.rule_id == "NESTED_SUSPICIOUS_ARCHIVE" for match in result.detections)
    assert result.nested_results


def test_non_standard_extension_archive(tmp_path):
    path = tmp_path / "example.jar.disabled"
    _write_feature_jar(path)

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert result.non_standard_archive is True
    assert result.archive_type == "java_archive_nonstandard_extension"


def test_deep_audit_ignores_documentation_marker_but_keeps_code_marker(tmp_path):
    path = tmp_path / "ordinary.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("README.txt", "This project discusses freecam compatibility in its documentation.")
        jar.writestr("com/example/Freecam.class", _class_bytes("Freecam"))

    scanner = _scanner(tmp_path)
    result = scanner.scan(path, _location(tmp_path))
    audited = scanner.deep_audit(path, result)

    assert any("Freecam.class" in hit for hit in audited.deep_audit_feature_hits)
    assert not any("README.txt" in hit for hit in audited.deep_audit_feature_hits)


def test_deep_audit_downgrades_generic_class_string_without_feature_path(tmp_path):
    path = tmp_path / "ordinary.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("com/example/Utility.class", _class_bytes("freecam compatibility text"))

    scanner = _scanner(tmp_path)
    audited = scanner.deep_audit(path, scanner.scan(path, _location(tmp_path)))

    matches = [item for item in audited.detections if item.rule_id == "DEEP_AUDIT_FEATURE_STRING" and item.matched_keyword == "freecam"]
    assert matches and all(item.severity == "medium" for item in matches)


def test_bare_wurst_class_name_is_not_a_known_client_identity(tmp_path):
    path = tmp_path / "ordinary.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "ordinary", "name": "Ordinary"}))
        jar.writestr("com/example/Wurst.class", _class_bytes("Example class"))

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert not any(match.rule_id.startswith("KNOWN_CLIENT_NAME") for match in result.detections)


def test_mixin_target_context(tmp_path):
    path = tmp_path / "reach-helper.jar"
    _write_feature_jar(path, mixin=True)

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert any(match.rule_id in {"MIXIN_TARGET_FEATURE_CONTEXT", "MIXIN_INJECTION_FEATURE_TARGET"} for match in result.detections)


def test_structural_fingerprint_rename_similarity(tmp_path):
    first = tmp_path / "fps.jar"
    second = tmp_path / "core-helper.jar"
    _write_feature_jar(first)
    _write_feature_jar(second)
    scanner = _scanner(tmp_path)

    left = scanner.scan(first, _location(tmp_path))
    right = scanner.scan(second, _location(tmp_path))

    assert left.structure_fingerprint
    assert left.structure_fingerprint == right.structure_fingerprint


def test_previous_scan_diff_new_jar(tmp_path):
    first = tmp_path / "clean.jar"
    second = tmp_path / "new.jar"
    _write_clean_jar(first)
    scanner = _scanner(tmp_path)
    clean = scanner.scan(first, _location(tmp_path))
    db = ArtifactDatabase(tmp_path / "cache")
    db.update([clean])
    db.save()

    _write_feature_jar(second)
    suspicious = scanner.scan(second, _location(tmp_path))
    db2 = ArtifactDatabase(tmp_path / "cache")
    diff = db2.compare_previous([clean, suspicious])

    assert diff["new"] == 1
    assert "Recently added suspicious jar" in " ".join(diff["important"])


def test_cache_reuse(tmp_path):
    path = tmp_path / "cached.jar"
    _write_feature_jar(path)
    scanner = JarScanner(cache_dir=tmp_path / "cache")
    location = _location(tmp_path)

    first = scanner.scan(path, location)
    second = scanner.scan(path, location)

    assert first.cache_reused is False
    assert second.cache_reused is True


def test_resource_lang_evidence(tmp_path):
    path = tmp_path / "lang.jar"
    _write_feature_jar(path, lang=True)

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert any(match.rule_id == "TRANSLATION_FEATURE_CONTEXT" for match in result.detections)


def test_metadata_build_mismatch(tmp_path):
    path = tmp_path / "performance.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "performance", "name": "Performance"}))
        jar.writestr("META-INF/maven/com/test/reach-core/pom.properties", "groupId=com.test\nartifactId=reach-core\nversion=1.0\n")
        jar.writestr("com/test/modules/combat/Reach.class", _class_bytes("Reach", "module.combat.reach.name"))

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert any(match.rule_id == "BUILD_METADATA_CONTENT_MISMATCH" for match in result.detections)


def test_partial_analysis_flag(tmp_path, monkeypatch):
    from xien_control import jar_scanner as jar_scanner_module

    path = tmp_path / "partial.jar"
    _write_feature_jar(path)
    monkeypatch.setattr(jar_scanner_module, "MAX_CLASS_BYTES_PER_JAR", 1)

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert result.analysis_status == "PARTIAL_ANALYSIS"


def test_false_positive_guard_speed_word(tmp_path):
    path = tmp_path / "notes.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "notes", "name": "Notes"}))
        jar.writestr("com/example/Notes.class", _class_bytes("speed"))

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert result.verdict in {"CLEAN", "LOW_SIGNAL"}


def test_render_mixin_is_not_a_cheat_feature(tmp_path):
    path = tmp_path / "animatium.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr(
            "fabric.mod.json",
            json.dumps({"id": "animatium", "environment": "client", "entrypoints": {"client": ["org.visuals.animatium.AnimatiumClient"]}, "mixins": ["animatium.mixins.json"]}),
        )
        jar.writestr("animatium.mixins.json", json.dumps({"package": "org.visuals.animatium.mixins", "client": ["GameRendererAccessor"]}))
        jar.writestr("org/visuals/animatium/AnimatiumClient.class", _class_bytes("ClientModInitializer"))
        jar.writestr("org/visuals/animatium/mixins/GameRendererAccessor.class", _class_bytes("net/minecraft/client/render/GameRenderer", "Accessor"))

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert result.verdict in {"CLEAN", "LOW_SIGNAL"}
    assert not any(match.rule_id in {"MIXIN_TARGET_FEATURE_CONTEXT", "ENTRYPOINT_NEAR_FEATURE"} for match in result.detections)


def test_entrypoint_render_helper_is_not_a_feature(tmp_path):
    path = tmp_path / "appleskin.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr(
            "fabric.mod.json",
            json.dumps({"id": "appleskin", "environment": "client", "entrypoints": {"client": ["squeek.appleskin.AppleSkin"]}}),
        )
        jar.writestr("squeek/appleskin/AppleSkin.class", _class_bytes("ClientModInitializer"))
        jar.writestr("squeek/appleskin/mixin/JEIRenderHelperMixin.class", _class_bytes("JEIRenderHelperMixin.java", "net/minecraft/client/gui/DrawContext"))

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert result.verdict in {"CLEAN", "LOW_SIGNAL"}
    assert not any(match.rule_id == "ENTRYPOINT_NEAR_FEATURE" for match in result.detections)


def test_normal_feature_config_screen_is_not_labeled_cheat_gui(tmp_path):
    path = tmp_path / "visual-settings.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "visualsettings", "name": "Visual Settings"}))
        jar.writestr("dev/visual/ConfigScreen.class", _class_bytes("Fullbright enabled mode smooth players"))

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert not any(match.rule_id in {"GUI_FEATURE_SETTING_CONTEXT", "GUI_MODULE_UI_CONTEXT"} for match in result.detections)


def test_cheat_feature_specific_gui_pair_is_detected(tmp_path):
    path = tmp_path / "client-menu.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "clientmenu", "name": "Client Menu"}))
        jar.writestr("client/gui/CombatScreen.class", _class_bytes("Reach combat module range targets walls"))

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert any(match.rule_id == "GUI_FEATURE_SETTING_CONTEXT" for match in result.detections)


def test_obfuscated_triggerbot_behavior_chain_is_critical(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "a.jar")
    method = MethodBytecodeBehavior(
        name="a",
        method_refs=["hio.a(Lddm;Lcgk;)V", "chl.a(Lcdb;)V", "ddm.I(F)F"],
        class_refs=["ftk"],
        conditional_branches=3,
    )
    analysis = BytecodeAnalysis(
        parsed=True,
        method_refs=list(method.method_refs),
        class_refs=list(method.class_refs),
        conditional_branches=3,
        methods=[method],
    )

    scanner._scan_bytecode_behavior(result, analysis, "a/b.class")
    breakdown = calculate_jar_risk(result)

    assert any(match.rule_id == "BYTECODE_TBOT_AUTOMATION" for match in result.detections)
    assert breakdown.verdict == "CRITICAL"
    assert breakdown.score >= 95


def test_attack_reference_without_full_triggerbot_chain_is_not_flagged(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "combat-helper.jar")
    method = MethodBytecodeBehavior(
        name="onAttack",
        method_refs=["net/minecraft/client/network/ClientPlayerInteractionManager.attackEntity(Lnet/minecraft/entity/player/PlayerEntity;Lnet/minecraft/entity/Entity;)V"],
        conditional_branches=1,
    )
    analysis = BytecodeAnalysis(parsed=True, method_refs=list(method.method_refs), conditional_branches=1, methods=[method])

    scanner._scan_bytecode_behavior(result, analysis, "com/example/CombatHelper.class")

    assert not any(match.rule_id == "BYTECODE_TBOT_AUTOMATION" for match in result.detections)


def test_version_neutral_obfuscated_triggerbot_shape_is_detected(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "unknown-version.jar")
    method = MethodBytecodeBehavior(
        name="a",
        method_refs=["x.a(Lp;Le;)V", "p.b(F)F", "q.c(Lh;)V"],
        field_refs=["m.dLt;"],
        conditional_branches=4,
    )
    analysis = BytecodeAnalysis(
        parsed=True,
        method_refs=list(method.method_refs),
        field_refs=list(method.field_refs),
        conditional_branches=4,
        methods=[method],
    )

    scanner._scan_bytecode_behavior(result, analysis, "a/a.class")
    breakdown = calculate_jar_risk(result)

    assert any(match.rule_id == "BYTECODE_TBOT_AUTOMATION" for match in result.detections)
    assert breakdown.verdict == "CRITICAL"


def test_version_neutral_shape_requires_target_field_and_branches(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "normal-combat.jar")
    method = MethodBytecodeBehavior(
        name="a",
        method_refs=["x.a(Lp;Le;)V", "p.b(F)F", "q.c(Lh;)V"],
        conditional_branches=1,
    )
    analysis = BytecodeAnalysis(parsed=True, method_refs=list(method.method_refs), conditional_branches=1, methods=[method])

    scanner._scan_bytecode_behavior(result, analysis, "normal/Combat.class")

    assert not any(match.rule_id == "BYTECODE_TBOT_AUTOMATION" for match in result.detections)


def test_version_neutral_aimassist_behavior(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "aim.jar")
    method = MethodBytecodeBehavior(
        name="a",
        method_refs=["java/lang/Math.atan2(DD)D", "p.a(F)V", "p.b(F)V"],
        field_refs=["m.tLx;"],
        conditional_branches=2,
    )
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "a/A.class")
    assert any(match.rule_id == "BYTECODE_AIMASSIST_BEHAVIOR" for match in result.detections)


def test_version_neutral_reach_behavior(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "reach.jar")
    method = MethodBytecodeBehavior(
        name="b",
        method_refs=["e.d(Le;)D", "r.a(DDZ)Lh;"],
        field_refs=["m.tLh;"],
        numeric_constants=[4.5],
        conditional_branches=2,
    )
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "b/B.class")
    assert any(match.rule_id == "BYTECODE_REACH_BEHAVIOR" for match in result.detections)


def test_version_neutral_velocity_behavior(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "velocity.jar")
    method = MethodBytecodeBehavior(
        name="c",
        method_refs=["p.a(DDD)V", "v.a()I", "v.b()I", "v.c()I"],
        field_refs=["m.packetLv;"],
        numeric_constants=[0.6],
        conditional_branches=2,
    )
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "c/C.class")
    assert any(match.rule_id == "BYTECODE_VELOCITY_BEHAVIOR" for match in result.detections)


def test_render_culling_method_does_not_match_neutral_velocity_shape(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "moreculling.jar")
    method = MethodBytecodeBehavior(
        name="moreculling$optimizedRender",
        method_refs=["p.a(DDD)V", "v.a()I", "v.b()I", "v.c()I"],
        field_refs=["m.packetLv;"],
        numeric_constants=[0.6],
        conditional_branches=17,
    )

    scanner._scan_bytecode_behavior(
        result,
        BytecodeAnalysis(parsed=True, methods=[method]),
        "ca/fxco/moreculling/mixin/entities/ItemFrameRenderer_cullMixin.class",
    )

    assert not any(match.rule_id == "BYTECODE_VELOCITY_BEHAVIOR" for match in result.detections)


def test_version_neutral_autoclicker_behavior(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "clicker.jar")
    method = MethodBytecodeBehavior(
        name="d",
        method_refs=["java/lang/System.currentTimeMillis()J", "java/util/Random.nextInt(I)I", "x.doAttack()Z"],
        numeric_constants=[12.0],
        conditional_branches=2,
    )
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "d/D.class")
    assert any(match.rule_id == "BYTECODE_AUTOCLICKER_BEHAVIOR" for match in result.detections)


def test_normal_timed_gui_method_does_not_match_combat_behaviors(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "gui.jar")
    method = MethodBytecodeBehavior(
        name="render",
        method_refs=["java/lang/System.currentTimeMillis()J", "screen.render()V"],
        numeric_constants=[12.0],
        conditional_branches=2,
    )
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "ui/Screen.class")
    behavior_rules = {"BYTECODE_AIMASSIST_BEHAVIOR", "BYTECODE_REACH_BEHAVIOR", "BYTECODE_VELOCITY_BEHAVIOR", "BYTECODE_AUTOCLICKER_BEHAVIOR"}
    assert not any(match.rule_id in behavior_rules for match in result.detections)


def test_trusted_sodium_identity_softens_context_only_false_positive(tmp_path):
    result = _empty_result(tmp_path / "sodium.jar")
    result.mod_id = "sodium"
    result.class_references["net/caffeinemc/mods/sodium/client/render/Test"] = {"net/minecraft/client/render"}
    result.detections.append(DetectionMatch("RENDER_XRAY", "XRay", "Render", "critical", 0.8, "xray", "translation", "option text", "context"))

    breakdown = calculate_jar_risk(result)

    assert breakdown.verdict == "CLEAN"
    assert breakdown.score <= 19


def test_trusted_public_config_and_optimization_packages_soften_dotted_class_paths(tmp_path):
    for mod_id, class_name in (
        ("cloth-config", "me.shedaniel.clothconfig2.fabric.ClothConfigModMenuDemo"),
        ("fabric-language-kotlin", "net.fabricmc.language.kotlin.KotlinAdapter"),
        ("moreculling", "ca.fxco.moreculling.config.cloth.DynamicEnumEntry"),
        ("debugify", "com.ishland.debugify.Debugify"),
    ):
        result = _empty_result(tmp_path / f"{mod_id}.jar")
        result.mod_id = mod_id
        result.class_references[class_name] = {"net/minecraft/client/gui/screen/Screen"}
        result.detections.append(DetectionMatch("BYTECODE_METHOD_FIELD_SIGNAL", "Suspicious method/field naming", "Bytecode", "low", 0.35, "register", "string", f"{class_name}: constant_pool contains register", "weak"))
        result.detections.append(DetectionMatch("RESOURCE_SEMANTIC_CONTEXT", "Resource semantic context", "Resource", "medium", 0.62, "resource feature path", "resource", "me.shedaniel.autoconfig.gui.registry", "support"))

        breakdown = calculate_jar_risk(result)

        assert breakdown.score <= 19
        assert breakdown.verdict == "CLEAN"


def test_trusted_loader_suffixed_filename_still_requires_matching_package(tmp_path):
    result = _empty_result(tmp_path / "moreculling-fabric-1.21.11.jar")
    result.class_references["ca.fxco.moreculling.config.cloth.DynamicEnumEntry"] = set()
    result.detections.append(DetectionMatch("RESOURCE_SEMANTIC_CONTEXT", "Resource semantic context", "Resource", "medium", 0.62, "resource feature path", "resource", "config/cloth", "support"))

    breakdown = calculate_jar_risk(result)

    assert breakdown.score <= 19
    assert breakdown.verdict == "CLEAN"


def test_moreculling_trust_uses_detection_class_when_class_index_omits_it(tmp_path):
    result = _empty_result(tmp_path / "moreculling-fabric-1.21.11-1.6.2.jar")
    result.analysis_confidence = "High"
    result.analysis_status = "FULL_ANALYSIS"
    result.detections.extend([
        DetectionMatch(
            "BYTECODE_METHOD_FIELD_SIGNAL", "Suspicious method/field naming", "Bytecode", "low", 0.35,
            "dynamic", "string", "ca/fxco/moreculling/config/cloth/DynamicEnumEntry.class: dynamic",
            "A weak method or field name was found.", "method_like",
            class_name="ca.fxco.moreculling.config.cloth.DynamicEnumEntry",
        ),
        DetectionMatch(
            "MOD_OWNED_FEATURE_EVIDENCE", "Mod owned feature evidence", "Ownership", "high", 0.7,
            "feature", "ownership", "package classified as mod owned", "Support-only ownership context.",
        ),
        DetectionMatch(
            "RENAMED_SUSPICIOUS_JAR", "Possible renamed suspicious jar", "Heuristic", "high", 0.7,
            "safe filename", "heuristic", "moreculling", "Support-only heuristic.",
        ),
    ])

    breakdown = calculate_jar_risk(result)

    assert breakdown.score <= 19
    assert breakdown.verdict == "CLEAN"


def test_own_jar_delete_is_critical_self_destruct(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "hidden.jar")
    method = MethodBytecodeBehavior(
        name="x",
        method_refs=["java/lang/Class.getProtectionDomain()Ljava/security/ProtectionDomain;", "java/security/CodeSource.getLocation()Ljava/net/URL;", "java/io/File.delete()Z"],
    )
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "a/A.class")
    assert any(match.rule_id == "BYTECODE_SELF_DELETE" and match.severity == "critical" for match in result.detections)


def test_remote_own_jar_replacement_and_timestamp_restore(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "restore.jar")
    method = MethodBytecodeBehavior(
        name="y",
        method_refs=["java/lang/Class.getProtectionDomain()Ljava/security/ProtectionDomain;", "java/security/CodeSource.getLocation()Ljava/net/URL;", "java/net/URL.openStream()Ljava/io/InputStream;", "java/io/FileOutputStream.<init>(Ljava/io/File;)V", "java/io/File.setLastModified(J)Z"],
    )
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "b/B.class")
    assert any(match.rule_id == "BYTECODE_SELF_RESTORE_OVERWRITE" and match.severity == "critical" for match in result.detections)


def test_normal_config_file_delete_is_not_self_destruct(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "normal.jar")
    method = MethodBytecodeBehavior(name="clearConfig", method_refs=["java/io/File.delete()Z"])
    scanner._scan_bytecode_behavior(result, BytecodeAnalysis(parsed=True, methods=[method]), "config/Cleaner.class")
    assert not any(match.rule_id.startswith("BYTECODE_SELF_") for match in result.detections)


def test_encrypted_in_memory_jar_loader_is_critical(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "loader.jar")
    analysis = BytecodeAnalysis(
        parsed=True,
        method_refs=[
            "javax/crypto/Cipher.doFinal([B)[B",
            "java/util/jar/JarInputStream.getNextJarEntry()Ljava/util/jar/JarEntry;",
            "x.defineClass(Ljava/lang/String;[BII)Ljava/lang/Class;",
            "java/lang/ClassLoader.findClass(Ljava/lang/String;)Ljava/lang/Class;",
        ],
    )
    scanner._scan_bytecode_behavior(result, analysis, "x/Loader.class")
    assert any(match.rule_id == "BYTECODE_ENCRYPTED_JAR_LOADER" and match.severity == "critical" for match in result.detections)


def test_remote_byte_payload_reflection_loader_is_critical(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "remote-loader.jar")
    analysis = BytecodeAnalysis(
        parsed=True,
        method_refs=[
            "java/net/http/HttpClient.send(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/net/http/HttpResponse;",
            "java/net/http/HttpResponse$BodyHandlers.ofByteArray()Ljava/net/http/HttpResponse$BodyHandler;",
            "net/fabricmc/loader/impl/launch/FabricLauncher.getTargetClassLoader()Ljava/lang/ClassLoader;",
            "java/lang/Class.loadClass(Ljava/lang/String;)Ljava/lang/Class;",
            "java/lang/reflect/Constructor.newInstance([Ljava/lang/Object;)Ljava/lang/Object;",
            "java/lang/reflect/Method.invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
        ],
    )
    scanner._scan_bytecode_behavior(result, analysis, "x/Init.class")
    assert any(match.rule_id == "BYTECODE_REMOTE_PAYLOAD_LOADER" and match.severity == "critical" for match in result.detections)


def test_doomsday_internal_layout_is_critical_independent_of_filename(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "ordinary-performance-name.jar")
    result.mod_id = "dd"
    result.java_agent_manifest = True
    result.java_agent_retransform = True
    result.metadata_files_found = ["fabric.mod.json", "META-INF/mods.toml", "mcmod.info", "META-INF/MANIFEST.MF"]
    result.class_count = 11
    result.obfuscation_ratio = 1.0
    result.opaque_payload_paths = ["000", "64FV7P4H2NO7Q", *(f"net/java/{letter}" for letter in "abcde")]
    result.opaque_payload_bytes = 5_100_000
    result.opaque_payload_high_entropy = 6
    result.opaque_payload_zero_filled = 1

    scanner._scan_bytecode_behavior(
        result,
        BytecodeAnalysis(
            parsed=True,
            method_refs=[
                "java/lang/ClassLoader.loadClass(Ljava/lang/String;)Ljava/lang/Class;",
                "net/java/m.defineClass(Ljava/lang/String;[BII)Ljava/lang/Class;",
            ],
            class_refs=["java/lang/ClassLoader"],
            string_literals=["/64FV7P4H2NO7Q", "/net/java/a", "/net/java/b"],
        ),
        "net/java/m.class",
    )
    scanner._scan_bytecode_behavior(
        result,
        BytecodeAnalysis(
            parsed=True,
            method_refs=[
                "com/sun/jna/NativeLibrary.getInstance(Ljava/lang/String;)Lcom/sun/jna/NativeLibrary;",
                "com/sun/jna/NativeLibrary.getFunction(Ljava/lang/String;)Lcom/sun/jna/Function;",
                "com/sun/jna/Pointer.read(J[BII)V",
                "com/sun/jna/Pointer.write(J[BII)V",
                "java/lang/Runtime.exec([Ljava/lang/String;)Ljava/lang/Process;",
            ],
            class_refs=["com/sun/jna/Pointer", "com/sun/jna/Memory"],
        ),
        "net/java/g.class",
    )
    scanner._scan_bytecode_behavior(
        result,
        BytecodeAnalysis(
            parsed=True,
            method_refs=[
                "java/nio/channels/SocketChannel.open()Ljava/nio/channels/SocketChannel;",
                "java/io/RandomAccessFile.read([B)I",
                "java/lang/Class.getResourceAsStream(Ljava/lang/String;)Ljava/io/InputStream;",
            ],
        ),
        "net/java/l.class",
    )
    result.class_references = {
        "net/java/m": {"net/java/l"},
        "net/java/l": {"net/java/g"},
        "net/java/g": set(),
    }
    result.entrypoint_classes = {"net/java/m"}
    scanner._apply_loader_context_heuristics(result)
    breakdown = calculate_jar_risk(result)

    assert result.family_id == "doomsday-concealed-loader"
    assert any(match.rule_id == "DOOMSDAY_STRUCTURAL_FAMILY" for match in result.detections)
    assert breakdown.verdict == "CRITICAL"
    assert breakdown.score >= 99


def test_extensionless_class_payload_magic_is_reported(tmp_path):
    path = tmp_path / "hidden-payload.jar"
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "hiddenpayload"}))
        jar.writestr("payload/core", b"\xca\xfe\xba\xbe" + b"\x00" * 8192)

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert result.opaque_payload_formats["payload/core"] == "JVM class"
    assert any(match.rule_id == "HIDDEN_EXECUTABLE_RESOURCE" for match in result.detections)


def test_custom_agent_loader_without_native_bridge_is_not_doomsday(tmp_path):
    scanner = _scanner(tmp_path)
    result = _empty_result(tmp_path / "ordinary-agent.jar")
    result.java_agent_manifest = True
    result.java_agent_retransform = True
    result.class_count = 12
    result.obfuscation_ratio = 0.9
    result.opaque_payload_paths = [f"payload/{letter}" for letter in "abcd"]
    result.opaque_payload_bytes = 900_000
    result.opaque_payload_high_entropy = 4
    scanner._scan_bytecode_behavior(
        result,
        BytecodeAnalysis(
            parsed=True,
            method_refs=[
                "java/lang/ClassLoader.loadClass(Ljava/lang/String;)Ljava/lang/Class;",
                "example/Loader.defineClass(Ljava/lang/String;[BII)Ljava/lang/Class;",
            ],
            class_refs=["java/lang/ClassLoader"],
            string_literals=["/payload/a"],
        ),
        "example/Loader.class",
    )

    scanner._apply_loader_context_heuristics(result)
    breakdown = calculate_jar_risk(result)

    assert not any(match.rule_id in {"DOOMSDAY_STRUCTURAL_FAMILY", "BYTECODE_CONCEALED_AGENT_PAYLOAD_LOADER"} for match in result.detections)
    assert breakdown.verdict != "CRITICAL"


def test_extensionless_high_entropy_payloads_are_inventoried(tmp_path):
    path = tmp_path / "packed.jar"
    high_entropy = bytes(range(256)) * 32
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "packed"}))
        for letter in "abcd":
            jar.writestr(f"payload/{letter}", high_entropy)

    result = _scanner(tmp_path).scan(path, _location(tmp_path))

    assert result.opaque_payload_high_entropy == 4
    assert result.opaque_payload_bytes == len(high_entropy) * 4
    assert set(result.opaque_payload_paths) == {f"payload/{letter}" for letter in "abcd"}


def _scanner(tmp_path):
    return JarScanner(cache_dir=tmp_path / "cache", enable_cache=False)


def _empty_result(path):
    return JarScanResult(
        path=path,
        file_name=path.name,
        sha256="0" * 64,
        size_bytes=1,
        last_modified=dt.datetime(2026, 1, 1),
        launcher_name="test",
        instance_name="test",
    )


def _location(tmp_path):
    return LauncherLocation("Prism", "Hypixel PvP profile", tmp_path, "test")


def _write_feature_jar(path, mixin: bool = False, lang: bool = False):
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr(
            "fabric.mod.json",
            json.dumps({"id": "helper", "name": "Helper", "environment": "client", "entrypoints": {"client": ["com.xien.Main"]}, "mixins": ["helper.mixins.json"]}),
        )
        if mixin:
            jar.writestr("helper.mixins.json", json.dumps({"package": "com.xien.mixin", "client": ["ReachMixin"]}))
            jar.writestr("com/xien/mixin/ReachMixin.class", _class_bytes("net/minecraft/client/network/ClientPlayerEntity", "Inject", "Reach"))
        jar.writestr("com/xien/Main.class", _class_bytes("com/xien/ModuleManager", "ClientModInitializer"))
        jar.writestr("com/xien/ModuleManager.class", _class_bytes("com/xien/modules/combat/Reach", "ModuleManager", "Category", "Setting"))
        jar.writestr("com/xien/modules/combat/Reach.class", _class_bytes("Reach", "module.combat.reach.name", "range enabled"))
        if lang:
            jar.writestr("assets/helper/lang/en_us.json", json.dumps({"module.combat.reach.name": "Reach", "setting.reach.distance": "Reach Distance"}))


def _write_clean_jar(path):
    with zipfile.ZipFile(path, "w") as jar:
        jar.writestr("fabric.mod.json", json.dumps({"id": "clean", "name": "Clean"}))
        jar.writestr("com/example/Clean.class", _class_bytes("CleanMod"))


def _class_bytes(*utf8_values: str) -> bytes:
    constants = []
    for value in utf8_values:
        encoded = value.encode("utf-8")
        constants.append(b"\x01" + len(encoded).to_bytes(2, "big") + encoded)
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + (len(constants) + 1).to_bytes(2, "big") + b"".join(constants)
