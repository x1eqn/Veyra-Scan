from xien_control.client_names import find_client_name_matches


def test_distinctive_client_name_matches_exactly():
    matches = find_client_name_matches(["ccbluex/liquidbounce/features/module.class"])
    assert any(item.family == "liquidbounce" and item.kind == "exact" for item in matches)


def test_small_client_name_typo_matches_by_similarity():
    matches = find_client_name_matches(["client/tenac1ty/ModuleManager.class"])
    assert any(item.family == "tenacity" and item.kind == "similar-name" for item in matches)


def test_ambiguous_word_requires_explicit_client_context():
    assert not find_client_name_matches(["future/task/FutureTask.class"])
    matches = find_client_name_matches(["me/grimclient/modules/Reach.class"])
    assert any(item.family == "grim client" for item in matches)


def test_normal_mod_names_do_not_fuzzy_match():
    assert not find_client_name_matches(["bettercrosshair", "configscreen", "minecraftclient"])


def test_structural_tokens_do_not_use_fuzzy_client_matching():
    assert not find_client_name_matches(["elementwas", "rootlnet", "modclient"], allow_fuzzy=False)


def test_bare_wurst_structural_token_requires_client_context():
    assert not find_client_name_matches(["com/example/Wurst.class"], allow_fuzzy=False, strict_context=True)
    matches = find_client_name_matches(["com/wurst/client/WurstClient.class"], allow_fuzzy=False, strict_context=True)
    assert any(item.family == "wurst" for item in matches)
