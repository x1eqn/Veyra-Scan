from __future__ import annotations

from xien_control.console import Console
from xien_control.interactive_menu import InteractiveMenu, SCAN_CATEGORIES


class DummyConsole(Console):
    def __post_init__(self) -> None:
        self.color = False
        self.messages: list[str] = []

    def line(self, message: str = "") -> None:
        self.messages.append(message)

    def tag(self, tag: str, message: str) -> None:
        self.messages.append(f"[{tag}] {message}")


def test_completed_category_is_hidden_and_numbering_is_dynamic(monkeypatch):
    console = DummyConsole()
    menu = InteractiveMenu(console)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "1")

    selected = menu.choose_category({"minecraft"})

    assert selected is not None
    assert selected.id == "manual_jar"
    rendered = "\n".join(console.messages)
    assert "Minecraft Jar / Mod Scan" not in rendered
    assert "[1] Manual JAR Deep Scan" in rendered


def test_zero_finishes_remaining_menu(monkeypatch):
    console = DummyConsole()
    menu = InteractiveMenu(console)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "0")

    assert menu.choose_category({"minecraft"}) is None


def test_all_categories_completed_returns_none_without_menu(monkeypatch):
    console = DummyConsole()
    menu = InteractiveMenu(console)

    assert menu.choose_category({category.id for category in SCAN_CATEGORIES}) is None
    assert any("All scan categories are complete" in msg for msg in console.messages)
