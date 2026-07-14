from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .console import Console, ask_yes_no


@dataclass(frozen=True)
class ScanCategory:
    id: str
    title: str
    description: str
    full_scan: bool = False


SCAN_CATEGORIES: tuple[ScanCategory, ...] = (
    ScanCategory(
        "minecraft",
        "Minecraft Jar / Mod Scan",
        "Scans .jar files in Minecraft launcher, modpack, and mods folders.",
    ),
    ScanCategory(
        "manual_jar",
        "Manual JAR Deep Scan",
        "Selects one JAR for an uncached, detailed class, bytecode, nested archive, and concealment scan.",
    ),
    ScanCategory(
        "javaw_scan",
        "Javaw Scan",
        "Scans javaw.exe memory/artifacts, compares runtime JARs with disk, and reviews removed-mod traces.",
    ),
    ScanCategory(
        "mousetweaks_freecam",
        "MouseTweaks / Freecam Finder",
        "Checks Minecraft instance logs and mod contents for MouseTweaks, Freecam, and FreeLook traces.",
    ),
    ScanCategory(
        "xray_autoclicker",
        "Xray / AutoClicker / Auto-Totem / Mace-Swap",
        "Checks logs, mods, and texture packs for Xray, AutoClicker, Auto-Totem, and Mace-Swap/Swap Helper traces.",
    ),
)

CATEGORY_BY_ID = {category.id: category for category in SCAN_CATEGORIES}
CATEGORY_TITLES = {category.id: category.title for category in SCAN_CATEGORIES}


class InteractiveMenu:
    def __init__(self, console: Console):
        self.console = console

    def choose_category(self, completed: Iterable[str]) -> ScanCategory | None:
        remaining = [category for category in SCAN_CATEGORIES if category.id not in set(completed)]
        if not remaining:
            self.console.line("All scan categories are complete.")
            return None
        while True:
            self.console.line()
            title = "What do you want to scan?" if len(remaining) == len(SCAN_CATEGORIES) else "Remaining scan options:"
            self.console.line(title)
            self.console.line()
            for number, category in enumerate(remaining, 1):
                self.console.line(f"[{number}] {category.title}")
                self.console.line(f"    {category.description}")
                self.console.line()
            exit_label = "Exit" if len(remaining) == len(SCAN_CATEGORIES) else "Finish and show report"
            self.console.line(f"[0] {exit_label}")
            try:
                answer = input("\nYour selection: ").strip()
            except EOFError:
                return None
            if answer == "0":
                return None
            try:
                selected = int(answer)
            except ValueError:
                self.console.line("Invalid selection. Choose a number from the list.")
                continue
            if 1 <= selected <= len(remaining):
                return remaining[selected - 1]
            self.console.line("Invalid selection. Choose a number from the list.")

    def ask_more(self, completed: Iterable[str]) -> bool:
        if len(set(completed)) >= len(SCAN_CATEGORIES):
            self.console.line("All scan categories are complete.")
            return False
        return ask_yes_no("Do you want to scan more? [Y/N]: ")
