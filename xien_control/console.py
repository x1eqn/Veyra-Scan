from __future__ import annotations

import ctypes
import os
import sys
import time
from dataclasses import dataclass


PURPLE = "\033[95m"
RESET = "\033[0m"

COLORS = {
    "BOOT": PURPLE,
    "CACHE": PURPLE,
    "LOAD": PURPLE,
    "OK": PURPLE,
    "FOUND": PURPLE,
    "DISCOVERY": PURPLE,
    "INDEX": PURPLE,
    "SCAN": PURPLE,
    "JAR": PURPLE,
    "CLASS": PURPLE,
    "STRINGS": PURPLE,
    "RULE": PURPLE,
    "SCORE": PURPLE,
    "ALERT": PURPLE,
    "WARN": PURPLE,
    "REPORT": PURPLE,
    "DONE": PURPLE,
    "EXE": PURPLE,
    "EXE-CACHE": PURPLE,
    "EXE-DISCOVERY": PURPLE,
    "EXE-FOUND": PURPLE,
    "EXE-OK": PURPLE,
    "EXE-PE": PURPLE,
    "EXE-REVIEW": PURPLE,
    "EXE-SCAN": PURPLE,
    "EXE-SCORE": PURPLE,
    "EXE-SIGN": PURPLE,
    "SYSTEM": PURPLE,
    "RESET": RESET,
}


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


@dataclass
class Console:
    color: bool = True

    def __post_init__(self) -> None:
        self.color = self.color and _enable_windows_ansi() and sys.stdout.isatty()

    def tag(self, tag: str, message: str) -> None:
        if self.color:
            color = COLORS.get(tag, "")
            reset = COLORS["RESET"] if color else ""
            print(f"{color}[{tag}]{reset} {message}")
        else:
            print(f"[{tag}] {message}")

    def line(self, message: str = "") -> None:
        if self.color and message:
            print(f"{PURPLE}{message}{RESET}")
            return
        print(message)

    def progress(self, current: int, total: int, scanning: str) -> None:
        total = max(total, 1)
        width = 20
        ratio = max(0.0, min(1.0, current / total))
        filled = int(width * ratio)
        bar = "#" * filled + "-" * (width - filled)
        percent = int(ratio * 100)
        text = f"\r[{bar}] {percent:3d}% | {current}/{total} | scanning: {scanning}"
        if self.color:
            text = f"{PURPLE}{text}{RESET}"
        print(text, end="", flush=True)
        if current >= total:
            print()

    def tiny_delay(self, seconds: float = 0.04) -> None:
        if sys.stdout.isatty():
            time.sleep(seconds)


def ask_yes_no(prompt: str) -> bool:
    try:
        if sys.stdout.isatty() and _enable_windows_ansi():
            prompt = f"{PURPLE}{prompt}{RESET}"
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes", "e", "evet"}


def pause_if_interactive() -> None:
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            input("\nPress Enter to close...")
        except EOFError:
            pass
