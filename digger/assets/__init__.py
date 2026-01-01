"""Static assets (logo, ASCII banner). Loaded as string constants."""

from __future__ import annotations

from pathlib import Path

_ASSET_DIR = Path(__file__).parent


def svg_logo() -> str:
    return (_ASSET_DIR / "logo.svg").read_text(encoding="utf-8")


# Compact monochrome ASCII rendering of the skeleton-with-shovel emblem,
# designed for 80-col terminals. Hand-tuned, do not auto-format.
# Single-quote triple delimiter so we can use double-quote characters
# inside the art without escape gymnastics.
ASCII_LOGO = r'''
                          .--""""--.
                         /          \           \         /
                        |   .--.     |            \       /
                  ____  |  ( oo )    |             \     /
                 /    \ |   '--'     |              \   /
                /      \ \  /||\  /  /               \=/
               /  ___   `'--||||--'`         _________|_________
              ,  /,-,\_  ___||||___         /                   \
              | /  | | |    ||||    |       \_________  _________/
              | \  | | |    ||||    |                 \/
              \  `-' /  \___||||___/                  /\
               \    /       /||\                     /  \
                `--'       / || \                   /    \
                          /  ||  \
                         /   ||   \
                        '----||----'
                             ##
                            ####
                           ######
        ____ ___ ____ ____ _____ ____
       |  _ \_ _/ ___|  _ \_   _|  _ \
       | | | | | |  _| | | || | | |_) |
       | |_| | | |_| | |_| || | |  _ <
       |____/___\____|____/ |_| |_| \_\
       cross-platform forensic investigation
'''


def ascii_logo() -> str:
    return ASCII_LOGO
