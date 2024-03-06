"""
commands output should use direct print (from rich)
side informations should use log from here
in some situations console is used (???)
"""
import os
from typing import Any

from rich import print
from rich.color import ColorSystem
from rich.console import Console


class Logger:
    def __init__(self, verbose=True):
        self.verbose = verbose

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        if self.verbose:
            print(*args, **kwds)


def set_colors():
    """set colors depend on terminal types

    os.getenv('TERM_PROGRAM')       --> vscode
    os.getenv('PROMPT') == '$P$G'   --> cmd and vscode
    os.getenv('WT_SESSION')         --> windows terminal & vscode
    """
    # 1) IP_COLOR on XXX
    color_system = Console()._detect_color_system()
    if color_system == ColorSystem.WINDOWS:
        # Windows-cmd, Windows-Powershell
        IP_COLOR = 'black'
    elif color_system == ColorSystem.TRUECOLOR:
        # Windows-Terminal, VSCode, Linux-Terminal
        IP_COLOR = 'bold grey0'
    else:
        IP_COLOR = 'black'

    # 2) red/green/yellow
    is_linux = (os.name == 'posix')
    is_windows = (os.name == 'nt')
    is_vscode = (os.getenv('TERM_PROGRAM') == 'vscode')
    is_windows_cmd = (os.getenv('PROMPT') == '$P$G') and (not os.getenv('TERM_PROGRAM'))
    is_windows_terminal = os.getenv('WT_SESSION') and (not os.getenv('TERM_PROGRAM'))
    if is_windows and (is_windows_cmd or is_windows_terminal):
        # windows-cmd, windows-terminal
        RED = 'red'
        YELLOW = 'yellow'
        GREEN = 'bright_green'
    elif is_linux and not is_vscode:
        # linux-terminal
        RED = 'bright_red'
        YELLOW = 'gold1'
        GREEN = 'green1'
    elif is_vscode:
        # vscode
        RED = 'bright_red'
        YELLOW = 'bright_yellow'
        GREEN = 'green1'
    else:
        # windows-powershell and others
        RED = 'bright_red'
        YELLOW = 'bright_yellow'
        GREEN = 'bright_green'
    return IP_COLOR, GREEN, YELLOW, RED


# color consts
YELLOW_LEVEL = 30
RED_LEVEL = 80
CYAN = 'cyan bold'
HIGH = 'green_yellow'
INFO_COLOR = "bold cyan on grey0"
IP_COLOR, GREEN, YELLOW, RED = set_colors()
log = Logger(verbose=True)
console = Console(color_system="auto")
