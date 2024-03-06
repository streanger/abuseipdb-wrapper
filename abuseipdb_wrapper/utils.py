import getpass
import json
import os
from pathlib import Path

import keyring
import pwinput

from abuseipdb_wrapper.logger import CYAN, RED, YELLOW, console, log, print


def write_json(filename, data):
    """write to json file"""
    try:
        with open(filename, "w", encoding="utf-8") as fp:
            # ensure_ascii -> False/True -> characters/u'type'
            json.dump(data, fp, sort_keys=True, indent=4, ensure_ascii=False)
    except Exception as err:
        log(f"[{RED}]\[x] failed to write to file: {filename}, err: {err}[/{RED}]")
    return True


def read_json(filename):
    """read json file to dict"""
    data = {}
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        log(f"[{YELLOW}]\[x] file not found: {filename}[/{YELLOW}]")
    return data


def write_file(filename, text):
    """write to file"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(text)
    except Exception as err:
        log(f"[{RED}]\[x] failed to write to file: {filename}, err: {err}[/{RED}]")
    return None


def get_abuse_directory():
    """create and return a folder in the user's home directory"""
    home_directory = Path.home()
    config_directory = home_directory.joinpath("abuse")
    config_directory.mkdir(exist_ok=True)
    return config_directory


def remove_duplicates_keep_order(items):
    """remove duplicates from list and keep order"""
    return list(dict.fromkeys(items))


def store_api_key(force_new=False):
    """retrieve or store abuseipdb API_KEY

    force_new - force reading new from user, not from keyring
    docs:
        https://docs.python.org/3/library/getpass.html
        In general, this function (getpass.getuser) should be preferred over os.getlogin()

    copy & paste API_KEY:
        https://bugs.python.org/issue37426
        > Clicking `Edit > Paste` from the window menu
        > Use right-click to paste
    """
    username = getpass.getuser()
    if not force_new:
        API_KEY = keyring.get_password("abuse", username)
    else:
        API_KEY = None

    if API_KEY is not None:
        log(f"[{CYAN}]\[*] using saved API_KEY[/{CYAN}]")
    else:
        try:
            if os.name == "nt":
                os.system("color")
            # use following to generate proper ansi codes
            # from rich.ansi import Style; from rich.console import Console
            # Style(color='cyan', bold=True)._make_ansi_codes(Console()._detect_color_system())
            prompt_text = "\x1b[1;36m[>] put your API KEY: \x1b[0m"
            user_input = pwinput.pwinput(prompt=prompt_text)
            try:
                if len(user_input) != 80:
                    raise ValueError
                int(user_input, 16)
                API_KEY == user_input
            except ValueError:
                log(f"[{YELLOW}]\[x] wrong API_KEY format, should be 80 hexstring chars[/{YELLOW}]")

        except KeyboardInterrupt:
            log()
            log(f"[{YELLOW}]\[x] broken by user[/{YELLOW}]")
            return False

        if not API_KEY:
            log(f"[{YELLOW}]\[x] API_KEY not provided[/{YELLOW}]")
            return False

        if API_KEY == "\x16":
            log(f"[{YELLOW}]\[x] ctrl+v won't work. Type API_KEY or use right-click to paste it from clipboard[/{YELLOW}]")
            return False

        keyring.set_password("abuse", username, API_KEY)
        log(f"[{CYAN}]\[*] API_KEY saved[/{CYAN}]")
    return API_KEY
