import os
import re
import json
import random
import getpass
import datetime
import ipaddress
from pathlib import Path

# 3rd party modules
import keyring
import requests
import pandas as pd
from rich import box, print
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.console import Console
from rich.columns import Columns
from pandas.io.formats.style import Styler

# my modules
from abuseipdb_wrapper.tor_enrich import get_tor_exit_nodes


# consts
YELLOW_LEVEL = 30
RED_LEVEL = 80


class AbuseIPDB:
    """abuseipdb api wrapper"""
    def __init__(self, API_KEY, ip_list=None, db_file=None, verbose=None):
        self._API_KEY = API_KEY
        if ip_list is None:
            ip_list = []
        valid_list = self.assert_ip_list(ip_list)
        self._ip_list = valid_list
        self._regular_items = [
            "abuseConfidenceScore",
            "countryCode",
            "domain",
            "hostnames",
            "ipAddress",
            "ipVersion",
            "isPublic",
            "isWhitelisted",
            "isp",
            "lastReportedAt",
            "numDistinctUsers",
            "totalReports",
            "url",  # additional (abuseipdb related url)
            "usageType",
            "date",  # additional (date of request)
            "isTorNode",  # additional; requires tor enrich
        ]
        self._table_columns_order = [
            "ipAddress",
            "abuseConfidenceScore",
            "totalReports",
            "countryCode",
            "hostnames",
            "domain",
            "isp",
        ]
        self._matched_only = False
        self.table_view = True
        self.__console = Console(color_system="truecolor")
        self.verbose = bool(verbose)

        # ********* filename & db *********
        self._db_file = db_file
        if self._db_file is None:
            self._ip_database = {}
        else:
            # ********* read db *********
            try:
                self._ip_database = self._read_json(self._db_file)
            except FileNotFoundError:
                print("[yellow]\[x] file not found: {}, continue with empty db")
                self._ip_database = {}
            except Exception as err:
                print("[red[-] couldn't read data from file: {}".format(self._db_file))
                raise

    @staticmethod
    def colors_legend():
        """show colors legend used in application"""
        legend_lines = [
            "[cyan]legend:",
            "[cyan]    [*] cyan    - information",
            "[green]    [+] green   - things made fine; low level of abuse",
            "[yellow]    \[x] yellow  - warning; medium level of abuse",
            "[red]    [-] red     - errors; high level of abuse",
            "[magenta]    [!] magenta - unexpected things happened",
        ]
        lines_joined = "\n".join(legend_lines)
        legend = Columns(
            [Panel(lines_joined, style="on black", border_style="royal_blue1")]
        )
        print(legend)
        return None

    def get_db(self, matched_only=None):
        """return data from db - total or matching to existing ip_list"""
        if matched_only is None:
            matched_only = self._matched_only

        if matched_only:
            matched = self._match_keys(self._ip_database, self._ip_list)
        else:
            matched = self._ip_database
        return matched

    def get_df(self, matched_only=None):
        """return dataframe object"""
        if matched_only is None:
            matched_only = self._matched_only
        matched = self.get_db(matched_only)
        df = pd.DataFrame(matched.values())
        return df

    def clear_ip_list(self):
        """clear internal ip list"""
        self._ip_list = []
        return None

    def assert_ip_list(self, ip_list):
        """if not valid, throw error"""
        if type(ip_list) not in (list, tuple):
            print("[red]\[-] ip_list should be type of list or tuple")
            raise TypeError

        valid_list = []
        for item in ip_list:
            try:
                valid_ip = str(ipaddress.ip_address(item))
                if valid_ip != item:
                    if self.verbose:
                        print("[cyan]\[*] conversion: {} -> {}".format(item, valid_ip))
                valid_list.append(valid_ip)

            except ValueError as err:
                if self.verbose:
                    print("[red]\[-] not valid IP address: {}".format(item))
                # raise  # re-throw exception; it may not be needed
        return valid_list

    def check_ip_orig(self, ip, max_age_in_days="90", verbose=False):
        """checks IP abuse using abuseipdb.com in original manner

        docs: https://docs.abuseipdb.com/?python#check-endpoint
        from docs:
            Omitting the verbose flag will exclude reports and the country name field.
            If you want to keep your response payloads light, this is recommended. 
        """
        # ********* Defining the api-endpoint *********
        url = "https://api.abuseipdb.com/api/v2/check"
        # IMPORTANT:
        #   including verbose flag in querystring will casue including reports
        #   (as well as country name) in response no matter of True/False
        #   so have it in mind
        if verbose:
            querystring = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_in_days,
                "verbose": verbose,
                }
        else:
            querystring = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_in_days,
                }
        headers = {
            "Accept": "application/json",
            "Key": self._API_KEY
            }
        response = requests.request(
            method="GET", url=url, headers=headers, params=querystring
        )

        # ********* Formatted output *********
        decoded = json.loads(response.text)
        return decoded

    def check_ip(self, ip, max_age_in_days="90"):
        """checks IP abuse using abuseipdb.com and adds url & date fields and removes reports

        docs: https://docs.abuseipdb.com/?python#check-endpoint
        typically errors:
            {'errors': [{'detail': 'Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.', 'status': 429}]}
            {'errors': [{'detail': 'The ip address must be a valid IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888).', 'status': 422, 'source': {'parameter': 'ipAddress'}}]}
            {'errors': [{'detail': 'Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.', 'status': 401}]}
        """
        decoded = self.check_ip_orig(ip, max_age_in_days)
        errors_status = decoded.get("errors", False)
        if errors_status:
            print("[red]    [-] API errors_status: {}".format(errors_status))
            raise ValueError("AbuseIPDB API error")
        data = decoded["data"]
        data["url"] = "https://www.abuseipdb.com/check/{}".format(ip)
        data["date"] = self._timestamp()
        data["isTorNode"] = ''
        return data

    def __log_table(self, table):
        """Generate an ascii formatted presentation of a Rich table
        Eliminates any column styling
        https://github.com/Textualize/rich/discussions/1799
        """
        with self.__console.capture() as capture:
            self.__console.print(table)
        return Text.from_ansi(capture.get())

    def _db_str(self, matched_only=None, table_view=None):
        """
        matched_only    -> True     -show only specified IP's
        matched_only    -> False    -show total db
        table_view      -> True     -table view (rows)
        table_view      -> False    -vertical view
        """
        # ********* match choosed *********
        if matched_only is None:
            matched_only = self._matched_only

        if table_view is None:
            table_view = self.table_view

        if matched_only:
            matched = self._match_keys(self._ip_database, self._ip_list)
        else:
            matched = self._ip_database

        # ********* sort by ipAddress *********
        sorted_matches = sorted(
            matched.values(), key=lambda x: self._ip_sorter(x["ipAddress"])
        )

        # ********* colord table *********
        if table_view:
            border_style = "blue on black"
            header_style = "bold green_yellow on royal_blue1"
            is_powershell = len(os.getenv("PSModulePath", "").split(os.pathsep)) >= 3
            if is_powershell:
                # https://stackoverflow.com/questions/55597797/detect-whether-current-shell-is-powershell-in-python
                table = Table(
                    box=box.ASCII, border_style=border_style, header_style=header_style
                )
            else:
                table = Table(border_style=border_style, header_style=header_style)

            # ********* columns *********
            column_on_style = "on black"
            table.add_column("No", style="green_yellow {}".format(column_on_style))
            for column in self._table_columns_order:
                table.add_column(column, style="royal_blue1 {}".format(column_on_style))

            # ********* rows *********
            for index, value in enumerate(sorted_matches):
                selected_data_row = [
                    str(value.get(key, "")) for key in self._table_columns_order
                ]
                abuse_color = self._abuse_color(value["abuseConfidenceScore"])
                table.add_row(str(index + 1), *selected_data_row, style=abuse_color)

            # capture as Text object
            db_str = self.__log_table(table)
        else:
            # ********* vertical view *********
            db_str_rows = []
            number_of_ip = len(sorted_matches)

            for index, value in enumerate(sorted_matches):
                abuse_color = self._abuse_color(value["abuseConfidenceScore"])
                selected_data_dict = {
                    key: value.get(key, "") for key in self._table_columns_order
                }
                items_str = "\n".join(
                    [
                        "    {}: {}".format(key.ljust(20), item)
                        for key, item in selected_data_dict.items()
                    ]
                )
                colored_items_str = "[{0}]{1}/{2})[/{0}] [[{0} reverse] {3} [/{0} reverse]]\n[{0}]{4}[/{0}]".format(
                    abuse_color,
                    index + 1,
                    number_of_ip,
                    value["ipAddress"],
                    items_str,
                )
                db_str_rows.append(colored_items_str)

            # capture as Text object
            db_str = self.__log_table("\n\n".join(db_str_rows))
        return db_str

    def show_db(self, matched_only=None, table_view=None):
        """show database in nice format"""
        if matched_only is None:
            matched_only = self._matched_only
        if table_view is None:
            table_view = self.table_view
        print(self._db_str(matched_only, table_view))
        return None

    @staticmethod
    def _match_keys(dict_data, list_keys):
        matched = {key: value for key, value in dict_data.items() if key in list_keys}
        return matched

    def apply_columns_order(self, order):
        """apply new columns order for show_db"""
        if not type(order) in (list, tuple):
            print(
                "[red]\[-] order should be list or tuple type; type(order): {}".format(
                    type(order)
                )
            )
            return False

        if not order:
            return False

        for item in order:
            if not item in self._regular_items:
                print("[red]\[-] wrong item in columns order: {}".format(item))
                return False
        self._table_columns_order = order
        return None

    def get_default_columns(self):
        """show json columns (keys) for user to know the order"""
        return self._regular_items

    def toggle_view(self):
        """switch db view -> vertical/table; main purpose is .viewer method, which uses __str__"""
        self.table_view = not self.table_view
        print("[cyan]\[*] self.table_view:[/cyan] {}".format(self.table_view))
        return None

    def _viewer_help(self):
        """viewer help content"""
        help_lines = [
            "[green_yellow]viewer help:",
            "[green_yellow]    cls\clear                  - clear terminal",
            "[green_yellow]    exit\quit                  - exit from viewer",
            "[green_yellow]    view                       - toggle table view",
            "[green_yellow]    live                       - check IP live if not in db",
            "[green_yellow]    all                        - show all IP's from db",
            "[green_yellow]    path                       - shows path to .db file",
            "[green_yellow]    columns \[columns list]     - shows or apply columns order",
            "[green_yellow]    export \[csv, html, xlsx]   - export to file",
            "[green_yellow]    tor                        - enrich info about tor node",
            "[green_yellow]    key                        - change API_KEY",
            "[green_yellow]    legend                     - colors legend",
        ]
        lines_joined = "\n".join(help_lines)
        legend = Columns(
            [Panel(lines_joined, style="on black", border_style="royal_blue1")]
        )
        print(legend)

    def viewer(self, check_live=True):
        """interactive viewer

        check_live - if IP is not found in local DB request is being made
        (!) Important: .viewer method resets ._ip_list attribute
        """
        while True:
            try:
                query = Prompt.ask("[cyan bold]~< go >~# ")
            except KeyboardInterrupt:
                print()
                continue

            full_query = query.strip()
            if not full_query:
                continue
            query, *rest = full_query.split()

            # ********* execute command *********
            if query in ("exit", "quit"):
                return None
            elif query in ("cls", "clear"):
                if os.name == "nt":
                    os.system("cls")
                else:
                    os.system("clear")
                continue
            elif query == "view":
                self.toggle_view()
                continue
            elif query == "live":
                check_live = not check_live
                print("[cyan]\[*] check_live:[/cyan] {}".format(check_live))
                continue
            elif query == "help":
                self._viewer_help()
                continue
            elif query == "all":
                # IMPORTANT: modify full_query, not query
                full_query = " ".join(list(self._ip_database.keys()))
            elif query == "path":
                print("[cyan]\[*] db file:[/cyan] {}".format(self._db_file))
                continue
            elif query == 'columns':
                if rest:
                    # filter out strings which are not ascii_letters
                    rest = [item for item in rest if item in self._regular_items]
                    self.apply_columns_order(rest)
                else:
                    # show current columns order
                    regular = self._regular_items.copy()
                    current_order = {item:True for item in self._table_columns_order}
                    not_used_order = {item:False for item in regular if not item in self._table_columns_order}
                    current_order.update(not_used_order)
                    print(current_order)
                    print('[cyan]\[*] availabe columns:[/cyan] {}'.format(' '.join(self._regular_items)))
                continue
            elif query == 'export':
                if rest:
                    file_format = rest[0]
                    directory = Path(self._db_file or '.').parent.absolute()
                    if file_format == 'csv':
                        filename = directory.joinpath('abuse.csv')
                        self.export_csv(filename)
                    elif file_format == 'html':
                        filename = directory.joinpath('abuse.html')
                        self.export_html_styled(filename)
                    elif file_format == 'xlsx':
                        filename = directory.joinpath('abuse.xlsx')
                        self.export_xlsx_styled(filename)
                    else:
                        print("[yellow]\[x] unrecognized; choose from: <csv>, <html>, <xlsx>")
                        continue
                else:
                    print("[yellow]\[x] no file format specfied")
                continue
            elif query == 'tor':
                enrich = False
                for value in self._ip_database.values():
                    if value.get('isTorNode', '') == '':
                        enrich = True
                        break
                if enrich:
                    # enrich informations about tor exit nodes
                    self.tor_info_enrich()
                continue
            elif query == 'key':
                API_KEY = store_api_key(force_new=True)
                if API_KEY:
                    self._API_KEY = API_KEY
                    print("[cyan]\[*] new API_KEY assigned")
                continue
            elif query == 'legend':
                self.colors_legend()
                continue
            else:
                pass

            # ********* execute query *********
            self.clear_ip_list()
            ips_query = [item.strip("\"' ") for item in re.split(",| |;", full_query)]
            ips_query = [item for item in ips_query if item]
            self.add_ip_list(ips_query)
            if not self._ip_list:
                if self.verbose:
                    print("[yellow]\[x] empty IP list for query")
                continue

            if check_live:
                no_existing = [
                    item for item in self._ip_list if not item in self._ip_database
                ]
                if no_existing:
                    base_ip_list = self._ip_list
                    self.clear_ip_list()
                    self.add_ip_list(no_existing)
                    self.check()
                    self._ip_list = base_ip_list
            else:
                if not self._match_keys(self._ip_database, self._ip_list):
                    print("[yellow]\[x] no results")
                    continue

            print(self._db_str(matched_only=True))
        return None

    def tor_info_enrich(self):
        """get info about tor exit nodes"""
        tor_exit_nodes = get_tor_exit_nodes()
        for key in self._ip_database.keys():
            self._ip_database[key]['isTorNode'] = (key in tor_exit_nodes)
        print("[cyan]\[*] tor exit nodes info enriched")
        self.update_local_db()

    def add_ip_list(self, ip_list):
        """add list of IP's to current check"""
        valid_list = self.assert_ip_list(ip_list)
        self._ip_list = list(set(self._ip_list + valid_list))
        return None

    @staticmethod
    def _abuse_color(level):
        """set color depend on abuse level"""
        if level >= RED_LEVEL:
            color = "red"
        elif YELLOW_LEVEL <= level < RED_LEVEL:
            color = "yellow"
        else:
            color = "green"
        return color

    def check(self, force_new=False):
        """iterate over collected IP list"""
        number_of_ip = len(self._ip_list)
        if not number_of_ip:
            print("[cyan]\[*] add some IPs for check -> .add_ip_list(ip_list)")
            return None

        print("[cyan]\[*] iteration starts")
        for index, ip in enumerate(self._ip_list):
            try:
                ip = str(ip)
                colored_items_str = (
                    "[{0}]{1}/{2})[/{0}] [[{0} reverse] {3} [/{0} reverse]]".format(
                        "cyan",
                        index + 1,
                        number_of_ip,
                        ip,
                    )
                )
                print(colored_items_str)

                # ********* check if exists *********
                data = self._ip_database.get(ip, False)
                if data and not force_new:
                    print_color = self._abuse_color(data["abuseConfidenceScore"])
                    print("[{}]    [+] already exists".format(print_color))
                    continue

                # ********* get & print data *********
                data = self.check_ip(ip)
                if not data:
                    break

                print_color = self._abuse_color(data["abuseConfidenceScore"])
                selected_data_dict = {
                    key: data[key] for key in self._table_columns_order
                }
                data_str = "\n".join(
                    [
                        "    {}: {}".format(key.ljust(20), value)
                        for key, value in selected_data_dict.items()
                    ]
                )
                print("[{}]{}".format(print_color, data_str))

                # ********* update json *********
                self._ip_database[ip] = data

            except KeyboardInterrupt:
                print("[yellow]    \[x] broken by user")
                break

            except Exception as err:
                print("[magenta]    [!] unexpected error catched: {}".format(err))
                break

            finally:
                # cleanup
                print()

        # ********* update db file if provided *********
        self.update_local_db()
        return None

    def update_local_db(self):
        """update local db with handling None file and verbose"""
        if self._db_file is not None:
            self._write_json(self._db_file, self._ip_database)
            if self.verbose:
                print(
                    "[cyan]\[*] data saved to file:[/cyan] [green_yellow]{}".format(
                        self._db_file
                    )
                )

    def __str__(self):
        """print as show_db with matched_only and table_view"""
        return self._db_str(matched_only=None, table_view=None).plain

    @staticmethod
    def _write_json(filename, data):
        """write to json file"""
        with open(filename, "w", encoding="utf-8") as fp:
            # ensure_ascii -> False/True -> characters/u'type'
            json.dump(data, fp, sort_keys=True, indent=4, ensure_ascii=False)
        return True

    @staticmethod
    def _read_json(filename):
        """read json file to dict"""
        data = {}
        try:
            with open(filename, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            print("[yellow]\[x] file not found: {}".format(filename))
        return data

    @staticmethod
    def _timestamp():
        """generate timestamp in string format"""
        out = str(datetime.datetime.now())
        return out

    @staticmethod
    def _timestamp_to_datetime(str_timestamp):
        """convert string timestamp to datetime type

        TODO: use it to set cache time and request again if elapsed
        """
        out = datetime.datetime.strptime(str_timestamp, "%Y-%m-%d %H:%M:%S.%f")
        # ~ out = datetime.datetime.strptime(str_timestamp, '%Y-%m-%d %H:%M:%S')
        return out

    @staticmethod
    def _unix_to_datetime(unix_time):
        """convert unix to datetime

        TODO: use it to set cache time and request again if elapsed
        """
        out = datetime.datetime.fromtimestamp(unix_time)
        return out

    @staticmethod
    def _ip_sorter(ip):
        """creation of sortable values based on the given IP"""
        try:
            if "." in ip:
                # IPv4
                return ".".join([item.zfill(3) for item in ip.split(".")])
            else:
                # IPv6
                return ipaddress.IPv6Address(ip).exploded
        except Exception:
            return ip

    def _write_file(self, filename, text, mode="w"):
        """write to file"""
        try:
            with open(filename, mode, encoding="utf-8") as f:
                f.write(text)
        except Exception as err:
            print("[red]\[x] Failed to write to file: {}, err: {}".format(filename, err))
        return None

    def export_html_styled(self, filename, matched_only=None, xlsx=False):
        """export database to styled html file using pandas"""
        if matched_only:
            matched = self._match_keys(self._ip_database, self._ip_list).values()
        else:
            matched = self._ip_database.values()

        # create dataframe; filter columns, clickable url & sorting
        df = pd.DataFrame(matched)
        if not set(self._table_columns_order).issubset(df.columns):
            print("[yellow]\[x] nothing to export")
            return False

        # handle lack of abuseConfidenceScore
        hide = []
        ABUSE_CONFIDENCE_SCORE = 'abuseConfidenceScore'
        if not ABUSE_CONFIDENCE_SCORE in self._table_columns_order:
            self._table_columns_order.append(ABUSE_CONFIDENCE_SCORE)
            hide = [ABUSE_CONFIDENCE_SCORE]

        df = df[self._table_columns_order]
        df.fillna("", inplace=True)
        if not xlsx and "url" in df.columns:
            df["url"] = ["<a href={}>{}</a>".format(item, item) for item in df["url"]]
        if "ipAddress" in df.columns:
            df["ip_sorter"] = df["ipAddress"].apply(lambda x: self._ip_sorter(x))
            df.sort_values(
                [
                    "ip_sorter",
                ],
                ascending=[
                    True,
                ],
                inplace=True,
            )
            df.drop(columns="ip_sorter", inplace=True)
            df.reset_index(drop=True, inplace=True)
            df.index += 1
        else:
            df.index += 1

        # create styled object & export it to file
        styled = apply_style(df, hide=hide)

        # hide cleanup
        for hidden in hide:
            self._table_columns_order.remove(hidden)

        if xlsx:
            # to xlsx
            styled.to_excel(filename, engine='openpyxl', columns=self._table_columns_order)
        else:
            # to html
            html = styled.to_html(render_links=True, escape=False)
            self._write_file(filename, html)

        print("[cyan]\[*] data saved to file:[/cyan] [green_yellow]{}".format(filename))
        return None

    def export_xlsx_styled(self, filename, matched_only=None):
        """export database to styled xlsx file using pandas"""
        self.export_html_styled(filename, matched_only=matched_only, xlsx=True)

    def export_csv(self, filename, matched_only=None):
        """export databse to csv file"""
        if matched_only:
            matched = self._match_keys(self._ip_database, self._ip_list).values()
        else:
            matched = self._ip_database.values()

        # create dataframe; filter columns
        df = pd.DataFrame(matched)
        if not set(self._table_columns_order).issubset(df.columns):
            print("[yellow]\[x] nothing to export")
            return False
        df = df[self._table_columns_order]
        df.fillna("", inplace=True)
        df.index += 1
        df.to_csv(filename, encoding="utf-8")
        print("[cyan]\[*] data saved to file:[/cyan] [green_yellow]{}".format(filename))
        return None


def style_df(x, green=None, orange=None, red=None):
    """style dataframe series

    colors default value:
        green   - #4cf58c
        orange  - #f5cd4c
        red     - #f54c4c

    TODO: allow passing arguments from abuse class
    """
    # ***** color style *****
    if green is None:
        green = '#4cf58c'
        
    if orange is None:
        orange = '#f5cd4c'
        
    if red is None:
        red = '#f54c4c'

    # add many levels
    if x["abuseConfidenceScore"] >= RED_LEVEL:
        bg_style = ["background-color: {}".format(red)]
    elif YELLOW_LEVEL <= x["abuseConfidenceScore"] < RED_LEVEL:
        bg_style = ["background-color: {}".format(orange)]
    else:
        bg_style = ["background-color: {}".format(green)]

    # ***** other styles *****
    other_styles = ["text-align:right"]

    # ***** total style *****
    total_style = ";".join(bg_style + other_styles)
    return [total_style] * len(x)


def apply_style(df, hide=()):
    """apply style to whole dataframe
    
    hiding columns:
        https://stackoverflow.com/questions/49239476/hide-a-pandas-column-while-using-style-apply
    """
    styles = [
        # table properties
        dict(
            selector="",
            props=[
                ("margin-left", "auto"),
                ("margin-right", "auto"),
                ("width", "80%"),
            ],
        ),
        dict(
            selector="td",
            props=[
                ("border", "1px solid #777"),
                ("border-spacing", "10px"),
                ("padding", "5px"),
            ],
        ),
    ]

    # large tables styling limitations
    # https://github.com/pandas-dev/pandas/issues/39400
    # styled = df.style.apply(style_df, axis=1) \
    styled = (
        Styler(df, uuid_len=0, cell_ids=False)
        .hide(axis='columns', subset=list(hide))
        .apply(style_df, axis=1)
        .set_table_styles(styles, overwrite=True)
    )
    return styled


def get_abuse_directory():
    """create and return a folder in the user's home directory"""
    home_directory = Path.home()
    config_directory = home_directory.joinpath("abuse")
    config_directory.mkdir(exist_ok=True)
    return config_directory


def abuse_banner():
    """abuse cli logo

    pip install art
    from art import *
    for font in ASCII_FONTS:
        art = text2art('abuseipdb-wrapper', font=font)
        print(font)
        print(art)
        input()
    """
    logo = """
            _                        _             _  _
           | |                      (_)           | || |
      __ _ | |__   _   _  ___   ___  _  _ __    __| || |__
     / _` || '_ \ | | | |/ __| / _ \| || '_ \  / _` || '_ \ 
    | (_| || |_) || |_| |\__ \|  __/| || |_) || (_| || |_) |
     \__,_||_.__/  \__,_||___/ \___||_|| .__/  \__,_||_.__/ 
          __      __ _ __   __ _  _ __ | |___    ___  _ __
          \ \ /\ / /| '__| / _` || '_ \|_|'_ \  / _ \| '__|
           \ V  V / | |   | (_| || |_) || |_) ||  __/| |
            \_/\_/  |_|    \__,_|| .__/ | .__/  \___||_|
                                 | |    | |
                                 |_|    |_|
    """

    pypi_url = 'https://pypi.org/project/abuseipdb-wrapper/'
    github_url = 'https://github.com/streanger/abuseipdb-wrapper'
    pip = 'pip install abuseipdb-wrapper'
    horizontal = "================================================================"
    styles = [
        "rgb(191,66,245)",
        "rgb(66,245,93)",
        "rgb(245,242,66)",
        "rgb(245,66,233)",
        "rgb(66,236,245)",
        "rgb(66,66,245)",
        "rgb(84,245,66)",
        "rgb(245,66,66)",
        "rgb(128,82,235)",
    ]
    style = random.choice(styles)
    console = Console()
    console.print(logo, highlight=False, style=style)
    print('home: {}'.format(github_url))
    print(' pip: [cyan]{}[/cyan]'.format(pip))
    print(horizontal)
    print()


def store_api_key(force_new=False):
    """retrieve or store abuseipdb API_KEY

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
        print('[cyan]\[*] using saved API_KEY')
    else:
        try:
            if os.name == 'nt':
                os.system('color')
            prompt_text = '\x1b[36m[>] put your API KEY: \x1b[0m'
            API_KEY = getpass.getpass(prompt=prompt_text)

        except KeyboardInterrupt:
            print()
            print('[yellow]\[x] broken by user')
            return False

        if not API_KEY:
            print('[yellow]\[x] API_KEY not provided')
            return False

        if API_KEY == '\x16':
            print("[yellow]\[x] ctrl+v won't work. Type API_KEY or use right-click to paste it from clipboard")
            return False

        keyring.set_password("abuse", username, API_KEY)
        print('[cyan]\[*] API_KEY saved')
    return API_KEY


def main():
    """main entrypoint"""
    # show banner
    abuse_banner()

    # read API_KEY
    API_KEY = store_api_key()
    if not API_KEY:
        return

    # run abuse viewer
    abuse_directory = get_abuse_directory()
    db_file = abuse_directory.joinpath("abuseipdb.json")
    abuse = AbuseIPDB(API_KEY, db_file=db_file)
    abuse.viewer()


if __name__ == "__main__":
    # ********* abuseipdb API wrapper *********
    API_KEY = Prompt.ask("[cyan]\[>] put your API KEY ")
    abuse = AbuseIPDB(API_KEY=API_KEY, db_file="abuseipdb.json")

    # ********* local db view *********
    columns = [
            "ipAddress",
            "abuseConfidenceScore",
            "totalReports",
            "countryCode",
            "domain",
            "isp",
            "date",
            "url",
        ]
    abuse.apply_columns_order(columns)
    abuse.colors_legend()
    abuse.viewer()
