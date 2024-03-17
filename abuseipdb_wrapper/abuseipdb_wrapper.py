import datetime
import ipaddress
import os
import random
import re
from pathlib import Path

# 3rd party modules
import pandas as pd
import requests
from pandas.io.formats.style import Styler
from rich.columns import Columns
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

# my modules
from abuseipdb_wrapper.__version__ import __version__
from abuseipdb_wrapper.logger import (CYAN, GREEN, HIGH, INFO_COLOR, IP_COLOR,
                                      RED, RED_LEVEL, YELLOW, YELLOW_LEVEL,
                                      console, log, print)
from abuseipdb_wrapper.utils import (get_abuse_directory, read_json,
                                     remove_duplicates_keep_order,
                                     store_api_key, write_file, write_json)


class Config():
    def __init__(self, config_file=None, verbose=None) -> None:
        self._all_columns = [
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
            "usageType",
            "url",  # additional (abuseipdb related url)
            "date",  # additional (date of request)
            "isTor",
        ]
        self._init_columns = [
            "ipAddress",
            "abuseConfidenceScore",
            "totalReports",
            "countryCode",
            "hostnames",
            "domain",
            "isp",
        ]
        self._config_file = config_file
        self.config = self._load_config(self._config_file, verbose)
        log.verbose = self.config["verbose"]
        if self._config_file is None:
            self._store = False
        else:
            self._store = True

    def _load_config(self, config_file, verbose):
        if config_file is None:
            config = {}
        else:
            config = read_json(config_file)
        config.setdefault("columns", self._init_columns)
        config.setdefault("view", True)
        config.setdefault("force", False)
        config.setdefault("live", True)
        config.setdefault("sumup", True)
        if verbose is None:
            config.setdefault("verbose", False)
        else:
            config["verbose"] = verbose
        config.setdefault("skip", True)
        return config

    def _update_config(self):
        if self._store:
            write_json(self._config_file, self.config)

    def _set_key(self, key: str, value):
        """set config key"""
        self.config[key] = value
        self._update_config()

    def _toggle_key(self, key: str):
        """toggle config key"""
        new_value = not self.config[key]
        self.config[key] = new_value
        print(f"[{CYAN}]\[*] [{HIGH}]{key}[/{HIGH}] set to:[/{CYAN}] {new_value}")
        self._update_config()

    def set_columns(self, order: list | tuple):
        """set new columns order"""
        if not type(order) in (list, tuple):
            log(f"[{RED}]\[-] order should be list or tuple type; type(order): {type(order)}[/{RED}]")
            return False

        if not order:
            return False

        for item in order:
            if not item in self._all_columns:
                log(f"[{RED}]\[-] wrong item in columns order: {item}[/{RED}]")
                return False
        self.config["columns"] = order
        self._update_config()
        return True

    def get_all_columns(self):
        """return all columns list"""
        return self._all_columns

    def get_init_columns(self):
        """return init columns list"""
        return self._init_columns


class AbuseIPDB(Config):
    """abuseipdb api wrapper"""

    def __init__(
        self,
        *,
        api_key=None,
        db_file=None,
        config_file=None,
        verbose=None,
        ip_list=None,
    ):
        # ***** load config *****
        super().__init__(config_file=config_file, verbose=verbose)

        # ***** setup *****
        self._api_key = api_key
        self._ip_list = []
        if ip_list is not None:
            self.add_ip_list(ip_list=ip_list)
        self._abuse_domain = 'https://api.abuseipdb.com'
        self._matched_only = False

        # ***** filename & db *****
        self._db_file = db_file
        if self._db_file is None:
            self._path = Path().cwd()
            self._ip_database = {}
        else:
            # ***** read db *****
            self._path = Path(self._db_file).parent.absolute()
            try:
                self._ip_database = read_json(self._db_file)
            except FileNotFoundError:
                print(f"[{YELLOW}]\[x] file not found: {self._db_file}, continue with empty db[/{YELLOW}]")
                self._ip_database = {}
            except Exception as err:
                print(f"[{RED}]\[-] couldn't read data from file: {self._db_file}[/{RED}]")
                raise

    def colors_legend(self):
        """show colors legend used in application"""
        legend_lines = [
            f"[{CYAN}]legend:[/{CYAN}]",
            f"[{CYAN}]  [*] cyan    - information[/{CYAN}]",
            f"[{GREEN}]  [+] green   - fine; low level of abuse[/{GREEN}]",
            f"[{YELLOW}]  \[x] yellow  - warning; medium level of abuse[/{YELLOW}]",
            f"[{RED}]  [-] red     - errors; high level of abuse[/{RED}]",
        ]
        lines_joined = "\n".join(legend_lines)
        legend = Panel(lines_joined, style="on grey0", border_style="royal_blue1", width=62)
        console.print(legend)

    def get_db(self, matched_only=None):
        """return data from db - total or matching to current ip_list"""
        if matched_only is None:
            matched_only = self._matched_only

        if matched_only:
            matched = self._match_keys(self._ip_database, self._ip_list)
        else:
            matched = self._ip_database
        return matched

    def add_ip_list(self, ip_list):
        """add list of IPs to current check"""
        valid_list = self.assert_ip_list(ip_list)
        self._ip_list = remove_duplicates_keep_order(self._ip_list + valid_list)
        return None

    def assert_ip_list(self, ip_list):
        """if not valid, throw error"""
        if type(ip_list) not in (list, tuple):
            log("[{RED}]\[-] ip_list should be type of list or tuple[/{RED}]")
            raise TypeError

        valid_list = []
        skipped = 0
        for item in ip_list:
            try:
                valid_ip = str(ipaddress.ip_address(item))
                if valid_ip != item:
                    log(f"[{CYAN}]\[*] conversion: {item} -> {valid_ip}")
                if self.config["skip"] and ipaddress.ip_address(item).is_private:
                    skipped += 1
                    continue
                valid_list.append(valid_ip)

            except ValueError as err:
                log(f"[{RED}]\[-] invalid IP address: {item}[/{RED}]")
        if skipped:
            log(f"[{CYAN}][*] skipped private IPs number: {skipped}[/{CYAN}]")
        return valid_list

    def clear_ip_list(self):
        """clear internal ip list"""
        self._ip_list = []
        return None

    def check_ip_orig(self, ip, max_age_in_days="90", verbose=False):
        """checks IP abuse using abuseipdb.com in original manner. No caching data approach

        docs: https://docs.abuseipdb.com/?python#check-endpoint
        from docs:
            Omitting the verbose flag will exclude reports and the country name field.
            If you want to keep your response payloads light, this is recommended.
        """
        if not self._api_key:
            raise Exception("API key not set")

        # **** Defining the api-endpoint ****
        url = self._abuse_domain + "/api/v2/check"
        # IMPORTANT:
        # including verbose flag in querystring will casue including reports
        # (as well as country name) in response no matter of True/False
        # so have it in mind
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
        headers = {"Accept": "application/json", "Key": self._api_key}
        response = requests.request(
            method="GET", url=url, headers=headers, params=querystring
        )
        return response.json()

    def check_ip(self, ip, max_age_in_days="90"):
        """checks IP abuse using abuseipdb.com and adds url & date fields and removes reports. No caching data approach

        docs: https://docs.abuseipdb.com/?python#check-endpoint
        typically errors:
            {'errors': [{'detail': 'Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.', 'status': 429}]}
            {'errors': [{'detail': 'The ip address must be a valid IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888).', 'status': 422, 'source': {'parameter': 'ipAddress'}}]}
            {'errors': [{'detail': 'Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.', 'status': 401}]}
        """
        decoded = self.check_ip_orig(ip, max_age_in_days)
        errors_status = decoded.get("errors", False)
        if errors_status:
            print(f"[{RED}]    [-] API errors_status: {errors_status}[/{RED}]")
            raise ValueError("AbuseIPDB API error")
        data = decoded["data"]
        data["url"] = f"https://www.abuseipdb.com/check/{ip}"
        data["date"] = self._timestamp()
        return data

    def _log_table(self, table):
        """Generate an ascii formatted presentation of a Rich table
        Eliminates any column styling
        https://github.com/Textualize/rich/discussions/1799
        """
        with console.capture() as capture:
            console.print(table)
        return Text.from_ansi(capture.get())

    def _create_view(self, matched_only=None, table_view=None):
        """
        matched_only    -> True     -show only specified IPs
        matched_only    -> False    -show total db
        table_view      -> True     -table view (rows)
        table_view      -> False    -vertical view
        """
        # **** match choosed ****
        if matched_only is None:
            matched_only = self._matched_only

        if table_view is None:
            table_view = self.config["view"]

        if matched_only:
            matched = self._match_keys(self._ip_database, self._ip_list)
        else:
            matched = self._ip_database

        # return nothing if no match
        if not matched:
            return ''

        # **** sort by ipAddress ****
        sorted_matches = sorted(matched.values(), key=lambda x: self._ip_sorter(x["ipAddress"]))

        # **** colored table ****
        if table_view:
            border_style = "blue on grey0"
            header_style = "bold green_yellow on royal_blue1"
            view = Table(border_style=border_style, header_style=header_style)

            # **** columns ****
            column_on_style = "on grey0"
            view.add_column("No", style=f"green_yellow {column_on_style}")
            for column in self.config["columns"]:
                view.add_column(column, style=f"royal_blue1 {column_on_style}")

            # **** rows ****
            for index, value in enumerate(sorted_matches, start=1):
                selected_data_row = [str(value.get(key, "")) for key in self.config["columns"]]
                abuse_color = self._abuse_color(value["abuseConfidenceScore"])
                view.add_row(str(index), *selected_data_row, style=abuse_color)
        else:
            # **** vertical view ****
            db_str_rows = []
            number_of_ip = len(sorted_matches)
            for index, value in enumerate(sorted_matches, start=1):
                abuse_color = self._abuse_color(value["abuseConfidenceScore"])
                selected_data_dict = {key: value.get(key, "") for key in self.config["columns"]}
                items_str = "\n".join([f"    {key:<20}: {value}" for key, value in selected_data_dict.items()])
                colored_items_str = "[{0}]{1}/{2})[/{0}] [[{5} on {0}] {3} [/{5} on {0}]]\n[{0}]{4}[/{0}]".format(
                    abuse_color,
                    index,
                    number_of_ip,
                    value["ipAddress"],
                    items_str,
                    IP_COLOR,
                )
                db_str_rows.append(colored_items_str)
            view = "\n\n".join(db_str_rows)
        return view

    def show(self, matched_only=None, table_view=None):
        """show database in nice format"""
        if matched_only is None:
            matched_only = self._matched_only
        if table_view is None:
            table_view = self.config["view"]
        console.print(self._create_view(matched_only, table_view), highlight=False)
        return None

    @staticmethod
    def _match_keys(dict_data, list_keys):
        matched = {
            key: value
            for key, value in dict_data.items()
            if key in list_keys
        }
        return matched

    def _viewer_help(self):
        """interactive viewer help content"""
        # commands -> (cmd, description, cmd_type)
        commands = [
            ("all", "show/check all IPs from db", None),
            ("banner", "show welcome banner", None),
            ("cls|clear", "clear terminal", None),
            ("columns [columns-list]", "shows/apply columns order", 'params'),
            ("exit|quit", "exit from viewer", None),
            ("export [csv|html|xlsx|md]", "export all/matched IPs to file", 'params'),
            ("force", "force IP check", 'flag'),
            ("help", "show this help message", None),
            ("key", "change API_KEY", None),
            ("legend", "show colors legend", None),
            ("live", "check IP live if not in db", 'flag'),
            ("path", "shows path to db file", None),
            ("skip", "skip private IPs from check", 'flag'),
            ("sumup", "show sumup after check", 'flag'),
            ("view", "switch between table and vertical view", 'flag'),
            ("verbose", "show verbose informations", 'flag'),
        ]

        # justify
        justified = []
        for (cmd, description, cmd_type) in commands:
            if cmd_type == 'flag':
                status = self.config[cmd]
                cmd = f'{cmd} ({status})'
            elif cmd_type == 'params':
                cmd, params = cmd.split(None, maxsplit=1)
                params = params.strip('[]')
                cmd = f'{cmd} \[[{HIGH}]{params}[/{HIGH}]]'
                cmd = cmd.ljust(58)
            else:
                pass
            cmd = f'{cmd:<28}'
            row = f"  {cmd} - {description}"
            justified.append(row)

        # pretty print
        joined = "\n".join(justified)
        message = f"commands:\n{joined}"
        legend = Columns([Panel(message, style=INFO_COLOR, border_style="royal_blue1", highlight=True)])
        console.print(legend)

    def viewer(self):
        """interactive viewer

        check_live - if IP is not found in local DB request is being made
        (!) Important: .viewer method resets ._ip_list attribute
        """
        prompt = f"[{CYAN}]~< abuse >~"
        while True:
            try:
                query = Prompt.ask(prompt=prompt)
            except KeyboardInterrupt:
                print()
                continue

            full_query = query.strip()
            if not full_query:
                continue
            query, *rest = full_query.split()

            # **** execute command ****
            if query in ("exit", "quit"):
                return None
            elif query in ("cls", "clear"):
                if os.name == 'nt':
                    os.system('cls')
                else:
                    os.system('clear')
                continue
            elif query == "view":
                self._toggle_key("view")
                continue
            elif query == "verbose":
                self._toggle_key("verbose")
                log.verbose = self.config["verbose"]
                continue
            elif query == "live":
                self._toggle_key("live")
                continue
            elif query == "skip":
                self._toggle_key("skip")
                continue
            elif query == "sumup":
                self._toggle_key("sumup")
                continue
            elif query == "force":
                self._toggle_key("force")
                continue
            elif query == "banner":
                abuse_banner()
                continue
            elif query == "help":
                self._viewer_help()
                continue
            elif query == "all":
                # IMPORTANT: modify full_query, not just query
                full_query = " ".join(list(self._ip_database.keys()))
            elif query == "path":
                print(f"[{CYAN}]\[*] database file:[/{CYAN}] [{HIGH}]{self._path}[/{HIGH}]")
                continue
            elif query == "columns":
                if rest:
                    # sanitize passed columns
                    regular_items_mapping = {item.lower(): item for item in self._all_columns}
                    new_order = [
                        regular_items_mapping[item.lower()]
                        for item in rest
                        if item.lower() in regular_items_mapping
                    ]
                    new_order = remove_duplicates_keep_order(new_order)
                    if not new_order:
                        print(f"[{YELLOW}]\[x] no valid columns passed[/{YELLOW}]")
                        continue

                    # set new columns order
                    self.set_columns(new_order)
                    highlighted = [f"[{HIGH}]{item}[/{HIGH}]" for item in new_order]
                    highlighted = " ".join(highlighted)
                    print(f"[{CYAN}]\[*] new columns order:[/{CYAN}] {highlighted}")
                else:
                    # show current columns order
                    regular = self._all_columns.copy()
                    current_order = {item: True for item in self.config["columns"]}
                    not_used_order = {item: False for item in regular if not item in self.config["columns"]}
                    highlighted = [f"[{HIGH}]{item}[/{HIGH}]" for item in current_order]
                    highlighted = " ".join(highlighted)
                    current_order.update(not_used_order)

                    # show table
                    columns = Table(title="", header_style=INFO_COLOR, border_style="royal_blue1", style=INFO_COLOR, highlight=True)
                    columns.add_column("Column", style=INFO_COLOR, justify="right")
                    columns.add_column("Status", style=INFO_COLOR, justify="right")
                    for column, status in current_order.items():
                        columns.add_row(column, str(status))
                    print(columns)

                    # show list of columns
                    availabe_columns = " ".join(self._all_columns)
                    print(f"[{CYAN}]\[*] availabe columns:[/{CYAN}] {availabe_columns}")
                    print(f"[{CYAN}]\[*] current order:[/{CYAN}] {highlighted}")
                continue
            elif query == "export":
                if not rest:
                    print(f"[{YELLOW}]\[x] no file or file format specfied[/{YELLOW}]")
                    continue

                # create proper path
                path = Path(rest[0])
                allowed = ('csv', 'html', 'xlsx', 'md', '.csv', '.html', '.xlsx', '.md')
                if not (path.suffix in allowed or str(path) in allowed):
                    print(f"[{YELLOW}]\[x] unrecognized format; choose from: <csv|html|xlsx|md>[/{YELLOW}]")
                    continue
                if path.is_absolute():
                    # we use current path as output
                    pass
                else:
                    directory = Path(self._db_file or ".").parent.absolute()
                    if str(path) in allowed:
                        suffix = str(path).strip('.')
                        path = directory.joinpath(f"abuse.{suffix}")
                    else:
                        path = directory / path
                path.parent.mkdir(exist_ok=True, parents=True)

                # export to specified file type
                matched_only = bool(self._ip_list)  # auto-detect
                if path.suffix == ".csv":
                    self.export_csv(path, matched_only=matched_only)
                elif path.suffix == ".html":
                    self.export_html_styled(path, matched_only=matched_only)
                elif path.suffix == ".xlsx":
                    self.export_xlsx_styled(path, matched_only=matched_only)
                elif path.suffix == ".md":
                    self.export_md(path, matched_only=matched_only)
                continue
            elif query == "key":
                API_KEY = store_api_key(force_new=True)
                if API_KEY:
                    self._api_key = API_KEY
                    print(f"[{CYAN}]\[*] new API_KEY assigned[/{CYAN}]")
                continue
            elif query == "legend":
                self.colors_legend()
                continue
            else:
                pass

            # **** execute query ****
            self.clear_ip_list()
            ips_query = [item.strip("\"' ") for item in re.split(",| |;", full_query)]
            ips_query = [item for item in ips_query if item]
            self.add_ip_list(ips_query)
            if not self._ip_list:
                log(f"[{YELLOW}]\[x] empty IP list for query[/{YELLOW}]")
                continue

            if self.config["live"]:
                if self.config["force"]:
                    to_check = self._ip_list
                else:
                    to_check = [item for item in self._ip_list if not item in self._ip_database]
                log(f"[{CYAN}]\[*] {len(to_check)} IPs of {len(self._ip_list)} unique passed will be checked[/{CYAN}]")
                if to_check:
                    base_ip_list = self._ip_list
                    self.clear_ip_list()
                    self.add_ip_list(to_check)
                    self.check(force_new=self.config["force"])
                    self._ip_list = base_ip_list
                else:
                    log(f"[{CYAN}]\[*] force disabled. To enable type[/{CYAN}] [{HIGH}]force[/{HIGH}]")
            else:
                log(f"[{CYAN}]\[*] live disabled. To enable type[/{CYAN}] [{HIGH}]live[/{HIGH}]")

            # **** sumup ****
            if self.config["sumup"]:
                if not self._match_keys(self._ip_database, self._ip_list):
                    log(f"[{CYAN}]\[*] nothing to sumup")
                else:
                    log(f"[{CYAN}][*] sumup:[/{CYAN}]")
                    self.show(matched_only=True)
            else:
                log(f"[{CYAN}]\[*] sumup disabled. To enable type[/{CYAN}] [{HIGH}]sumup[/{HIGH}]")
        return None

    @staticmethod
    def _abuse_color(level):
        """set color depend on abuse level"""
        if level >= RED_LEVEL:
            color = RED
        elif YELLOW_LEVEL <= level < RED_LEVEL:
            color = YELLOW
        else:
            color = GREEN
        return color

    def check(self, force_new=False):
        """iterate over collected IP list. It caches results in memory"""
        number_of_ip = len(self._ip_list)
        if not number_of_ip:
            log(f"[{CYAN}]\[*] add some IPs for check -> .add_ip_list(ip_list)[/{CYAN}]")
            return None

        log(f"[{CYAN}]\[*] iteration starts[/{CYAN}]")
        for index, ip in enumerate(self._ip_list, start=1):
            try:
                ip = str(ip)
                colored_items_str = (
                    "[{0}]{1}/{2})[/{0}] [[{0} reverse] {3} [/{0} reverse]]".format(
                        CYAN,
                        index,
                        number_of_ip,
                        ip,
                    )
                )
                print(colored_items_str)

                # **** check if exists ****
                data = self._ip_database.get(ip, False)
                if data and not force_new:
                    print_color = self._abuse_color(data["abuseConfidenceScore"])
                    print(f"[{print_color}]    [+] already exists[/{print_color}]")
                    continue

                # **** get & print data ****
                data = self.check_ip(ip)
                if not data:
                    break

                print_color = self._abuse_color(data["abuseConfidenceScore"])
                selected_data_dict = {key: data[key] for key in self.config["columns"]}
                data_str = "\n".join([f"    {key:<20}: {value}" for key, value in selected_data_dict.items()])
                print(f"[{print_color}]{data_str}[/{print_color}]")

                # **** update json ****
                self._ip_database[ip] = data

            except KeyboardInterrupt:
                print(f"[{YELLOW}]    \[x] broken by user[/{YELLOW}]")
                break

            except Exception as err:
                print(f"[{RED}]    \[-] error catched: {err}[/{RED}]")
                break

            finally:
                # cleanup
                print()

        # **** update db file if provided ****
        self.update_local_db()
        return None

    def update_local_db(self):
        """update local db with current results"""
        if self._db_file is None:
            return
        write_json(self._db_file, self._ip_database)
        log(f"[{CYAN}]\[*] data saved to file:[/{CYAN}] [{HIGH}]{self._db_file}[/{HIGH}]")

    def __str__(self):
        """returns view plain text"""
        view = self._create_view(matched_only=None, table_view=None)
        plain_text = self._log_table(view).plain
        return plain_text

    @staticmethod
    def _timestamp():
        """generate timestamp in string format"""
        out = str(datetime.datetime.now())
        return out

    @staticmethod
    def _timestamp_to_datetime(str_timestamp):
        """convert string timestamp to datetime type"""
        out = datetime.datetime.strptime(str_timestamp, "%Y-%m-%d %H:%M:%S.%f")
        return out

    @staticmethod
    def _unix_to_datetime(unix_time):
        """convert unix to datetime"""
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

    def export_wrapper(func):
        def wrapper(*args, **kwargs):
            # load matched
            self = args[0]
            matched_only = kwargs.get('matched_only')
            if matched_only:
                matched = self._match_keys(self._ip_database, self._ip_list).values()
            else:
                matched = self._ip_database.values()

            # log how many data will be exported
            log(f"[{CYAN}]\[*] exporting [{HIGH}]{len(matched)}[/{HIGH}] of [{HIGH}]{len(self._ip_database)}[/{HIGH}] items from db[/{CYAN}]")
            kwargs['matched'] = matched
            result = func(*args, **kwargs)

            # log saved if function executed correctly
            if result:
                path = kwargs.get('path') or args[1]
                print(f"[{CYAN}]\[*] data saved to file:[/{CYAN}] [{HIGH}]{path}[/{HIGH}]")
            return result
        return wrapper

    @export_wrapper
    def export_html_styled(self, path, matched_only=None, matched=None, xlsx=False):
        """export database to styled html file under specified path using pandas"""
        # create dataframe; filter columns, clickable url & sorting
        df = pd.DataFrame(matched)
        if not set(self.config["columns"]).issubset(df.columns):
            print(f"[{YELLOW}]\[x] nothing to export[/{YELLOW}]")
            return False

        # handle lack of abuseConfidenceScore
        hide = []
        ABUSE_CONFIDENCE_SCORE = "abuseConfidenceScore"
        if ABUSE_CONFIDENCE_SCORE not in self.config["columns"]:
            self.config["columns"].append(ABUSE_CONFIDENCE_SCORE)
            hide = [ABUSE_CONFIDENCE_SCORE]

        df = df[self.config["columns"]]
        df.fillna("", inplace=True)
        if not xlsx and "url" in df.columns:
            df["url"] = [f"<a href={item}>{item}</a>" for item in df["url"]]
        if "ipAddress" in df.columns:
            df["ip_sorter"] = df["ipAddress"].apply(lambda x: self._ip_sorter(x))
            df.sort_values(["ip_sorter"], ascending=[True], inplace=True)
            df.drop(columns="ip_sorter", inplace=True)
            df.reset_index(drop=True, inplace=True)
            df.index += 1
        else:
            df.index += 1

        # create styled object & export it to file
        styled = apply_style(df, hide=hide)

        # hide cleanup
        for hidden in hide:
            self.config["columns"].remove(hidden)

        if xlsx:
            # to xlsx
            styled.to_excel(path, engine="openpyxl", columns=self.config["columns"])
        else:
            # to html
            html = styled.to_html(render_links=True, escape=False)
            write_file(path, html)
        return True

    def export_xlsx_styled(self, path, matched_only=None):
        """export database to styled xlsx file under specified path using pandas"""
        self.export_html_styled(path, matched_only=matched_only, xlsx=True)

    @export_wrapper
    def export_md(self, path, matched_only=None, matched=None):
        """export databse to markdown file under specified path"""
        # create dataframe; filter columns
        df = pd.DataFrame(matched)
        if not set(self.config["columns"]).issubset(df.columns):
            print(f"[{YELLOW}]\[x] nothing to export[/{YELLOW}]")
            return False
        df = df[self.config["columns"]]
        df.fillna("", inplace=True)
        df.index += 1
        md = df.to_markdown()
        Path(path).write_text(md, encoding='utf-8')
        return True

    @export_wrapper
    def export_csv(self, path, matched_only=None, matched=None):
        """export databse to csv file under specified path"""
        # create dataframe; filter columns
        df = pd.DataFrame(matched)
        if not set(self.config["columns"]).issubset(df.columns):
            print(f"[{YELLOW}]\[x] nothing to export[/{YELLOW}]")
            return False
        df = df[self.config["columns"]]
        df.fillna("", inplace=True)
        df.index += 1
        df.to_csv(path, encoding="utf-8")
        return True


def style_df(x, green=None, orange=None, red=None):
    """style dataframe series

    colors default value:
        green   - #4cf58c
        orange  - #f5cd4c
        red     - #f54c4c
    """
    # ***** color style *****
    if green is None:
        green = "#4cf58c"

    if orange is None:
        orange = "#f5cd4c"

    if red is None:
        red = "#f54c4c"

    # add many levels
    if x["abuseConfidenceScore"] >= RED_LEVEL:
        bg_style = [f"background-color: {red}"]
    elif YELLOW_LEVEL <= x["abuseConfidenceScore"] < RED_LEVEL:
        bg_style = [f"background-color: {orange}"]
    else:
        bg_style = [f"background-color: {green}"]

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
        .hide(axis="columns", subset=list(hide))
        .apply(style_df, axis=1)
        .set_table_styles(styles, overwrite=True)
    )
    return styled


def abuse_banner():
    """abuse cli logo"""
    pypi_url = "https://pypi.org/project/abuseipdb-wrapper/"
    github_url = "https://github.com/streanger/abuseipdb-wrapper"
    pypi = "pip install abuseipdb-wrapper"
    logo = f"""\
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
[{CYAN}]\
 v.{__version__}
 home: [blue underline]{github_url}[/blue underline]
 pypi: {pypi}\
[/{CYAN}]"""
    logo = Panel(logo, style="on grey0", border_style="royal_blue1", expand=False)

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
    console.print(logo, highlight=False, style=style)
    print()


def main():
    """main entrypoint"""
    # setup
    abuse_banner()
    API_KEY = store_api_key()

    # run abuse viewer
    abuse_directory = get_abuse_directory()
    db_file = abuse_directory.joinpath("abuse.json")
    config_file = abuse_directory.joinpath("config.json")
    abuse = AbuseIPDB(api_key=API_KEY, db_file=db_file, config_file=config_file)
    abuse.viewer()


if __name__ == "__main__":
    # **** abuseipdb API wrapper ****
    API_KEY = store_api_key()
    abuse = AbuseIPDB(api_key=API_KEY, db_file="abuse.json")

    # **** local db view ****
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
    abuse.set_columns(columns)
    abuse.colors_legend()
    abuse.viewer()
