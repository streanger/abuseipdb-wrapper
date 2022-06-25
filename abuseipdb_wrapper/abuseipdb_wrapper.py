import os
import re
import csv
import json
import datetime
import ipaddress
import requests
from rich import box
from rich import print
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.console import Console


class AbuseIPDB:
    """abuseipdb api wrapper"""

    def __init__(self, API_KEY=None, ip_list=None, db_file=None):
        if API_KEY is None:
            raise ValueError("[red][-] no API_KEY specified")
        self._API_KEY = API_KEY

        if ip_list is None:
            ip_list = []
        valid_list = self.assert_ip_list(ip_list)
        self._ip_list = valid_list
        self.__regular_items = [
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
            "url",
            "usageType",
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
        self._table_view = True
        self.__console = Console(color_system="truecolor")

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
        """show colors legend used in application
        https://newreleases.io/project/pypi/rich/release/5.0.0
        """
        print("[cyan on black]legend:")
        print("[cyan on black]    [*] cyan    - information")
        print("[green on black]    [+] green   - things made fine; low level of abuse")
        print("[yellow on black]    \[x] yellow  - warning; medium level of abuse")
        print("[red on black]    [-] red     - errors; high level of abuse")
        print("[magenta on black]    [!] magenta - unexpected things happened")
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

    def clear_ip_list(self):
        """clear internal ip list"""
        self._ip_list = []
        return None

    @staticmethod
    def assert_ip_list(ip_list):
        """if not valid, throw error"""
        if type(ip_list) not in (list, tuple):
            print("[red][-] ip_list should be type of list or tuple")
            raise TypeError

        valid_list = []
        for item in ip_list:
            try:
                valid_ip = str(ipaddress.ip_address(item))
                if valid_ip != item:
                    print("[cyan][*] conversion: {} -> {}".format(item, valid_ip))
                valid_list.append(valid_ip)

            except ValueError as err:
                print("[red][-] not valid IP address: {}".format(item))
                # raise  # re-throw exception; it may not be needed
        return valid_list

    def check_ip(self, ip, max_age_in_days="90"):
        """check IP(ip) abuse using abuseipdb.com
        typically errors:
            {'errors': [{'detail': 'Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.', 'status': 429}]}
            {'errors': [{'detail': 'The ip address must be a valid IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888).', 'status': 422, 'source': {'parameter': 'ipAddress'}}]}
            {'errors': [{'detail': 'Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.', 'status': 401}]}
        """
        # ********* Defining the api-endpoint *********
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip, "maxAgeInDays": max_age_in_days}
        headers = {"Accept": "application/json", "Key": self._API_KEY}
        response = requests.request(
            method="GET", url=url, headers=headers, params=querystring
        )

        # ********* Formatted output *********
        decoded = json.loads(response.text)
        errors_status = decoded.get("errors", False)
        if errors_status:
            print("[red]    [-] API errors_status: {}".format(errors_status))
            raise ValueError("AbuseIPDB API error")
        data = decoded["data"]
        url = "https://www.abuseipdb.com/check/{}".format(ip)
        data["url"] = url
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
            table_view = self._table_view

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
                    str(value[key]) for key in self._table_columns_order
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
                    key: value[key] for key in self._table_columns_order
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
            table_view = self._table_view
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
                "[red][-] order should be list or tuple type; type(order): {}".format(
                    type(order)
                )
            )
            return False

        for item in order:
            if not item in self.__regular_items:
                print("[red][-] wrong item in columns order: {}".format(item))
                return False
        self._table_columns_order = order
        return None

    def get_default_columns(self):
        """show json columns (keys) for user to know the order"""
        return self.__regular_items

    def toggle_view(self):
        """switch db view -> vertical/table; main purpose is .viewer method, which uses __str__"""
        self._table_view = not self._table_view
        print("[cyan][*] self._table_view: {}".format(self._table_view))
        return None

    def _viewer_help(self):
        """viewer help content"""
        print("[cyan on black]viewer help:")
        print("[cyan on black]    cls\clear            -clear terminal")
        print("[cyan on black]    exit\quit            -exit from viewer")
        print("[cyan on black]    toggle_view          -toggle table view")
        print("[cyan on black]    toggle_check_live    -check IP live if not in db")
        print("[cyan on black]    all                  -show all IP's from db")
        return None

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

            query = query.strip()
            if not query:
                continue

            # ********* execute command *********
            if query in ("exit", "quit"):
                return None
            elif query in ("cls", "clear"):
                if os.name == "nt":
                    os.system("cls")
                else:
                    os.system("clear")
                continue
            elif query == "toggle_view":
                self.toggle_view()
                continue
            elif query == "toggle_check_live":
                check_live = not check_live
                print("[cyan][*] check_live: {}".format(check_live))
                continue
            elif query == "help":
                self._viewer_help()
                continue
            elif query == "all":
                query = " ".join(list(self._ip_database.keys()))
            else:
                pass

            # ********* execute query *********
            self.clear_ip_list()
            ips_query = [item.strip("\"' ") for item in re.split(",| |;", query)]
            ips_query = [item for item in ips_query if item]
            self.add_ip_list(ips_query)
            if not self._ip_list:
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

    def add_ip_list(self, ip_list):
        """add list of IP's to current check"""
        valid_list = self.assert_ip_list(ip_list)
        self._ip_list = list(set(self._ip_list + valid_list))
        return None

    @staticmethod
    def _abuse_color(level):
        """set color depend on abuse level"""
        if level > 80:
            color = "red"
        elif 30 <= level < 80:
            color = "yellow"
        else:
            color = "green"
        return color

    def check(self, force_new=False):
        """iterate over collected IP list
        -think of input/output
        """
        number_of_ip = len(self._ip_list)
        if not number_of_ip:
            print(
                "[cyan][*] please add some ip_list for check -> .add_ip_list(ip_list)"
            )
            return None

        print("[cyan][*] iteration starts")
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
        if self._db_file is not None:
            self._write_json(self._db_file, self._ip_database)
            print("[cyan][*] data saved to file: {}".format(self._db_file))
        return None

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
        """generate timestamp in string format
        FOR FURTHER USE
        """
        out = str(datetime.datetime.now())
        return out

    @staticmethod
    def _timestamp_to_datetime(str_timestamp):
        """convert string timestamp to datetime type
        FOR FURTHER USE
        """
        out = datetime.datetime.strptime(str_timestamp, "%Y-%m-%d %H:%M:%S.%f")
        # ~ out = datetime.datetime.strptime(str_timestamp, '%Y-%m-%d %H:%M:%S')
        return out

    @staticmethod
    def _unix_to_datetime(unix_time):
        """convert unix to datetime
        FOR FURTHER USE
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

    def export_csv(self, filename, matched_only=None):
        """export databse to csv file"""
        if matched_only:
            matched = list(self._match_keys(self._ip_database, self._ip_list).values())
        else:
            matched = list(self._ip_database.values())

        try:
            keys = matched[0].keys()
        except IndexError:
            keys = []
        with open(filename, "w", newline="", encoding="utf-8") as output_file:
            dict_writer = csv.DictWriter(output_file, keys)
            dict_writer.writeheader()
            dict_writer.writerows(matched)
        print("[cyan][*] data saved to file: {}".format(filename))
        return None


def main():
    """entry point for script mode; TODO"""
    return None


if __name__ == "__main__":
    # ********* abuseipdb API wrapper *********
    API_KEY = Prompt.ask("[cyan]\[>] put your API KEY ")
    abuse = AbuseIPDB(API_KEY=API_KEY, db_file="abuseipdb.json")

    # ********* local db view *********
    abuse.apply_columns_order(
        [
            "ipAddress",
            "abuseConfidenceScore",
            "totalReports",
            "countryCode",
            "domain",
            "isp",
        ]
    )  # 'url'
    abuse.colors_legend()
    abuse.viewer()

"""
https://stackoverflow.com/questions/1301346/what-is-the-meaning-of-single-and-double-underscore-before-an-object-name
https://medium.com/linkit-intecs/how-to-build-a-small-command-line-interface-to-store-and-retrieve-data-with-python-database-d6596caff2bf
https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
https://stackoverflow.com/questions/14671487/what-is-the-difference-in-python-attributes-with-underscore-in-front-and-back
https://stackoverflow.com/questions/1535327/how-to-print-instances-of-a-class-using-print
https://nedbatchelder.com/blog/200711/rethrowing_exceptions_in_python.html
https://stackoverflow.com/questions/6505008/dictionary-keys-match-on-list-get-key-value-pair
https://github.com/foutaise/texttable/
https://dev.to/paulshuvo/blessedtable-a-python-package-for-building-colorful-formatted-ascii-tables-45np
https://pypi.org/project/blessedtable/
https://appdividend.com/2022/02/15/how-to-split-string-with-multiple-delimiters-in-python/
https://docs.abuseipdb.com/?python#check-endpoint
https://stackoverflow.com/questions/3086973/how-do-i-convert-this-list-of-dictionaries-to-a-csv-file
https://stackoverflow.com/questions/41983209/how-do-i-add-images-to-a-pypi-readme-that-works-on-github
https://packaging.python.org/en/latest/guides/making-a-pypi-friendly-readme/
https://stackoverflow.com/questions/55597797/detect-whether-current-shell-is-powershell-in-python

legend:
    [*] cyan    - information
    [+] green   - things made fine; low level of abuse
    [x] yellow  - warning; medium level of abuse
    [-] red     - errors; high level of abuse
    [!] magenta - unexpected things happened
    
todo:
    -add last_checked column with time
    -wrap text in table cells (juster modification)
    -show_db - vertical view  (+)
    -check method with regular input and output
    -move whole table to center by spaces (consider)
    -allow for db sorting (by user specify)
    -abuseipdb url -> https://www.abuseipdb.com/check/1.2.3.4
    -ip sorter (+)
    -viewer (+)
    -IP ranges for viewer -> 1.2.3.0/24
    -make console script
    -think of more info than 'data' section in response: reports -> comments, categories
    
example:
    1.2.3.4, 5.6.7.8, 9.10.11.12, 13.14.15.16
    
classes:
    variable    - global attribute
    _variable   - private attribute
    __variable  - very private attribute
    
valid_ip attributes:
    valid_ip.is_global
    valid_ip.is_link_local
    valid_ip.is_loopback
    valid_ip.is_private
    valid_ip.is_multicast
    valid_ip.is_reserved
    valid_ip.is_unspecified
    valid_ip.reverse_pointer
    valid_ip.version
    
"""
