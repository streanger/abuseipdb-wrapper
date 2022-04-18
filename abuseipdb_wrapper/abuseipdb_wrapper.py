import sys
import os
import re
import time
import datetime
import json
import ipaddress
import requests
import csv
from termcolor import colored


def justify(content, colors_column=None, grid=True, frame=False, enumerator=False, header=False, topbar='', newline='\n', delimiter=';', justsize=4):
    """
    (function comes from juster module from 2019 with a little modification)
    justify(content, colors_column=None, grid=True, frame=False, enumerator=False, header=False, topbar='', newline='\n', delimiter=';', justsize=4)
        convert text to justified
        parameters:
            content - text with newlines and delimiters, to be converted
                      from version 0.1.2 it also can be list(tuple) of lists(tuples)
            grid - True/False value, grid inside; default is True
            frame - True/False value, frame around; default is False
            enumerator - True/False value, will add enumerator column on the left
            header - True/False value, will extract first row from content as header
            topbar - str value. Topbar will be added on the top
            newline - newline symbol; default is '\n'
            delimiter - delimiter symbol; default is ';'
            justsize - justify size; default is 4

        justify(content, grid=True, frame=False, newline='\n', delimiter=';', justsize=4)
        
    TODO: modify function/update juster pypi package
    """
    
    content = [[str(item).strip() for item in row] for row in content]
    maxRow = len(max(content, key=len))
    content = [item + [""]*(maxRow-len(item)) for item in content]
    
    # ********* extract header from content *********
    if header:
        if enumerator:
            headerValue = ['No.'] + content[0]
        else:
            headerValue = content[0]
        content = content[1:]
        
    # ********* add enumerator *********
    if enumerator:
        rowsNumber = len(str(len(content)))
        content = [[str(key+1).zfill(rowsNumber)] + row for key, row in enumerate(content)]
        
    # ********* append header after enumeration *********
    if header:
        content.insert(0, headerValue)
        
    # ********* create transposed *********
    transposed = list(map(list, zip(*content)))
    
    # ********* making table *********
    # characters
    if grid:
        horSign = '|'
    else:
        horSign = ' '
    vertSign = ' '
    lineLen = [max([len(part) for part in item]) for item in transposed]
    
    # justify all columns in the same way
    justifiedParts = [[part.center(lineLen[key]+justsize, vertSign) for key, part in enumerate(item)] for item in content]
    justifiedColoredParts = [[colored(part, *colors_column[index]) for part in item] for index, item in enumerate(justifiedParts)]
    content = [horSign.join(item) for item in justifiedColoredParts]
    
    line = '+'.join(["-"*len(item) for item in justifiedParts[0]])      # with '+' in the cross
    if frame:
        edgeLine = line.join(['+']*2)                                                       # with crosses
        line = line.join(['+']*2)
        content = [item.join(['|']*2) for item in content]
    line = line.join(['\n']*2)
    
    if grid:
        out = line.join(content)
    else:
        out = "\n".join(content)
        
    if frame:
        out = '\n'.join([edgeLine, out, edgeLine])
        
    # ********* add topbar *********
    if not topbar:
        return out
    contentWidth = out.find('\n')
    if contentWidth > 2:
        line = '+' + "-"*(contentWidth-2) + '+'
        sentence = '+' + topbar[:contentWidth-2].upper().center(contentWidth-2, ' ') + '+'
        if frame:
            strTopbar= '\n'.join([line, sentence])
        else:
            strTopbar = '\n'.join([line, sentence, line])
        out = strTopbar + '\n' + out
    return out
    
    
class AbuseIPDB():
    """api"""
    def __init__(self, API_KEY=None, ip_list=None, db_file=None):
        os.system('color')
        if API_KEY is None:
            raise ValueError(colored('[-] no API_KEY specified', 'red'))
        self._API_KEY = API_KEY
        
        if ip_list is None:
            ip_list = []
        valid_list = self.assert_ip_list(ip_list)
        self._ip_list = valid_list
        self.__regular_items = ["abuseConfidenceScore", "countryCode", "domain", "hostnames", "ipAddress", "ipVersion", "isPublic", "isWhitelisted", "isp", "lastReportedAt", "numDistinctUsers", "totalReports", "url", "usageType"]
        self._table_columns_order = ['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'hostnames', 'domain', 'isp']
        self._table_view = True
        
        
        # ********* filename & db *********
        self._db_file = db_file
        if self._db_file is None:
            self._ip_database = {}
        else:
            # ********* read db *********
            try:
                self._ip_database = self._read_json(self._db_file)
            except FileNotFoundError:
                print(colored('[x] file not found: {}, continue with empty db', 'yellow'))
                self._ip_database = {}
            except Exception as err:
                print(colored("[-] couldn't read data from file: {}".format(self._db_file), 'red'))
                raise
                
    @staticmethod
    def colors_legend():
        print(colored('legend:', 'cyan'))
        print(colored('    [*] cyan    - information', 'cyan'))
        print(colored('    [+] green   - things made fine; low level of abuse', 'green'))
        print(colored('    [x] yellow  - warning; medium level of abuse', 'yellow'))
        print(colored('    [-] red     - errors; high level of abuse', 'red'))
        print(colored('    [!] magenta - unexpected things happened', 'magenta'))
        return None
        
    def get_db(self, matched_only=False):
        """return data from db - total or matching to existing ip_list"""
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
            print(colored('[-] ip_list should be type of list or tuple', 'red'))
            raise TypeError
            
        valid_list = []
        for item in ip_list:
            try:
                valid_ip = str(ipaddress.ip_address(item))
                if valid_ip != item:
                    print(colored('[*] conversion: {} -> {}'.format(item, valid_ip), 'cyan'))
                valid_list.append(valid_ip)

            except ValueError as err:
                print(colored('[-] not valid IP address: {}'.format(item), 'red'))
                # raise  # re-throw exception; it may not be needed
        return valid_list
        
    def check_ip(self, ip, max_age_in_days='90'):
        '''check IP(ip) abuse using abuseipdb.com
        typically errors:
            {'errors': [{'detail': 'Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.', 'status': 429}]}
            {'errors': [{'detail': 'The ip address must be a valid IPv4 or IPv6 address (e.g. 8.8.8.8 or 2001:4860:4860::8888).', 'status': 422, 'source': {'parameter': 'ipAddress'}}]}
            {'errors': [{'detail': 'Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.', 'status': 401}]}
        '''
        # ********* Defining the api-endpoint *********
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': max_age_in_days
        }
        headers = {
            'Accept': 'application/json',
            'Key': self._API_KEY
        }
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        
        # ********* Formatted output *********
        decoded = json.loads(response.text)
        errors_status = decoded.get('errors', False)
        if errors_status:
            print(colored('    [-] API errors_status: {}'.format(errors_status), 'red'))
            raise ValueError('AbuseIPDB API error')
        data = decoded['data']
        url = 'https://www.abuseipdb.com/check/{}'.format(ip)
        data['url'] = url
        return data
        
    def _db_str(self, matched_only=True, table_view=True):
        """
        matched_only    -> True     -show only specified IP's
        matched_only    -> False    -show total db
        table_view      -> True     -table view (rows)
        table_view      -> False    -vertical view
        """
        # ********* match choosed *********
        if matched_only:
            matched = self._match_keys(self._ip_database, self._ip_list)
        else:
            matched = self._ip_database
            
        # ********* sort by ipAddress *********
        sorted_matches = sorted(matched.values(), key=lambda x: self._ip_sorter(x['ipAddress']))
        
        # ********* colord table *********
        if table_view:
            db_str_rows = [self._table_columns_order]
            header_color_style = ('cyan', None, ['underline'])  # one item for top row colors
            colors_column = [header_color_style]
            for value in sorted_matches:
                selected_data_row = [value[key] for key in self._table_columns_order]
                db_str_rows.append(selected_data_row)
                
                # ********* colored table *********
                abuse_color = self._abuse_color(value['abuseConfidenceScore'])
                color_pattern = (abuse_color, None, ['reverse'])
                colors_column.append(color_pattern)
                
            db_str = justify(db_str_rows, colors_column=colors_column, frame=True, enumerator=True, header=True, justsize=2)
        else:
            # ********* vertical view *********
            db_str_rows = []
            number_of_ip = len(sorted_matches)
            
            for index, value in enumerate(sorted_matches):
                abuse_color = self._abuse_color(value['abuseConfidenceScore'])
                selected_data_dict = {key:value[key] for key in self._table_columns_order}
                items_str = '\n'.join(['    {}: {}'.format(key.ljust(20), item) for key, item in selected_data_dict.items()])
                colored_items_str = '{}/{}) [{}]\n{}'.format(
                    colored(index+1, abuse_color),
                    colored(number_of_ip, abuse_color),
                    colored(' {} '.format(value['ipAddress']), abuse_color, None, ['reverse']),
                    colored(items_str, abuse_color),
                    )
                db_str_rows.append(colored_items_str)
            db_str = '\n\n'.join(db_str_rows)
        return db_str
        
    def show_db(self, matched_only=False, table_view=True):
        print(self._db_str(matched_only, table_view))
        return None
        
    @staticmethod
    def _match_keys(dict_data, list_keys):
        matched = {key:value for key, value in dict_data.items() if key in list_keys}
        return matched
        
    def apply_columns_order(self, order):
        """apply new columns order for show_db"""
        if not type(order) in (list, tuple):
            print(colored('[-] order should be list or tuple type; type(order): {}'.format(type(order)), 'red'))
            return False
            
        for item in order:
            if not item in self.__regular_items:
                print(colored('[-] wrong item in columns order: {}'.format(item), 'red'))
                return False
        self._table_columns_order = order
        return None
        
    def get_default_columns(self):
        """show json columns (keys) for user to know the order"""
        return self.__regular_items
        
    def toggle_view(self):
        """switch db view -> vertical/table; main purpose is .viewer method, which uses __str__"""
        self._table_view = not self._table_view
        print(colored('[*] self._table_view: {}'.format(self._table_view), 'cyan'))
        return None
        
    def _viewer_help(self):
        print(colored('viewer help:', 'cyan'))
        print(colored('    cls\clear            -clear terminal', 'cyan'))
        print(colored('    exit\quit            -exit from viewer', 'cyan'))
        print(colored('    toggle_view          -toggle table view', 'cyan'))
        print(colored('    toggle_check_live    -check IP live if not in db', 'cyan'))
        print(colored('    all                  -show all IP\'s from db', 'cyan'))
        return None
        
    def viewer(self, check_live=True):
        """interactive viewer
        check_live - if IP is not found in local DB request is being made
        (!) Important: .viewer method resets ._ip_list attribute
        """
        while True:
            try:
                query = input(colored('~< go >~# ', 'cyan', None, ['bold']))
            except KeyboardInterrupt:
                print()
                continue
                
            query = query.strip()
            if not query:
                continue
                
            # ********* execute command *********
            if query in ('exit', 'quit'):
                return None
            elif query in ('cls', 'clear'):
                if os.name == 'nt':
                    os.system('cls')
                else:
                    os.system('clear')
                continue
            elif query == 'toggle_view':
                self.toggle_view()
                continue
            elif query == 'toggle_check_live':
                check_live = not check_live
                print(colored('[*] check_live: {}'.format(check_live), 'cyan'))
                continue
            elif query == 'help':
                self._viewer_help()
                continue
            elif query == 'all':
                query = ' '.join(list(self._ip_database.keys()))
            else:
                pass
                
            # ********* execute query *********
            self.clear_ip_list()
            ips_query = [item.strip('"\' ') for item in re.split(',| |;', query)]
            ips_query = [item for item in ips_query if item]
            self.add_ip_list(ips_query)
            if not self._ip_list:
                print(colored('[x] empty IP list for query', 'yellow'))
                continue
                
            if check_live:
                no_existing = [item for item in self._ip_list if not item in self._ip_database]
                if no_existing:
                    base_ip_list = self._ip_list
                    self.clear_ip_list()
                    self.add_ip_list(no_existing)
                    self.check()
                    self._ip_list = base_ip_list
            else:
                if not self._match_keys(self._ip_database, self._ip_list):
                    print(colored('[x] no results', 'yellow'))
                    continue
            print(self)  # FOR NOW, TO CONSIDER
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
            color = 'red'
        elif 30 <= level < 80:
            color = 'yellow'
        else:
            color = 'green'
        return color
        
    def check(self, display_live=True, force_new=False):
        """iterate over collected IP list
        -think of input/output
        """
        number_of_ip = len(self._ip_list)
        if not number_of_ip:
            print(colored('[*] please add some ip_list for check -> .add_ip_list(ip_list)', 'cyan'))
            return None
            
        print(colored('[*] iteration starts', 'cyan'))
        for index, ip in enumerate(self._ip_list):
            try:
                ip = str(ip)
                # print(colored('{}/{}) {}'.format(index+1, number_of_ip, ip), 'cyan'))
                colored_items_str = '{}/{}) [{}]'.format(
                    colored(index+1, 'cyan'),
                    colored(number_of_ip, 'cyan'),
                    colored(' {} '.format(ip), 'cyan', None, ['reverse']),
                    )
                print(colored_items_str)
                
                # ********* check if exists *********
                data = self._ip_database.get(ip, False)
                if data and not force_new:
                    print_color = self._abuse_color(data['abuseConfidenceScore'])
                    print(colored('    [+] already exists', print_color))
                    continue
                    
                # ********* get & print data *********
                data = self.check_ip(ip)
                if not data:
                    break
                    
                print_color = self._abuse_color(data['abuseConfidenceScore'])
                selected_data_dict = {key:data[key] for key in self._table_columns_order}
                data_str = '\n'.join(['    {}: {}'.format(key.ljust(20), value) for key, value in selected_data_dict.items()])
                print(colored(data_str, print_color))
                
                # ********* update json *********
                self._ip_database[ip] = data
                
            except KeyboardInterrupt:
                print(colored('    [x] broken by user', 'yellow'))
                break
                
            except Exception as err:
                print(colored('    [!] unexpected error catched: {}'.format(err), 'magenta'))
                break
                
            finally:
                # cleanup
                print()
                
        # ********* update db file if provided *********
        if self._db_file is not None:
            self._write_json(self._db_file, self._ip_database)
            print(colored('[*] data saved to file: {}'.format(self._db_file), 'cyan'))
        return None
        
    def __str__(self):
        """print as show_db with matched_only and table_view"""
        return self._db_str(matched_only=True, table_view=self._table_view)
        
    @staticmethod
    def _write_json(filename, data):
        '''write to json file'''
        with open(filename, 'w') as fp:
            # ensure_ascii -> False/True -> characters/u'type'
            json.dump(data, fp, sort_keys=True, indent=4, ensure_ascii=False)
        return True
        
    @staticmethod
    def _read_json(filename):
        '''read json file to dict'''
        data = {}
        try:
            with open(filename) as f:
                data = json.load(f)
        except FileNotFoundError:
            print(colored('[x] file not found: {}'.format(filename), 'yellow'))
        return data
        
    @staticmethod
    def _timestamp():
        '''generate timestamp in string format
        FOR FURTHER USE
        '''
        out = str(datetime.datetime.now())
        return out
        
    @staticmethod
    def _timestamp_to_datetime(str_timestamp):
        '''convert string timestamp to datetime type
        FOR FURTHER USE
        '''
        out = datetime.datetime.strptime(str_timestamp, '%Y-%m-%d %H:%M:%S.%f')
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
            if '.' in ip:
                # IPv4
                return '.'.join([item.zfill(3) for item in ip.split('.')])
            else:
                # IPv6
                return ipaddress.IPv6Address(ip).exploded
        except:
            return ip
        
    def export_csv(self, filename, matched_only=False):
        """export databse to csv file"""
        db_dicts_list = list(self._ip_database.values())
        try:
            keys = db_dicts_list[0].keys()
        except IndexError:
            keys = []
        with open(filename, 'w', newline='') as output_file:
            dict_writer = csv.DictWriter(output_file, keys)
            dict_writer.writeheader()
            dict_writer.writerows(db_dicts_list)
        print(colored('[*] data saved to file: {}'.format(filename), 'cyan'))
        return None
        
        
def main():
    """entry point for script mode; TODO"""
    return None
    
    
if __name__ == "__main__":
    if os.name == 'nt':
        os.system('color')
        
    # ********* abuseipdb API wrapper *********
    API_KEY = input(colored('[>] put your API KEY: ', 'cyan'))
    abuse = AbuseIPDB(API_KEY=API_KEY, db_file='abuseipdb.json')
    
    # ********* local db view *********
    abuse.apply_columns_order(['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'domain', 'isp'])  # 'url'
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
