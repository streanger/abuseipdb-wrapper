import sys
import os
import time
import types
import json
import requests
import json
import ipaddress
from termcolor import colored


def script_path():
    '''set current path, to script path'''
    current_path = os.path.realpath(os.path.dirname(sys.argv[0]))
    os.chdir(current_path)
    return current_path
    
    
def write_json(filename, data):
    '''write to json file'''
    with open(filename, 'w') as fp:
        # ensure_ascii -> False/True -> characters/u'type'
        json.dump(data, fp, sort_keys=True, indent=4, ensure_ascii=False)
    return True


def read_json(filename):
    '''read json file to dict'''
    data = {}
    try:
        with open(filename) as f:
            data = json.load(f)
    except FileNotFoundError:
        pass
    return data
    
    
def check_ip(ip):
    '''check IP abuse using abuseipdb.com
    error of daily requests:
        {'errors': [{'detail': 'Daily rate limit of 1000 requests exceeded for this endpoint. See headers for additional details.', 'status': 429}]}
    '''
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': 'YOUR_API_KEY'
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    
    # Formatted output
    decoded = json.loads(response.text)
    errors_status = decoded.get('errors', False)
    if errors_status:
        print('errors_status: {}'.format(errors_status))
        return False
    data = decoded['data']
    return data
    
    
def generate_ip_range(start='1.2.'):
    '''just for learning'''
    numbers = [item for item in start.split('.') if item]
    int_status = [item.isdigit() for item in numbers]
    
    if not all(int_status):
        print('error, non integer value passed')
        return []
        
    numbers = [int(item) for item in numbers]
    numbers_len = len(numbers)
    
    if numbers_len == 4:
        return '{}.{}.{}.{}'.format(*numbers)
        
    if numbers_len > 4:
        print('error, too much values')
        return []
        
    begin = '.'.join([str(item) for item in numbers])
    next_octet = [generate_ip_range('{}.{}'.format(begin, x)) for x in range(256)]
    if type(next_octet[0]) is list:
        return [y for x in next_octet for y in x]
    return next_octet
    
    
def show_local_db():
    full_info = False
    
    filename = 'abuseipdb.json'
    ipdb_data = read_json(filename)
    number_of_ip = len(ipdb_data.items())
    for index, (ip, data) in enumerate(ipdb_data.items()):
        if data['abuseConfidenceScore'] > 90:
            print_color = 'red'
        else:
            print_color = 'green'
            
        if full_info or data['abuseConfidenceScore'] > 90:
            data_str = '\n'.join(['    {}: {}'.format(key.ljust(20), value) for key, value in data.items()])
            print(colored('{}/{}) {}\n{}'.format(index+1, number_of_ip, ip, data_str), print_color))
        else:
            print(colored('{}/{}) {}'.format(index+1, number_of_ip, ip), print_color))
    return None
    
    
if __name__ == "__main__":
    script_path()
    os.system('color')
    
    # ****** quick show local db ******
    # if True:
        # show_local_db()
        # sys.exit()
        
    # ****** IP list & setup ******
    # ip_list = list(ipaddress.IPv4Network('81.81.81.0/24'))
    # ip_list = generate_ip_range(start='81.81.0.')
    ip_list = ['81.22.33.44', '81.33.44.55', '81.44.55.66']
    force = False
    filename = 'abuseipdb.json'
    ipdb_data = read_json(filename)
    number_of_ip = len(ip_list)
    print(colored('[*] number_of_ip: {}\n'.format(number_of_ip), 'cyan'))
    
    
    for index, ip in enumerate(ip_list):
        ip = str(ip)
        try:
            # ****** check if exists ******
            data = ipdb_data.get(ip, False)
            if data and not force:
                if data['abuseConfidenceScore'] > 90:
                    print_color = 'red'
                else:
                    print_color = 'green'
                print(colored('{}/{}) {} is already in local db'.format(index+1, number_of_ip, ip), print_color))
                continue
        except Exception as err:
            print('    [x] error catched: {}'.format(err))
            break
            
        try:
            # ****** get & print data ******
            data = check_ip(ip)
            if not data:
                break
                
            if data['abuseConfidenceScore'] > 90:
                print_color = 'red'
            else:
                print_color = 'green'
            data_str = '\n'.join(['    {}: {}'.format(key.ljust(20), value) for key, value in data.items()])
            print(colored('{}/{}) {}\n{}'.format(index+1, number_of_ip, ip, data_str), print_color))
            print()
            
            # ****** update json ******
            ipdb_data[ip] = data
            time.sleep(0.1)
            
        except KeyboardInterrupt:
            print('    [x] broken by user')
            break
            
        except Exception as err:
            print('   [x] error catched: {}'.format(err))
            break
            
            
    # ****** save json ******
    write_json(filename, ipdb_data)
    print(colored('\n[*] data saved to file: {}'.format(filename), 'cyan'))
    
    
'''
data output:
    ('ipAddress', '81.69.248.82')
    ('isPublic', True)
    ('ipVersion', 4)
    ('isWhitelisted', False)
    ('abuseConfidenceScore', 100)
    ('countryCode', 'CN')
    ('usageType', 'Data Center/Web Hosting/Transit')
    ('isp', 'Tencent Cloud Computing (Beijing) Co. Ltd')
    ('domain', 'tencent.com')
    ('hostnames', [])
    ('totalReports', 969)
    ('numDistinctUsers', 251)
    ('lastReportedAt', '2021-04-03T21:07:32+00:00')

'''
