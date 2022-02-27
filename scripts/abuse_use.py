import sys
import os
from abuseipdb_wrapper import AbuseIPDB


def script_path():
    '''set current path, to script path'''
    current_path = os.path.realpath(os.path.dirname(sys.argv[0]))
    os.chdir(current_path)
    return current_path
    
    
if __name__ == "__main__":
    script_path()
    if os.name == 'nt':
        os.system('color')
        
    # ********* abuseipdb API wrapper *********
    API_KEY = 'YOUR_API_KEY'
    abuse = AbuseIPDB(API_KEY=API_KEY, db_file='abuseipdb.json')
    abuse.colors_legend()
    
    # ********* IP's list *********
    ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12', '13.14.15.16']
    abuse.add_ip_list(ips)
    abuse.check()
    
    # ********* local db view *********
    abuse.apply_columns_order(['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'domain', 'isp'])  # 'url'
    print(abuse)
    abuse.show_db(matched_only=False, table_view=True)
    
    # ********* viewer *********
    abuse.viewer()
    
    # ********* check and return (none stdout if ok) *********
    # abuse = AbuseIPDB(API_KEY=API_KEY)
    # ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12', '13.14.15.16']
    # out = [abuse.check_ip(ip) for ip in ips]
    # abuse.check()
    
    # ********* example of codes in README *********
    # abuse init (API KEY usage); colors legend; show api key use and abuse init first time, in other cases just use abuse object
    # example of local db, iter and show_db method
    # example of print abuse object -> print(abuse)
    # example of check and return (none stdout if ok); no local db used
    # example of viewer and queries; help
    