*****************
abuseipdb_wrapper
*****************

Info
#######

- python wrapper for abuseipdb API -> https://docs.abuseipdb.com/#introduction

- one way API - only gets info about IP address abuse
 
- particulary info - data section from API response is parsed and extended with abuseipdb related url
 
- aimed to local db usage, quick query and response

Install
#######

.. code-block:: python

    pip install abuseipdb_wrapper

or

.. code-block:: python

	pip install git+https://github.com/streanger/abuseipdb_wrapper.git
	
Example usage
#############

- **init `AbuseIPDB` object**
 
  Init AbuseIPDB object using API KEY created on https://www.abuseipdb.com/. Optionally you can provide `db_file` for your local database. It is recommended becasue this project aims on storing data for further quick access without need of another requests.
	
  .. code-block:: python

    from abuseipdb_wrapper import AbuseIPDB
    API_KEY = 'YOUR_API_KEY'
    # provide API KEY and local db filename
    abuse = AbuseIPDB(API_KEY=API_KEY, db_file='abuseipdb.json')
    abuse.colors_legend()  # show colors legend
	
- **check list of IP's**
    
  Specify list of IP's to check and apply them using `add_ip_list` method. Next step run `check` method and wait.
    
  .. code-block:: python

    ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12', '13.14.15.16']
    abuse.add_ip_list(ips)
    abuse.check()
	
- **show local db**
    
  To display collected information use `show_db` call. Data table should be displayed on terminal. Alternatively call `print` on your `AbuseIPDB` object. Before showing db you can specifiy columns to be displayed. Do it using `apply_columns_order` method.
	
  .. code-block:: python

    abuse.apply_columns_order(
	    ['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'domain', 'isp']
	    )
    print(abuse)
    abuse.show_db(matched_only=False, table_view=True)
	
- **db viewer**
    
  For interactive viewing of IP's and checking them as well use `viewer` method. It let you to provide list of IP's or single one. Use help for more information.
    
  .. code-block:: python

    abuse.viewer()
	
- **export db to csv file**
 
  .. code-block:: python
    
    abuse.export_csv('out.csv', matched_only=False)
	
- **export db to styled html file**
 
  .. code-block:: python
    
    abuse.export_html_styled('out.html', matched_only=False)
 
- **export db to styled xlsx file**
 
  .. code-block:: python
    
    abuse.export_xlsx_styled('out.xlsx', matched_only=False)
 
Screenshots
###########

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb_wrapper/main/screenshots/colors_legend.png

----

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb_wrapper/main/screenshots/check_example.png

----

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb_wrapper/main/screenshots/viewer_example1.png

----

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb_wrapper/main/screenshots/viewer_example2.png

Update/Todo
###########



todo/think of (25.06.2022)
**********************

- html output (from rich table or from pandas df)
 
- black background for better view in powershell

- wrap text in table columns (not only cut off with dots)
 
todo/think of
**********************

- add last_checked column with containing timestamp
	
- wrap text in table cells (juster/justify modification needed)
	
- allow for justify/center table (consider)
	
- allow for db sorting (specified by user)
	
- IP ranges for viewer -> 1.2.3.0/24
	
- make console script (consider)
	
- think of more info than 'data' section in api response: reports -> comments, categories
	
- check subnet 1.2.3.4/24 -> https://www.abuseipdb.com/check-block/1.2.3.4/24
