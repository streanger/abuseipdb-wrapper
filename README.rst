*********************
abuseipdb-wrapper
*********************

Info
#################

- python wrapper for abuseipdb API -> https://docs.abuseipdb.com/#introduction

- allows you to get info about specified IP address(es) abuse
 
- aimed to local db usage, quick query and response

Install
#################

stable version from pypi

.. code-block:: python

    pip install abuseipdb-wrapper

or newest version from github

.. code-block:: python

    pip install git+https://github.com/streanger/abuseipdb-wrapper.git
	
Example usage
#################

- **init `AbuseIPDB` object**
 
  Init ``AbuseIPDB`` object using API KEY created on https://www.abuseipdb.com/. Optionally you can provide `db_file` for your local database. It is recommended becasue this project aims on storing data for further quick access without need of another requests.
	
  .. code-block:: python

    from abuseipdb_wrapper import AbuseIPDB
    API_KEY = 'YOUR_API_KEY'
    # provide API KEY and local db filename
    abuse = AbuseIPDB(API_KEY=API_KEY, db_file='abuseipdb.json')
    abuse.colors_legend()  # show colors legend
	
- **check list of IP's**
    
  Specify list of IP's to check and apply them using ``add_ip_list`` method. Next step run ``check`` method and wait.
    
  .. code-block:: python

    ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12', '13.14.15.16']
    abuse.add_ip_list(ips)
    abuse.check()
	
- **show local db**
    
  To display collected information use ``show_db`` call. Data table should be displayed on terminal. Alternatively call ``print`` on your ``AbuseIPDB`` object. Before showing db you can specifiy columns to be displayed. Do it using ``apply_columns_order`` method.
	
  .. code-block:: python

    abuse.apply_columns_order(
	    ['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'domain', 'isp']
	    )
    print(abuse)
    abuse.show_db(matched_only=False, table_view=True)
	
- **db viewer**
    
  For interactive viewing of IP's and checking them as well use ``viewer`` method. It let you to provide list of IP's or single one. Use help for more information.
    
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
 
- **convert to dataframe object**
 
  .. code-block:: python
    
    df = abuse.get_df(matched_only=False)
	
Screenshots
#################

colors legend

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/abuse-legend.png

interactive viewer help

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/abuse-help-view.png

checking IPs 

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/abuse-live-check.png

showing IPs in vertical mode

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/abuse-vertical-view.png

showing IPs in table mode

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/abuse-table-view.png

Todo/to think of
#################

- black background for better view in powershell

- wrap text in table columns (not only cut off with dots)

- allow for justify/center table
	
- allow for db sorting (specified by user)

- implement more methods accessible from interactive view

- IP ranges for viewer -> 1.2.3.0/24

- make console script
	
- think of more info than 'data' section in api response: reports -> comments, categories
	
- check subnet 1.2.3.4/24 -> https://www.abuseipdb.com/check-block/1.2.3.4/24

- allow passing arguments (colors) for style_df function from abuse class level

Implemented
#################

- html output (from rich table or from pandas df)

- wrap text in table cells - made using rich table

- return dataframe object

- date of last check
