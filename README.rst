*********************
abuseipdb-wrapper
*********************

Info
###########################

- python wrapper for abuseipdb API -> https://docs.abuseipdb.com/#introduction

- gives you informations about abuse level of specified IP addresses

- focused on local db caching and viewing

Install
###########################

stable version from pypi

.. code-block:: bash

    pip install abuseipdb-wrapper

or newest version from github

.. code-block:: bash

    pip install git+https://github.com/streanger/abuseipdb-wrapper.git
	
Command-line usage
###########################

.. code-block:: bash

    abuse

or as module

.. code-block:: bash

    python -m abuseipdb_wrapper

Python usage
###########################

- **init `AbuseIPDB` object**

  Init ``AbuseIPDB`` object using API KEY created on https://www.abuseipdb.com/. Optionally you can provide `db_file` for your local database. It is recommended becasue this project focuses on storing data for further quick access without need of another requests.
	
  .. code-block:: python

    from abuseipdb_wrapper import AbuseIPDB
    API_KEY = 'YOUR_API_KEY'
    abuse = AbuseIPDB(API_KEY=API_KEY, db_file='abuseipdb.json')
    abuse.colors_legend()
	
- **check list of IP's**
    
  Specify list of IP's to check and apply them using ``add_ip_list`` method. Next step run ``check`` method and wait.
    
  .. code-block:: python

    ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12', '13.14.15.16']
    abuse.add_ip_list(ips)
    abuse.check()
    abuse.tor_info_enrich()  # new feature from v.0.1.7
                             # get info about tor exit nodes

- **no db caching approach**

  If you are not interested in caching data in local database and only want to request for IP addresses one by one use the following code.
  Have in mind that `.check_ip` method enriches results and removes `reports` section
  If using wrapper is like overkill in your project, go to: https://docs.abuseipdb.com/?python#check-endpoint

  .. code-block:: python

    from abuseipdb_wrapper import AbuseIPDB
    API_KEY = 'YOUR_API_KEY'
    abuse = AbuseIPDB(API_KEY=API_KEY)
    ips = ['1.2.3.4', '2.3.4.5', '3.4.5.6']
    for IP in ips:
        result = abuse.check_ip()  # enriched with url and request time
        result = abuse.check_ip_orig()  # results in original form
        print(result)

- **show local db**
    
  To display collected information use ``show_db`` call. Data table should be displayed on terminal. Alternatively call ``print`` on your ``AbuseIPDB`` object. Before showing db you can specifiy columns to be displayed. Do it using ``apply_columns_order`` method.
	
  .. code-block:: python

    columns = ['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'domain', 'isp']
    abuse.apply_columns_order(columns)
    # show db by print or using .show_db method
    print(abuse)
    abuse.show_db(matched_only=False, table_view=True)

- **db viewer**
    
  For interactive IPs check and use ``.viewer`` method. It let you to provide list of IP's or single one. Use help for more information.
  
  .. code-block:: python

    abuse.viewer()
    # commands inside interactive view
    columns [columns list]  # shows or apply columns order
    export [csv, html, xlsx]  # export to file
    all  # show all database

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

- **json columns**

  - :code:`abuseConfidenceScore`
  - :code:`countryCode`
  - :code:`date`  # additional
  - :code:`domain`
  - :code:`hostnames`
  - :code:`ipAddress`
  - :code:`ipVersion`
  - :code:`isPublic`
  - :code:`isWhitelisted`
  - :code:`isp`
  - :code:`lastReportedAt`
  - :code:`numDistinctUsers`
  - :code:`totalReports`
  - :code:`url`  # additional
  - :code:`usageType`
  - :code:`isTorNode`  # additional

Screenshots
###########################

cli entrypoint

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/entrypoint.png

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

Ideas
###########################

- wrap text in table columns (not only cut off with dots)

- allow for justify/center table

- allow for db sorting (specified by user)

- IP ranges for viewer -> 1.2.3.0/24

- think of more info than 'data' section in api response: reports -> comments, categories

- check subnet 1.2.3.4/24 -> https://www.abuseipdb.com/check-block/1.2.3.4/24

- allow passing arguments (colors) for style_df function from abuse class level

- export html (from rich)

Changelog
###########################
- `v.0.1.8`:

  - interactive view: enrich tor info no matter of cached value
  - :code:`.swap_api_key:code:` method to change API_KEY
  - pretty banner using rich Panel
  - option for calling module from command line
  - optional API_KEY argument in AbuseIPDB class, which allows you to interact with db
  - using pwinput inside :code:`.store_api_key` which shows asterisks in mask and allows for ctrl+v
  - unique IPs from list keeps order
  - TODO: keep user config in home directory
  - TODO: make sure rich is used for printing
  - TODO: matched command in interactive view - operations refers to matched only:
    - there are XX IPs matched of YY in total
    - to disable/enable matched mode use :code:`matched` command
    - to reset matched IPs type :code:`reset` command 
  - TODO: show command in interactive view - show all items or matched depend on matched flag
  - sumup flag in interactive view
  - force-new command in interactive view
  - info about how many IPs are to be checked in interactive view
  - passing :code:`ip_list` to :code:`AbuseIPDB` class no longer possible

- `v.0.1.7`:

  - `abuse` entrypoint
  - `columns` command in interactive view
  - `export` command in interactive view (to .csv, .html, .xlsx)
  - tor exit nodes enrichment
  - storing db file in user home directory
  - original API request -> `.check_ip_orig`
  - getpass and keyring for API_KEY read & store

- `v.0.1.6` and before:

  - black background for better view in powershell
  - export to html (from pandas df)
  - export to xlsx
  - export to csv
  - wrap text in table cells - made using rich table
  - return dataframe object
  - date of last check
