*********************
abuseipdb-wrapper
*********************

Info
###########################

- python wrapper for abuseipdb API (https://docs.abuseipdb.com/#introduction)

- gives you informations about abuse level of specified IP addresses

- focuses on caching results in local db

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

  Init ``AbuseIPDB`` object using API KEY created on https://www.abuseipdb.com/. Optionally you can provide `db_file` for your local database. It is recommended because this project focuses on storing data for further quick access without need of another requests.

  .. code-block:: python

    from abuseipdb_wrapper import AbuseIPDB
    API_KEY = 'YOUR_API_KEY'
    abuse = AbuseIPDB(api_key=API_KEY, db_file='abuseipdb.json')
    abuse.colors_legend()

- **check list of IPs**

  Specify list of IPs to be checked using ``add_ip_list`` method. Then call ``check`` method and wait for results. You can enrich your results about TOR nodes info using ``tor_info_enrich`` methods.

  .. code-block:: python

    ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12', '13.14.15.16']
    abuse.add_ip_list(ips)
    abuse.check()
    abuse.tor_info_enrich()

- **no db caching approach**

  If you are not interested in caching data in local database and only want to request for IP addresses one by one use the following code.
  Have in mind that `.check_ip` method enriches results and removes `reports` section.
  If using wrapper is like overkill in your project, go to: https://docs.abuseipdb.com/?python#check-endpoint

  .. code-block:: python

    from abuseipdb_wrapper import AbuseIPDB
    API_KEY = 'YOUR_API_KEY'
    abuse = AbuseIPDB(api_key=API_KEY)
    ips = ['1.2.3.4', '2.3.4.5', '3.4.5.6']
    for IP in ips:
        result = abuse.check_ip()  # enriched with url and request time
        result = abuse.check_ip_orig()  # results in original form
        print(result)

- **show local db**

  To display collected informations use ``show`` method. Alternatively call ``print`` on your ``AbuseIPDB`` object. You can specify columns to be displayed using ``apply_columns_order`` method. It affects both vertical and table view.

  .. code-block:: python

    columns = ['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'domain', 'isp']
    abuse.apply_columns_order(columns)
    # show db by print or using .show method
    print(abuse)
    abuse.show(matched_only=False, table_view=True)

- **viewer**

  For interactive IP check use ``.viewer`` method. It let you to provide multiple IPs at once. Use help for more information.

  .. code-block:: python

    abuse.viewer()
    ~< abuse >~: columns [columns list]         # shows or apply columns order
    ~< abuse >~: export [csv, html, xlsx, md]   # export to file
    ~< abuse >~: all                            # check/show all database

- **exports**

  .. code-block:: python

    abuse.export_csv('out.csv', matched_only=False)
    abuse.export_html_styled('out.html', matched_only=False)
    abuse.export_xlsx_styled('out.xlsx', matched_only=False)
    abuse.export_md('out.md', matched_only=False)

- **convert to dataframe object**

  .. code-block:: python

    import pandas as pd
    matched = abuse.get_db(matched_only=False)
    df = pd.DataFrame(matched.values())

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

- banner

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/banner.png

- colors legend

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/legend.png

- help

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/help.png

- vertical view

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/abuse-vertical-view.png

- table view

.. image:: https://raw.githubusercontent.com/streanger/abuseipdb-wrapper/main/screenshots/abuse-table-view.png

Changelog
###########################

- `v.0.1.8`:

  - more flexible exports
  - passing :code:`api_key` to :code:`AbuseIPDB` is now optional
  - keep order for passing IPs
  - viewer:
      - skip private IPs flag
      - sumup flag
      - force new check flag
      - more verbose logs
      - asterisks for api key using pwinput
  - colors support for: windows-cmd, windows-terminal, windows-powershell, vscode, linux-terminal
  - tests coverage for most features
  - export to markdown
  - and few smaller changes

- `v.0.1.7`:

  - `abuse` entrypoint
  - `columns` command in interactive view
  - `export` command in interactive view (to .csv, .html, .xlsx)
  - tor exit nodes enrichment
  - storing db file in user home directory
  - original API request using `.check_ip_orig`
  - getpass and keyring for API_KEY read & store

- `v.0.1.6` and before:

  - black background for better view in powershell
  - export to csv, html, xlsx (from pandas df)
  - wrap text in table cells - made using rich table
  - return dataframe object
  - enrich results with date of last check
