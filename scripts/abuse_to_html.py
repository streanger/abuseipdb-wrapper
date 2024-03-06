import os
from pathlib import Path

# import qgrid
import pandas as pd
from pandas.io.formats.style import Styler

"""
useful:
    https://pbpython.com/dataframe-gui-overview.html
    https://datascientyst.com/create-clickable-link-pandas-dataframe-jupyterlab/
    https://stackoverflow.com/questions/67065785/pandas-styling-doesnt-display-for-all-rows-in-large-dataframes-in-chrome-or-edg
"""


def write_file(filename, text, mode="w"):
    """write to file"""
    try:
        with open(filename, mode, encoding="utf-8") as f:
            f.write(text)
    except Exception as err:
        print("[x] Failed to write to file: {}, err: {}".format(filename, err))
    return None


def style_df(x):
    # ***** color style *****
    # add many levels
    if x["abuseConfidenceScore"] > 50:
        bg_style = ["background-color: #ffcccb"]  # lightred
    elif 20 < x["abuseConfidenceScore"] <= 50:
        bg_style = ["background-color: #ffcc7a"]  # yellow
    else:
        bg_style = ["background-color: lightgreen"]

    # ***** other styles *****
    other_styles = ["text-align:right"]

    # ***** total style *****
    total_style = ";".join(bg_style + other_styles)
    return [total_style] * len(x)


def hover(hover_color="lightblue"):
    """
    #add8e6
    https://www.titanwolf.org/Network/q/495331bc-4796-4f2b-8667-40e050be5c7e/y
    """
    row_style = dict(
        selector="tbody tr:hover", props=[("background-color", "%s" % hover_color)]
    )
    return row_style


def apply_style(df):
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
        hover(),
    ]

    # large tables styling limitations
    # https://github.com/pandas-dev/pandas/issues/39400
    # styled = df.style.apply(style_df, axis=1) \
    styled = (
        Styler(df, uuid_len=0, cell_ids=False)
        .apply(style_df, axis=1)
        .set_table_styles(styles, overwrite=True)
    )
    # styled = df.style.set_table_styles(styles, overwrite=True) # only hover
    return styled


def ipv4_sorter(ip):
    return ".".join([item.zfill(3) for item in ip.split(".")])


if __name__ == "__main__":
    os.chdir(str(Path(__file__).parent))

    # ******** read data ********
    # filename = 'fake_abuseipdb.csv'
    filename = "some.csv"
    df = pd.read_csv(filename, index_col=None)

    # *********** rearange & sort by IP ***********
    # new_order = ['ipAddress', 'abuseConfidenceScore', 'totalReports', 'countryCode', 'domain', 'isp', 'url']
    new_order = [
        "ipAddress",
        "abuseConfidenceScore",
        "totalReports",
        "countryCode",
        "domain",
        "isp",
    ]
    df = df[new_order]
    df.fillna("", inplace=True)
    if "url" in df.columns:
        df["url"] = ["<a href={}>{}</a>".format(item, item) for item in df["url"]]
    if "ipAddress" in df.columns:
        df["ip_sorter"] = df["ipAddress"].apply(lambda x: ipv4_sorter(x))
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

    # *********** qgrid display ***********
    # widget = qgrid.show_grid(df, show_toolbar=True)
    # display(widget)

    # ******** to html ********
    styled = apply_style(df)
    html = styled.to_html(render_links=True, escape=False)
    write_file("dfout.html", html)

    # ******** to excel ********
    styled.to_excel("dfout.xlsx")
