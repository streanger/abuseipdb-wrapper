import json
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from abuseipdb_wrapper.logger import RED_LEVEL, YELLOW_LEVEL

# colors are specific to html and xlsx so we dont import them from logger
GREEN = "#4cf58c"
YELLOW = "#f5cd4c"
RED = "#f54c4c"
BLUE = "#00ffff"
ONION = "🧅"
MARK_TRUE = "✓"
MARK_FALSE = "x"
ABUSE_CONFIDENCE_SCORE = "abuseConfidenceScore"
GREEN_XLSX = PatternFill(start_color=GREEN.lstrip('#'), end_color=GREEN.lstrip('#'), fill_type="solid")
YELLOW_XLSX = PatternFill(start_color=YELLOW.lstrip('#'), end_color=YELLOW.lstrip('#'), fill_type="solid")
RED_XLSX = PatternFill(start_color=RED.lstrip('#'), end_color=RED.lstrip('#'), fill_type="solid")
BLUE_XLSX = PatternFill(start_color=BLUE.lstrip('#'), end_color=BLUE.lstrip('#'), fill_type="solid")


def apply_color(value):
    if value >= RED_LEVEL:
        color = RED
    elif YELLOW_LEVEL <= value < RED_LEVEL:
        color = YELLOW
    else:
        color = GREEN
    return color


def apply_color_xlsx(value):
    if value >= RED_LEVEL:
        color = RED_XLSX
    elif YELLOW_LEVEL <= value < RED_LEVEL:
        color = YELLOW_XLSX
    else:
        color = GREEN_XLSX
    return color


def read_json(filename):
    """read json file to dict"""
    data = {}
    try:
        with open(filename, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[x] FileNotFoundError: {}".format(filename))
    return data


def to_xlsx(data, hide=None):
    if hide is None:
        hide = []

    cambria_font = Font(name='Cambria', bold=True)
    calibri_font = Font(name='Calibri')
    center_alignment = Alignment(horizontal='center', vertical='center')
    right_alignment = Alignment(horizontal='right', vertical='center')
    thin_border = Border(left=Side(style='thin'),
                        right=Side(style='thin'),
                        top=Side(style='thin'),
                        bottom=Side(style='thin'))

    # Create a workbook and select active worksheet
    wb = Workbook()
    ws = wb.active

    # Write headers with blue color
    header, *data = data
    header_map = {value: index for index, value in enumerate(header)}
    for hidden in hide:
        del header[header_map[hidden]]
    for col_index, value in enumerate(header, start=2):
        cell = ws.cell(row=1, column=col_index, value=value)
        cell.font = cambria_font
        cell.alignment = center_alignment
        cell.border = thin_border

    # Write data with color based on condition
    for row_index, row in enumerate(data, start=2):
        index_cell = ws.cell(row=row_index, column=1, value=row_index-1)  # Write index
        index_cell.font = cambria_font
        index_cell.alignment = center_alignment
        index_cell.border = thin_border
        row_color = apply_color_xlsx(row[header_map[ABUSE_CONFIDENCE_SCORE]])

        # remove hidden item(s)
        for hidden in hide:
            del row[header_map[hidden]]

        for col_index, col in enumerate(row, start=2):
            if type(col) is list:
                col = str(col)
            cell = ws.cell(row=row_index, column=col_index, value=col)
            cell_color = row_color
            cell.fill = cell_color
            cell.font = calibri_font
            cell.alignment = right_alignment
    return wb


def to_html(data, hide=None):
    """convert table with list of lists to html table

    code is modfied version of func from sets_matcher.py
    """
    if hide is None:
        hide = []

    # **** create body ****
    header, *table = data
    header = header.copy()
    tab = ' '*4
    table_body = ""
    header_map = {value: index for index, value in enumerate(header)}
    for row_index, row in enumerate(table, start=1):
        row_color = apply_color(row[header_map['abuseConfidenceScore']])

        # **** remove hidden item(s) ****
        for hidden in hide:
            del row[header_map[hidden]]

        # **** iterate cells ****
        cells = []
        cells.append(f"<td>{row_index}</td>")
        for index, column in enumerate(row):
            if str(column).startswith('https://'):
                column = f"<a href=\"{column}\">url</a>"
                cell_class = ""
            else:
                cell_class = ""
            cell_class += f' style="background-color: {row_color};"'
            cells.append(f"{tab*5}<td {cell_class}>{column}</td>\n")
        cells = ''.join(cells)
        table_body += f"{tab*4}<tr>\n{cells}{tab*4}</tr>\n"
    table_body = table_body.rstrip()

    # **** create head ****
    for hidden in hide:
        del header[header_map[hidden]]
    header.insert(0, 'Index')
    table_head = '\n'.join([f"{tab*4}<th><button>{column}</button></th>" for column in header])

    style = '''\
        .styled-table {
            border-collapse: collapse;
            margin-left: auto;
            margin-right: auto;
            font-size: 0.8em;
            font-family: sans-serif;
            min-width: 400px;
        }
        .styled-table thead tr {
            background-color: #009879;
            color: #ffffff;
        }
        .styled-table td {
            padding: 6px 9px;
            text-align: center;
        }
        .styled-table td:first-child {
            padding: 6px 9px;
            text-align: right;
        }
        .styled-table td:last-child {
            padding: 6px 9px;
            text-align: left;
        }
        .styled-table tbody tr {
            border-bottom: 1px solid #dddddd;
        }
        .styled-table th {
            padding: 0;
            text-align: center;
        }
        .styled-table th button {
            background-color: transparent;
            border: none;
            font: inherit;
            color: inherit;
            height: 100%;
            width: 100%;
            padding: 6px 9px;
            display: inline-block;
        }
        .styled-table th button::after {
            content: "\\00a0\\00a0";
            font-family: 'Courier New', Courier, monospace
        }
        .styled-table th button[direction="ascending"]::after {
            content: " ▲";
        }
        .styled-table th button[direction="descending"]::after {
            content: " ▼";
        }
        .marker {
        background-color: #eeeeee;
        border-radius: 10px;
        }'''

    script = """\
// https://webdesign.tutsplus.com/how-to-create-a-sortable-html-table-with-javascript--cms-92993t
// https://css-tricks.com/almanac/selectors/a/after-and-before/
// https://stackoverflow.com/questions/2965229/nbsp-not-working-in-css-content-tag
// https://stackoverflow.com/questions/7790811/how-do-i-put-variables-inside-javascript-strings

function main() {
    var table = document.getElementsByTagName("table")[0];
    var header = table.getElementsByTagName("tr")[0];
    var headers = header.getElementsByTagName("th");
    for (var i = 0; i < headers.length; i++) {
        var btn = headers[i].getElementsByTagName("button")[0];
        btn.setAttribute("onclick", `table_sorter(${i})`);
    }
}

function table_sorter(column) {
    var table = document.getElementsByTagName("table")[0];
    var tableBody = table.getElementsByTagName("tbody")[0];
    var columnButton = table.getElementsByTagName("tr")[0].getElementsByTagName("th")[column].getElementsByTagName("button")[0];
    var direction = columnButton.getAttribute("direction");
    if (direction == "ascending") {
        direction = "descending";
    } else {
        direction = "ascending";
    }
    var rows = Array.from(table.getElementsByTagName("tr")).slice(1);
    rows.sort(function(a, b) {
        var x = a.getElementsByTagName("td")[column].textContent.toLowerCase();
        var y = b.getElementsByTagName("td")[column].textContent.toLowerCase();
        if (direction === "ascending") {
            // try to sort numbers
            return x - y || x.localeCompare(y);
        } else {
            // try to sort numbers
            return y - x || y.localeCompare(x);
        }
    });
    rows.forEach(function(row) {
        tableBody.appendChild(row);
    });

    // show direction using arrow icon
    var header = table.getElementsByTagName("tr")[0];
    var headers = header.getElementsByTagName("th");
    for (var i = 0; i < headers.length; i++) {
        var btn = headers[i].getElementsByTagName("button")[0];
        if (i == column) {
            btn.setAttribute("direction", direction);
        } else {
            btn.setAttribute("direction", "");
        }
    }
}"""

    template = f"""\
<html>
    <head>
        <title>sets matcher</title>
        <meta charset="utf-8">
        <style>
{style}
        </style>
        <script>
{script}
        </script>
    </head>
    <body onload=main()>
        <table class="styled-table">
            <thead>
                <tr>
{table_head}
                </tr>
            </thead>
            <tbody>
{table_body}
            </tbody>
        </table>
    </body>
</html>\
"""
    return template


if __name__ == '__main__':
    db = read_json('tests/test_home/abuse.json')
    matched = list(db.values())
    temporary_columns = list(matched[0].keys()).copy()
    matched = [[row[column] for column in temporary_columns] for row in matched]
    matched.insert(0, temporary_columns)

    html = to_html(data=matched)
    xlsx = to_xlsx(data=matched)

    # TODO: use style instead of background-color all the time (3 styles for red, green, yellow)
    # TODO: first column index
    # TODO: pseudo dataframe to match columns
    # TODO: true ip sorter for html
    # TODO: make sorter arrow not to flow
    # TODO: switch with night mode
    # TODO: take colors from terminal (if better)
    # TODO: clickable url in excel
    # TODO: onion ascii in html
    # FIXED: date should be in iso format
    # TODO: add index in the front (csv export)
    # TODO: url sorter should use value (in html)
    # TODO: index in html maybe should stay in place?
