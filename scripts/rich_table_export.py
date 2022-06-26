import os
from pathlib import Path
from rich import print, inspect
from rich.table import Table
from rich.text import Text
from rich.console import Console


def log_table(table):
    """Generate an ascii formatted presentation of a Rich table
    Eliminates any column styling
    https://github.com/Textualize/rich/discussions/1799
    """
    console = Console()
    with console.capture() as capture:
        console.print(table)
    return Text.from_ansi(capture.get())
    
    
if __name__ == "__main__":
    os.chdir(str(Path(__file__).parent))
    # border_style = "blue on black"
    border_style = "blue on white"
    header_style = "bold green_yellow on royal_blue1"
    table = Table(border_style=border_style, header_style=header_style)

    # ********* columns *********
    columns = [('some', 'royal_blue1'), ('thing', 'green'), ('here', 'red')]
    # column_on_style = "on black"
    column_on_style = "on white"
    table.add_column("No", style="green_yellow {}".format(column_on_style))
    for column, base in columns:
        table.add_column(column, style="{} {}".format(base, column_on_style))
    
    #
    data = [
        ['this', 'is', 'data'],
        ['next', 'line', 'here'],
        ['last', 'one', 'some'],
    ]
    
    for index, row in enumerate(data):
        table.add_row(str(index+1), *row)
        
    # print(table)
    # text = log_table(table)
    console = Console(record=True)
    console.print(table)
    console.save_html('table2.html')
    