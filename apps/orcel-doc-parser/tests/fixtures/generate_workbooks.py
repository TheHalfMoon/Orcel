"""Generate the workbook fixtures with two independent writers. Run once, in a
throwaway environment; the output is committed with its provenance."""

import sys
from pathlib import Path

import openpyxl
import xlsxwriter

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)

# XlsxWriter stores a saved value for a formula when given one, as Excel does.
workbook = xlsxwriter.Workbook(str(out / "written-by-xlsxwriter.xlsx"))
money = workbook.add_format({"num_format": '"$"#,##0.00'})
percent = workbook.add_format({"num_format": "0%"})
bold = workbook.add_format({"bold": True})
sales = workbook.add_worksheet("Sales")
audit = workbook.add_worksheet("Audit")
audit.hide()
sales.write("A1", "Region", bold)
sales.write("B1", "Revenue", bold)
sales.write("A2", "North")
sales.write_number("B2", 1250.5, money)
sales.write("A3", "South")
sales.write_number("B3", 749.25, money)
sales.write("A4", "Total")
sales.write_formula("B4", "=SUM(B2:B3)", money, 1999.75)
sales.write_formula("C2", "=B2/B4", percent, 0.625)
sales.write_rich_string("D2", "Bold ", bold, "words")
sales.write_boolean("E2", True)
sales.write_formula("E3", "=1/0", None, "#DIV/0!")
sales.write("F2", "line one\nline two")
sales.write_comment("A1", "A comment, in a part of its own")
audit.write("A1", "Reviewed")
workbook.define_name("TotalRevenue", "=Sales!$B$4")
workbook.close()

# openpyxl stores no saved value for a formula, so it must read as having none.
book = openpyxl.Workbook()
first = book.active
first.title = "Sales"
first["A1"] = "Region"
first["B2"] = 1250.5
first["B2"].number_format = '"$"#,##0.00'
first["B3"] = 749.25
first["B4"] = "=SUM(B2:B3)"
first["D2"] = True
second = book.create_sheet("Audit")
second["A1"] = "Reviewed"
second.sheet_state = "hidden"
book.save(out / "written-by-openpyxl.xlsx")

print("xlsxwriter", xlsxwriter.__version__, "openpyxl", openpyxl.__version__)
