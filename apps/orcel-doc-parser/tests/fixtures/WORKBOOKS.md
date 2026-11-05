# Workbook fixtures written by other software

Most workbook fixtures are written by hand in `mod.rs`, which can only show what this reader's author expected. These come from other software.

An `.xlsx` is a zip of XML. **Each is committed unzipped, byte for byte, as `workbooks/<name>/`,** and `fixtures::unpacked` zips it for a test. That keeps every part open to review: the repository's semantic review refuses binary files, rightly, since nobody can read them. `workbooks/.gitattributes` stops line endings being changed.

| Directory | Written by | Source | SHA-256 of the original file |
|---|---|---|---|
| `written-by-xlsxwriter` | XlsxWriter 3.3.1, which aims to match Excel's output | `generate_workbooks.py` | `8269637152341ebd1dc446ef2b1379ae6c1b8af2b298e7c92427f5f7d9220c24` |
| `written-by-openpyxl` | openpyxl 3.1.5 (with et_xmlfile 2.0.0), which stores no saved value for a formula | `generate_workbooks.py` | `269adbbb07d653ad982d7a0ca02ca98db24c913668d9ec9fa86e2bf45cd0d233` |
| `excel-12-with-various-data` | Reports Microsoft Excel 12.0 (2007) | Apache POI `test-data/spreadsheet/WithVariousData.xlsx` | `1440a832bb810c09687d3498b841782964b0b697e9242428fed1072ab22d078a` |
| `excel-12-sample` | Reports Microsoft Excel 12.0 (2007) | Apache POI `test-data/spreadsheet/SampleSS.xlsx` | `44f1b6ef310c370d4902ee3452e6174da25a67bdb09f47850d51b3287cb3db71` |

## The Excel files

- **Source:** [Apache POI](https://github.com/apache/poi) at commit `7f4d36854109efa17152b27a5fb1b2c7d842c314`, licensed Apache-2.0. The notice is `docs/orcel/notices/apache-poi-Apache-2.0.txt`. Each file's `docProps/core.xml` names an author.
- **Why they're believed to be Excel's:** they've been in POI's test data, where it tests its reading of Excel's format, since at least 2009. **That's the reason, not their metadata.** Each says `Microsoft Excel`, version `12.0000`, `appName="xl"` and `rupBuild="4505"`, but `written-by-xlsxwriter` here says the same, so those markers prove nothing. **That Excel saved them is well-founded but not proved.**

## Tried, and not committed

The parser also read these from the same POI commit without a refusal: `Formatting.xlsx`, `sample.xlsx`, `50096.xlsx` (all reporting Excel 12.0), and `simple-monthly-budget.xlsx` (reporting Excel 16.03, `rupBuild="16828"`, SHA-256 `cae00c6894b95743017aeded4186f15a12c2d8382d71760029df490d58197db6`). The last showed its currency formats and its formulas over named ranges, such as `=TotalMonthlyIncome-TotalMonthlyExpenses`.

It's the only evidence here of a recent Excel, it rests on those same markers, and **it isn't a repeatable test:** it looks like a template of unclear authorship, and it holds binary parts, so it isn't committed.

## What's left

A workbook saved by a current Excel on a machine under this project's control, committed here. Until then, Excel compatibility rests on POI's samples.

`generate_workbooks.py` made the first two files, once, in a throwaway environment. Neither writer is a dependency of this project, and CI doesn't run the script.
