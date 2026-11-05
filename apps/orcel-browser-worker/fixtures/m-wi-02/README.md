# M-WI-02 fixture pages

Five US government pages, saved on 2026-11-05 and converted with `convert.py`, for the
measurement in `src/extract/extract.test.ts`. Each JSON file records its source, date, question
and expected answer. The saved HTML isn't committed, so the conversion can only be repeated
against the live page, which may have changed. Then `body` is reduced to tags, links and text.

One edit: a staff photo credit naming a person is replaced with "NPS photo" in
`nps-grand-canyon-fees.json`.
