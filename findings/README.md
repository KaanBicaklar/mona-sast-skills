# findings/ — generated output

This directory is populated **at runtime** when the detection skills run. Each
vulnerability-class skill writes only to its own file here:

```
findings/01-sql-injection.md
findings/02-nosql-injection.md
...
findings/38-llm-and-ai-application-security.md
```

Every finding follows `references/finding-template.md`. Do not hand-edit these
during a run — the skills append to them, and `sast-final-report` reads them all to
produce `SECURITY-ASSESSMENT-REPORT.md`.

One class = one file. Keep it that way so every class stays independently auditable.
