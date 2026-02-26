param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("gen","build","train","score","dashboard","all")]
  [string]$Mode,

  [int]$Rows = 50000
)

$ErrorActionPreference = "Stop"

function Ensure-Venv {
  if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    throw "Virtual env not found. Run: python -m venv .venv"
  }
}

Ensure-Venv

$py = ".\.venv\Scripts\python.exe"

switch ($Mode) {
  "gen"       { & $py .\src\sim\generate_logs.py --rows $Rows }
  "build"     { & $py .\src\pipeline\build_dataset.py }
  "train"     { & $py .\src\pipeline\train_model.py }
  "score"     { & $py .\src\pipeline\score_events.py }
  "dashboard" { & ".\.venv\Scripts\streamlit.exe" run .\dashboard\app.py }
  "all"       {
    & $py .\src\sim\generate_logs.py --rows $Rows
    & $py .\src\pipeline\build_dataset.py
    & $py .\src\pipeline\train_model.py
    & $py .\src\pipeline\score_events.py
    & ".\.venv\Scripts\streamlit.exe" run .\dashboard\app.py
  }
}
