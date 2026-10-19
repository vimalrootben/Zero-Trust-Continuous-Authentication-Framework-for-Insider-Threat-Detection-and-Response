@echo off
pushd "%~dp0"
if errorlevel 1 exit /b 1
set "GRAPHIFY_EXE="
if defined GRAPHIFY_PYTHON (
  if exist "%GRAPHIFY_PYTHON%" set "GRAPHIFY_EXE=%GRAPHIFY_PYTHON%"
)
if not defined GRAPHIFY_EXE (
  if exist "C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe" (
    set "GRAPHIFY_EXE=C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe"
  )
)
if not defined GRAPHIFY_EXE (
  for /f "delims=" %%I in ('where python.exe 2^>nul') do (
    if not defined GRAPHIFY_EXE set "GRAPHIFY_EXE=%%I"
  )
)

if not defined GRAPHIFY_EXE (
  echo Graphify environment missing. Set GRAPHIFY_PYTHON or install graphify into Python environment.
  popd
  exit /b 1
)

"%GRAPHIFY_EXE%" -m graphify %*
set "graphify_exit=%errorlevel%"
popd
exit /b %graphify_exit%

