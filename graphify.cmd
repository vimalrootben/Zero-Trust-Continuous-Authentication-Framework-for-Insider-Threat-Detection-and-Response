@echo off
pushd "%~dp0"
if errorlevel 1 exit /b 1
if not exist "C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe" (
  echo Graphify environment missing at C:\Users\peter\Documents\Codex\Graphify\.venv.
  popd
  exit /b 1
)
"C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe" -m graphify %*
set "graphify_exit=%errorlevel%"
popd
exit /b %graphify_exit%
