@echo off
pushd "%~dp0"
if errorlevel 1 exit /b 1
if not exist "C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe" (
  echo Graphify environment missing at C:\Users\peter\Documents\Codex\Graphify\.venv.
  popd
  exit /b 1
)
"C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe" -m graphify extract "\\?\C:\p\Zero-Trust-Continuous-Authentication-Framework-for-Insider-Threat-Detection-and-Response-main\Zero-Trust-Continuous-Authentication-Framework-for-Insider-Threat-Detection-and-Response-main" --code-only --max-workers 1
if errorlevel 1 goto failed
"C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe" -m graphify cluster-only "\\?\C:\p\Zero-Trust-Continuous-Authentication-Framework-for-Insider-Threat-Detection-and-Response-main\Zero-Trust-Continuous-Authentication-Framework-for-Insider-Threat-Detection-and-Response-main" --no-label
if errorlevel 1 goto failed
"C:\Users\peter\Documents\Codex\Graphify\.venv\Scripts\python.exe" -m graphify export callflow-html graphify-out --output graphify-out/callflow.html
if errorlevel 1 goto failed
popd
exit /b 0
:failed
set "graphify_exit=%errorlevel%"
popd
exit /b %graphify_exit%
