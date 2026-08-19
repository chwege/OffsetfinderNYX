@echo off
setlocal
cd /d "%~dp0"

if not exist "vendor\nyx\.git" (
  echo NYX submodule is missing. Run: git submodule update --init --recursive
  exit /b 1
)

git -C vendor\nyx apply --check "..\..\patches\nyx-local.patch" >nul 2>&1
if not errorlevel 1 (
  git -C vendor\nyx apply "..\..\patches\nyx-local.patch"
  if errorlevel 1 exit /b 1
  echo NYX patch applied successfully.
  exit /b 0
)

git -C vendor\nyx apply --reverse --check "..\..\patches\nyx-local.patch" >nul 2>&1
if not errorlevel 1 (
  echo NYX patch is already applied.
  exit /b 0
)

echo NYX patch cannot be applied cleanly. Check the submodule revision.
exit /b 1
