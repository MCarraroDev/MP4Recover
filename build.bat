@echo off
setlocal EnableDelayedExpansion

echo ==========================================
echo      MP4Recover Build ^& Start Script
echo ==========================================

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running or not installed.
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)

echo [INFO] Docker is running.

REM Stop and remove existing containers
echo.
echo [1/3] Stopping and cleaning up old containers...
docker compose down -v --remove-orphans
if %errorlevel% neq 0 (
    echo [WARNING] Failed to clean up some resources. Continuing...
)

REM Build and start containers
echo.
echo [2/3] Building and starting containers...
docker compose up -d --build --force-recreate --remove-orphans
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build or start containers.
    pause
    exit /b 1
)

REM Show status
echo.
echo [3/3] Checking container status...
docker compose ps
echo.
echo ==========================================
echo      SUCCESS! System is up and running
echo ==========================================
echo Orchestrator: http://localhost:8000
echo Web Interface: http://localhost:8080
echo.

endlocal
pause
