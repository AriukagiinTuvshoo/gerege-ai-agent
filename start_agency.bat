@echo off
chcp 65001 >nul
title AI Agency Hub - 24/7 Server & Tunnel Launcher

echo ========================================================
echo   🚀 AI AGENCY HUB - Олон Хуудасны Автоматжуулалтын Студио
echo ========================================================
echo.

:: 1. Серверийг асаах
echo [1/2] Серверийг асааж байна (FastAPI + Uvicorn)...
start "AI Agency Server" cmd /k "python main.py"

:: Түр 3 секунд хүлээх
timeout /t 3 /nobreak >nul

:: 2. Cloudflare туннелийг асаах
echo [2/2] Онлайн холболтыг асааж байна (Cloudflare Tunnel)...
if exist "C:\Program Files (x86)\cloudflared\cloudflared.exe" (
    start "Cloudflare Live Tunnel" cmd /k ""C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:8000"
) else (
    start "Cloudflare Live Tunnel" cmd /k "cloudflared tunnel --url http://localhost:8000"
)

echo.
echo ========================================================
echo   ✅ БҮХ СИСТЕМ АМЖИЛТТАЙ АСЛАА!
echo.
echo   - Дотоод хаяг:   http://localhost:8000
echo   - Админ нууц үг: admin2026
echo   - Онлайн хаягийг Cloudflare цонхноос харна уу.
echo ========================================================
echo.
pause
