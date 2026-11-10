@echo off
echo ==========================================================
echo   Cloudflare Secure Tunnel эхлүүлж байна...
echo   (Таны локал серверийг дэлхийн нийтийн HTTPS болгоно)
echo ==========================================================
"C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:8000
pause
