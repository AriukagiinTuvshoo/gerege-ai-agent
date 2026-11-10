import os
import shutil
import sqlite3

# Vercel serverless орчинд writable зам нь зөвхөн /tmp байна
if os.getenv("VERCEL"):
    tmp_db = "/tmp/leads.db"
    orig_db = os.path.join(os.path.dirname(os.path.dirname(__file__)), "leads.db")
    if not os.path.exists(tmp_db) and os.path.exists(orig_db):
        try:
            shutil.copy(orig_db, tmp_db)
        except Exception:
            pass
    import database
    database.DB_PATH = tmp_db
    database.init_db()

from main import app
