import sqlite3

def run():
    conn = sqlite3.connect("leads.db")
    c = conn.cursor()
    c.execute("PRAGMA table_info(pages)")
    cols = [r[1] for r in c.fetchall()]
    if "google_sheets_url" not in cols:
        c.execute("ALTER TABLE pages ADD COLUMN google_sheets_url TEXT DEFAULT ''")
        conn.commit()
        print("Column google_sheets_url added.")
    else:
        print("Column google_sheets_url already exists.")
    conn.close()

if __name__ == "__main__":
    run()
