import csv
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from core import outbound_http
import uuid
from typing import Dict, List, Any, Optional

# In-memory cache to avoid hammering Google Sheets on every message (TTL = 60 seconds)
_SHEET_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 60


#: Hosts the CSV fetch may contact. Checked before the request AND after any redirect.
_ALLOWED_SHEET_HOST = "docs.google.com"


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when it stays on the allowlisted host.

    Phase 27 (B310). `normalize_sheet_csv_url()` validates the URL the operator supplies,
    but `urlopen` then followed whatever the server sent back. The final URL was never
    re-checked, so validation covered only the first hop.

    What that is and is not worth, stated precisely because both directions matter:

    * `urllib` already refuses a redirect to `file:`/`ftp:` - it raises "Redirection to url
      is not allowed" for any non-http(s) scheme. So the classic scheme downgrade was not
      reachable here, and this is not described as a fix for it.
    * What `urllib` *does* follow is an http(s) redirect to any host, including
      `169.254.169.254` (cloud metadata) and RFC1918 addresses. Verified against a local
      server: the client reached the target and returned its 401. That is the actual
      SSRF surface, and pinning the host is the control that closes it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse

        parsed = urlparse(newurl)
        # https only: a downgrade to plain http would discard the certificate check that
        # makes the rest of this defence meaningful.
        if parsed.scheme != "https" or parsed.hostname != _ALLOWED_SHEET_HOST:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                f"refusing redirect to {parsed.scheme}://{parsed.netloc}: the sheet fetch may "
                f"only contact {_ALLOWED_SHEET_HOST}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _sheet_opener() -> urllib.request.OpenerDirector:
    """An opener that applies the host allowlist to every hop."""
    return urllib.request.build_opener(_SameHostRedirectHandler)


def normalize_sheet_csv_url(sheet_url: str) -> str:
    """
    Converts any Google Sheets sharing URL or edit URL into a direct CSV export URL.
    Enforces strict SSRF validation: only https://docs.google.com/spreadsheets/... is allowed.
    """
    if not sheet_url:
        return ""
    url = sheet_url.strip()
    from urllib.parse import urlparse
    parsed = urlparse(url)
    # Phase 28: https only. `http` was accepted, and the pass-through branch below returned
    # an http URL unchanged - so the fetch ran in plaintext, where nothing binds the
    # connection to the hostname. That matters because TLS is the control that actually
    # defeats DNS rebinding: to serve docs.google.com from a rebound internal address an
    # attacker must present a certificate for docs.google.com. Over plain http they need
    # only answer the request.
    if parsed.scheme != "https" or parsed.hostname != _ALLOWED_SHEET_HOST:
        raise ValueError("Зөвхөн docs.google.com дээрх Google Sheets холбоос зөвшөөрөгдөнө (SSRF хамгаалалт).")

    if "output=csv" in url or "/export?format=csv" in url:
        return url

    match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", url)
    if not match:
        raise ValueError("Google Sheets ID олдсонгүй. Зөв холбоос оруулна уу.")

    sheet_id = match.group(1)
    gid_match = re.search(r"[#&?]gid=([0-9]+)", url)
    gid = gid_match.group(1) if gid_match else "0"
    return f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}"


def fetch_sheet_rows(sheet_url: str, force_refresh: bool = False) -> List[Dict[str, str]]:
    """
    Downloads and parses a Google Sheet (must be shared as 'Anyone with the link can view')
    into a list of dictionaries keyed by column header.
    """
    if not sheet_url or not sheet_url.strip():
        return []

    csv_url = normalize_sheet_csv_url(sheet_url)
    now = time.time()

    if not force_refresh and csv_url in _SHEET_CACHE:
        cached = _SHEET_CACHE[csv_url]
        if now - cached["ts"] < CACHE_TTL_SECONDS:
            return cached["rows"]

    req = urllib.request.Request(
        csv_url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; GeregeBot/2.0)"
        }
    )
    # Phase 28: resolve the allowlisted host and refuse if it is not globally routable.
    #
    # Honest scope, because overstating this would be worse than not doing it: this is a
    # second layer, not the primary control. It rejects an environment where docs.google.com
    # is hijacked by /etc/hosts or a poisoned resolver, and it rejects a host whose
    # resolution includes any private address. It does NOT close the race between this
    # lookup and the socket connect inside `urlopen` - only pinning the address would, and
    # that requires a custom HTTP client. What closes the race in practice is TLS: the
    # connection is https-only (enforced above), so a rebound address must still present a
    # valid certificate for docs.google.com.
    _refusal = outbound_http.reject_reason(_ALLOWED_SHEET_HOST, 443)
    if _refusal:
        raise ValueError(
            f"refusing to fetch a sheet: {_ALLOWED_SHEET_HOST} {_refusal}. This host must "
            "resolve only to public addresses."
        )

    # Phase 27: an opener that re-checks the host on every redirect, rather than trusting
    # the first-hop validation above.
    with _sheet_opener().open(req, timeout=10) as resp:
        final_host = urllib.parse.urlsplit(resp.geturl()).hostname
        if final_host != _ALLOWED_SHEET_HOST:
            raise ValueError(
                f"sheet fetch ended at {final_host!r}, which is not {_ALLOWED_SHEET_HOST}"
            )
        raw_bytes = resp.read()

    text = raw_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    all_rows = list(reader)
    if not all_rows:
        return []

    headers = [h.strip() or f"Багана_{i+1}" for i, h in enumerate(all_rows[0])]
    parsed_rows: List[Dict[str, str]] = []
    for r in all_rows[1:]:
        if not any(cell.strip() for cell in r):
            continue
        row_dict = {}
        for i, h in enumerate(headers):
            val = r[i].strip() if i < len(r) else ""
            row_dict[h] = val
        parsed_rows.append(row_dict)

    _SHEET_CACHE[csv_url] = {"ts": now, "rows": parsed_rows}
    return parsed_rows


def parse_uploaded_excel_bytes(file_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Parses an uploaded .xlsx or .csv file into one or more sheet definitions.
    If an .xlsx workbook contains multiple worksheets/tabs, ALL non-empty tabs are imported!
    """
    lower_name = (filename or "file.xlsx").lower()
    base_title = re.sub(r"\.(xlsx|xls|csv)$", "", filename or "Хүснэгт", flags=re.IGNORECASE)
    sheets_out: List[Dict[str, Any]] = []

    if lower_name.endswith(".csv"):
        text = file_bytes.decode("utf-8-sig", errors="replace")
        reader = csv.reader(io.StringIO(text))
        all_rows = list(reader)
        if not all_rows:
            return []
        headers = [str(h).strip() or f"Багана_{i+1}" for i, h in enumerate(all_rows[0])]
        parsed_rows: List[Dict[str, str]] = []
        for r in all_rows[1:]:
            if not any(str(c).strip() for c in r):
                continue
            row_dict = {}
            for i, h in enumerate(headers):
                row_dict[h] = str(r[i]).strip() if i < len(r) and r[i] is not None else ""
            parsed_rows.append(row_dict)

        if parsed_rows or headers:
            sheets_out.append({
                "id": f"sheet_{uuid.uuid4().hex[:8]}",
                "title": base_title,
                "type": "excel",
                "filename": filename,
                "columns": headers,
                "rows": parsed_rows,
                "row_count": len(parsed_rows),
                "updated_at": time.strftime("%Y-%m-%d %H:%M")
            })
        return sheets_out

    # Parse .xlsx with openpyxl (supports unlimited tabs/sheets inside one workbook)
    from openpyxl import load_workbook
    wb = load_workbook(filename=io.BytesIO(file_bytes), read_only=True, data_only=True)
    for ws_name in wb.sheetnames:
        ws = wb[ws_name]
        raw_rows = list(ws.iter_rows(values_only=True))
        if not raw_rows:
            continue

        # Find the first non-empty row as header
        header_idx = None
        for idx, r in enumerate(raw_rows):
            if r and any(cell is not None and str(cell).strip() != "" for cell in r):
                header_idx = idx
                break
        if header_idx is None:
            continue

        header_row = raw_rows[header_idx]
        headers = [
            str(c).strip() if (c is not None and str(c).strip() != "") else f"Багана_{i+1}"
            for i, c in enumerate(header_row)
        ]

        parsed_rows: List[Dict[str, str]] = []
        for r in raw_rows[header_idx + 1:]:
            if not r or not any(cell is not None and str(cell).strip() != "" for cell in r):
                continue
            row_dict = {}
            for i, h in enumerate(headers):
                val = r[i] if i < len(r) else None
                row_dict[h] = str(val).strip() if val is not None else ""
            parsed_rows.append(row_dict)

        sheet_title = f"{base_title} — {ws_name}" if len(wb.sheetnames) > 1 else (ws_name or base_title)
        sheets_out.append({
            "id": f"sheet_{uuid.uuid4().hex[:8]}",
            "title": sheet_title,
            "type": "excel",
            "filename": filename,
            "sheet_tab": ws_name,
            "columns": headers,
            "rows": parsed_rows,
            "row_count": len(parsed_rows),
            "updated_at": time.strftime("%Y-%m-%d %H:%M")
        })

    wb.close()
    return sheets_out


def get_page_sheets_list(page_data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Returns the unified list of all sheets configured for a branch (`page_data`).
    Combines `knowledge_json["sheets"]` and any legacy `google_sheets_url`.
    """
    if not page_data:
        return []

    raw_kj = page_data.get("knowledge_json") or "{}"
    if isinstance(raw_kj, str):
        try:
            kj = json.loads(raw_kj)
        except Exception:
            kj = {}
    elif isinstance(raw_kj, dict):
        kj = raw_kj
    else:
        kj = {}

    sheets: List[Dict[str, Any]] = []
    stored_sheets = kj.get("sheets")
    if isinstance(stored_sheets, list):
        for s in stored_sheets:
            if isinstance(s, dict):
                sheets.append(s)

    # Ensure legacy google_sheets_url is also included if not already in sheets
    legacy_url = (page_data.get("google_sheets_url") or "").strip()
    if legacy_url:
        # Can be newline-separated or single URL
        urls = [u.strip() for u in re.split(r"[\r\n]+", legacy_url) if u.strip()]
        existing_urls = {normalize_sheet_csv_url(s.get("url", "")) for s in sheets if s.get("type") == "google"}
        for idx, u in enumerate(urls):
            norm_u = normalize_sheet_csv_url(u)
            if norm_u and norm_u not in existing_urls:
                sheets.append({
                    "id": f"legacy_gs_{idx+1}",
                    "title": f"Google Хүснэгт #{idx+1}" if len(urls) > 1 else "Үндсэн Google Хүснэгт",
                    "type": "google",
                    "url": u,
                    "updated_at": "Холбогдсон"
                })
                existing_urls.add(norm_u)

    return sheets


def load_all_page_sheets_rows(page_data: Optional[Dict[str, Any]], force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Loads rows from ALL configured sheets (Google Sheets + uploaded Excel sheets) for the branch.
    Returns a list of dicts: [{"id": ..., "title": ..., "type": ..., "columns": [...], "rows": [...]}]
    """
    sheets = get_page_sheets_list(page_data)
    loaded: List[Dict[str, Any]] = []

    for s in sheets:
        s_type = s.get("type", "google")
        s_title = s.get("title") or "Хүснэгт"
        s_id = s.get("id") or "sheet"
        if s_type == "excel":
            rows = s.get("rows") or []
            cols = s.get("columns") or (list(rows[0].keys()) if rows else [])
            loaded.append({
                "id": s_id,
                "title": s_title,
                "type": "excel",
                "columns": cols,
                "rows": rows,
                "url": ""
            })
        else:
            url = s.get("url") or ""
            if not url:
                continue
            try:
                rows = fetch_sheet_rows(url, force_refresh=force_refresh)
                cols = list(rows[0].keys()) if rows else (s.get("columns") or [])
                loaded.append({
                    "id": s_id,
                    "title": s_title,
                    "type": "google",
                    "columns": cols,
                    "rows": rows,
                    "url": url
                })
            except Exception:
                loaded.append({
                    "id": s_id,
                    "title": s_title,
                    "type": "google",
                    "columns": s.get("columns") or [],
                    "rows": [],
                    "url": url,
                    "error": True
                })
    return loaded


def search_sheet_rows(sheet_url: str, query: str) -> List[Dict[str, str]]:
    """
    Searches a single Google Sheet for any row matching `query`.
    """
    if not sheet_url or not query or len(query.strip()) < 2:
        return []
    rows = fetch_sheet_rows(sheet_url)
    return _filter_rows_by_query(rows, query)


def _filter_rows_by_query(rows: List[Dict[str, str]], query: str, sheet_title: str = "") -> List[Dict[str, str]]:
    if not rows or not query:
        return []
    q = query.strip().lower()
    q_clean = re.sub(r"[\s\-]", "", q)

    matches: List[Dict[str, str]] = []
    for row in rows:
        for _, v in row.items():
            val_lower = str(v).lower()
            val_clean = re.sub(r"[\s\-]", "", val_lower)
            if q in val_lower or (len(q_clean) >= 3 and q_clean in val_clean):
                enriched = dict(row)
                if sheet_title:
                    enriched["Хүснэгт"] = sheet_title
                matches.append(enriched)
                break
        if len(matches) >= 12:
            break
    return matches


def search_all_page_sheets(page_data: Optional[Dict[str, Any]], query: str) -> List[Dict[str, str]]:
    """
    Searches across ALL connected Google Sheets & Excel sheets of a branch for `query`.
    Each matching row includes `"Хүснэгт": <sheet_title>`.
    """
    if not page_data or not query or len(query.strip()) < 2:
        return []

    loaded_sheets = load_all_page_sheets_rows(page_data)
    all_matches: List[Dict[str, str]] = []
    for sheet in loaded_sheets:
        matches = _filter_rows_by_query(sheet.get("rows", []), query, sheet_title=sheet.get("title", "Хүснэгт"))
        all_matches.extend(matches)
        if len(all_matches) >= 15:
            break
    return all_matches[:15]


def get_page_sheets_lookup_context(page_data: Optional[Dict[str, Any]], user_text: str) -> str:
    """
    Builds a rich, multi-sheet lookup context for the AI Agent based on the customer's message.
    1. Extracts tokens (phone numbers, tracking codes, item names, keywords >= 2 chars) and searches all sheets.
    2. Even if no specific token matches, provides an overview of all connected sheets and their top rows so the AI can answer general table/price/inventory questions directly!
    """
    if not page_data:
        return ""

    loaded_sheets = load_all_page_sheets_rows(page_data)
    non_empty_sheets = [s for s in loaded_sheets if s.get("rows")]
    if not non_empty_sheets:
        return ""

    # Extract meaningful search tokens from user_text
    raw_tokens = re.findall(r"[A-Za-zА-Яа-яӨөҮүЁё0-9\-]{2,}", user_text or "")
    stop_words = {
        "сайн", "байна", "танай", "танайх", "юу", "ямар", "хэд", "хэдэн", "бараа",
        "ачаа", "карго", "үнэ", "мэдээлэл", "хүснэгт", "шалгах", "шалгаад", "өгөөч",
        "ирсэн", "болов", "хэзээ", "хаана", "байна", "вэ", "бэ", "энэ", "тэр", "миний"
    }
    candidates = [t for t in raw_tokens if t.lower() not in stop_words and len(t) >= 2]

    matched_rows: List[Dict[str, str]] = []
    seen_ChangeKeys = set()

    for token in candidates:
        for sheet in non_empty_sheets:
            rows = _filter_rows_by_query(sheet["rows"], token, sheet_title=sheet["title"])
            for r in rows:
                sig = json.dumps(r, ensure_ascii=False, sort_keys=True)
                if sig not in seen_ChangeKeys:
                    seen_ChangeKeys.add(sig)
                    matched_rows.append(r)
                if len(matched_rows) >= 15:
                    break
            if len(matched_rows) >= 15:
                break

    lines = [
        "\n\n=== САЛБАРЫН ХОЛБОГДСОН ХҮСНЭГТҮҮД (GOOGLE SHEETS & EXCEL САН) ==="
    ]
    lines.append(f"Нийт идэвхтэй хүснэгтийн тоо: {len(non_empty_sheets)}")
    for s in non_empty_sheets:
        cols_preview = ", ".join(s.get("columns", [])[:10])
        lines.append(f"- «{s['title']}» ({len(s['rows'])} мөр өгөгдөлтэй | Баганууд: {cols_preview})")

    if matched_rows:
        lines.append(f"\n[ХЭРЭГЛЭГЧИЙН АСУУЛТААР ШҮҮЖ ОЛСОН МӨРҮҮД ({len(matched_rows)} илэрц)]:")
        for idx, m in enumerate(matched_rows[:12], 1):
            sheet_name = m.get("Хүснэгт", "Хүснэгт")
            pairs = [f"{k}: {v}" for k, v in m.items() if v and k != "Хүснэгт"]
            lines.append(f"  {idx}. [{sheet_name}] -> " + " | ".join(pairs))
        lines.append(
            "ЗААВАР: Дээрх хүснэгтээс олдсон бодит мөрүүд дээр үндэслэн хэрэглэгчид аль хүснэгтээс ямар мэдээлэл олдсоныг маш тодорхой, цэгцтэй хэлж өг!"
        )
    else:
        lines.append(
            "\nЗААВАР: Хэрэглэгчийн асуултад тохирох мөр хараахан шүүгдээгүй байна. "
            "Хэрэв хэрэглэгч ачаа, бараа, захиалга шалгуулах гэж байгаа бол утасны дугаар эсвэл трак кодыг нь асууж `check_sheet_cargo_status` багажийг дуудаж шалгаж өгнө үү. "
            "Бусад хүний хувийн мэдээллийг задруулахгүй."
        )

    return "\n".join(lines)


def get_sheet_lookup_context(sheet_url: str, user_text: str) -> str:
    """
    Legacy helper for single sheet URL lookup.
    """
    if not sheet_url or not user_text:
        return ""
    fake_page = {"google_sheets_url": sheet_url, "knowledge_json": "{}"}
    return get_page_sheets_lookup_context(fake_page, user_text)
