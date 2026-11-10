import re
import csv
import io
import time
import logging
import urllib.request
from typing import List, Dict, Optional, Any

logger = logging.getLogger("sheets_service")

# 30 секундын кэш (Google Sheets-ийг хэт олон удаа зэрэг дуудахаас сэргийлж, хурдыг нэмэгдүүлнэ)
_SHEET_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 30  # seconds

def get_google_sheet_csv_url(sheet_url: str) -> Optional[str]:
    """Google Sheet холбоосыг шууд татаж болох CSV экспорт линк болгон хөрвүүлэх"""
    if not sheet_url or "docs.google.com/spreadsheets" not in sheet_url:
        return None
    
    if "output=csv" in sheet_url or "format=csv" in sheet_url:
        return sheet_url

    # Spreadsheet ID ялгах
    m = re.search(r"/d/([a-zA-Z0-9-_]+)", sheet_url)
    if not m:
        return None
    sheet_id = m.group(1)
    
    # GID (хуудасны дугаар) ялгах
    gid_match = re.search(r"[#&?]gid=([0-9]+)", sheet_url)
    gid = gid_match.group(1) if gid_match else "0"
    
    return f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}"

def fetch_google_sheet_data(sheet_url: str) -> List[Dict[str, str]]:
    """Google Sheet-ийн бүх мөрүүдийг татаж dict жагсаалт болгон буцаах"""
    csv_url = get_google_sheet_csv_url(sheet_url)
    if not csv_url:
        return []
    
    now = time.time()
    if csv_url in _SHEET_CACHE:
        cached = _SHEET_CACHE[csv_url]
        if now - cached["time"] < CACHE_TTL:
            return cached["data"]
            
    try:
        req = urllib.request.Request(
            csv_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            content = resp.read().decode("utf-8-sig", errors="replace")
            reader = csv.reader(io.StringIO(content))
            rows = list(reader)
            
        if not rows:
            return []
            
        headers = [h.strip() for h in rows[0]]
        data = []
        for r in rows[1:]:
            if not any(cell.strip() for cell in r):
                continue
            row_dict = {}
            for i, h in enumerate(headers):
                if h:
                    row_dict[h] = r[i].strip() if i < len(r) else ""
            data.append(row_dict)
            
        _SHEET_CACHE[csv_url] = {"data": data, "time": now}
        return data
    except Exception as e:
        logger.error(f"Google Sheet татахад алдаа гарлаа: {e}")
        return []

def extract_potential_keywords(text: str) -> List[str]:
    """Хэрэглэгчийн мессежээс код, дугаар, утасны дугаар, нэрсийн түлхүүр үгсийг ялгах"""
    keywords = []
    
    # 1. 3 ба түүнээс дээш оронтой тоонууд (Барааны код, tracking дугаар, утас: 1254, 85898952 г.м)
    numbers = re.findall(r"\b\d{3,12}\b", text)
    keywords.extend(numbers)
    
    # 2. Англи үсэг + тоотой карго код (жишээ: CRG125, MN9921, A102)
    alphanumeric = re.findall(r"\b[A-Za-z]+[-_]?\d+\b", text)
    keywords.extend([k.upper() for k in alphanumeric])
    
    # 3. Хэрэглэгчийн нэр эсвэл тусгай үгсийг шалгах
    # "enhee 85898952" -> "enhee"
    stop_words = {
        "сайн", "байна", "уу", "юу", "байнаа", "байнауу", "энэ", "миний", "манай", "маань", 
        "ирчихсэн", "ирсэн", "үү", "үйлчилгээ", "карго", "kargo", "cargo", "baraa", "бараа",
        "дугаартай", "dugaartai", "тоотой", "болсон", "байгаа", "байгаам", "хүргэлт", "хэзээ",
        "хэд", "шалгаад", "өгөөч", "өгөөрэй", "туслаач", "шалгаж", "өгнө", "би", "чи",
        "irsen", "bnuu", "bna", "uu", "maan", "irchihsen", "bolson", "shalgah", "hurgelt",
        "hezee", "hed", "shalgaad", "ogooch", "ogooroi", "tand", "mini", "manai", "ene",
        "boloh", "bgaa", "bgaam", "kargoo", "dugaar", "kod", "code", "no", "num"
    }
    words = re.findall(r"[A-Za-zА-Яа-яӨөҮүЁё]+", text)
    for w in words:
        clean_w = w.lower()
        if len(clean_w) >= 3 and clean_w not in stop_words:
            keywords.append(clean_w)
            
    # Давхардлыг арилгах
    seen = set()
    result = []
    for k in keywords:
        k_lower = k.lower()
        if k_lower not in seen:
            seen.add(k_lower)
            result.append(k)
    return result

def search_sheet_records(sheet_url: str, query: str) -> List[Dict[str, str]]:
    """Хүснэгтийн өгөгдлөөс хайлт хийх"""
    data = fetch_google_sheet_data(sheet_url)
    if not data:
        return []
        
    keywords = extract_potential_keywords(query)
    if not keywords:
        return []
        
    matched = []
    for row in data:
        row_values_lower = " ".join(str(v).lower() for v in row.values())
        for kw in keywords:
            kw_clean = kw.lower()
            if kw_clean in row_values_lower:
                if row not in matched:
                    matched.append(row)
                break
    return matched

def get_sheet_lookup_context(sheet_url: str, user_text: str) -> Optional[str]:
    """Gemini AI-д зориулсан бодит цагийн баталгаажсан өгөгдлийн тайлбар үүсгэх"""
    if not sheet_url:
        return None
        
    keywords = extract_potential_keywords(user_text)
    if not keywords:
        return None
        
    matched_rows = search_sheet_records(sheet_url, user_text)
    
    if matched_rows:
        lines = ["[БОДИТ ЦАГИЙН ХОЛБОГДСОН GOOGLE SHEETS МЭДЭЭЛЭЛ]:"]
        lines.append(f"Хэрэглэгчийн асуусан хайлтаар нийт {len(matched_rows)} баримт/барааны мэдээлэл олдлоо:")
        for idx, r in enumerate(matched_rows[:5], 1):
            lines.append(f"--- Илэрц #{idx} ---")
            for k, v in r.items():
                if v:
                    lines.append(f"  • {k}: {v}")
        lines.append("\nЧУХАЛ ЗААВАР: Та дээрх олдсон бодит өгөгдлийг үндэслэн хэрэглэгчид барааны төлөв, байршил, олгоход бэлэн эсэх, төлбөрийн мэдээллийг эелдэг найрсаг, тодорхой мэдээлж өгнө үү!")
        return "\n".join(lines)
    else:
        # Хэрэв бараа, код, утас асуусан боловч олдсонгүй бол:
        tracking_kw = ", ".join(keywords)
        return (
            f"[БОДИТ ЦАГИЙН ХОЛБОГДСОН GOOGLE SHEETS ШАЛГАЛТ]:\n"
            f"Хэрэглэгч бараа/ачаа/захиалгын төлөв шалгах зорилгоор '{tracking_kw}' дугаарыг дурдсан боловч одоогоор Google Sheets бүртгэл дээр энэ дугаартай мэдээлэл ОЛДСОНГҮЙ.\n"
            f"ЧУХАЛ ЗААВАР: Хэрэглэгчид 'Таны илгээсэн {tracking_kw} дугаартай бараа манай одоогийн ирсэн барааны бүртгэл дээр олдсонгүй. Та дугаараа зөв эсэхийг дахин нэг шалгана уу эсвэл замдаа яваа байж магадгүй' гэж эелдэг тайлбарлаж өгнө үү."
        )
