import json
import os
from typing import Dict, Any

KNOWLEDGE_FILE = os.path.join(os.path.dirname(__file__), "knowledge.json")

def load_knowledge() -> Dict[str, Any]:
    if not os.path.exists(KNOWLEDGE_FILE):
        return {}
    try:
        with open(KNOWLEDGE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {}

def save_knowledge(data: Dict[str, Any]):
    with open(KNOWLEDGE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_knowledge_prompt_text() -> str:
    kb = load_knowledge()
    comp = kb.get("company", {})
    bank = kb.get("bank", {})
    links = kb.get("links", {})
    dramas = kb.get("dramas", [])
    faqs = kb.get("faqs", [])
    policies = kb.get("policies", "")

    text = f"""
=== БАЙГУУЛЛАГЫН МЭДЛЭГИЙН САН ===
Сувгийн нэр: {comp.get('name')}
Тайлбар: {comp.get('description')}

БАНКНЫ ШИЛЖҮҮЛЭГ & ДАНСНЫ МЭДЭЭЛЭЛ:
- Банк: {bank.get('bank_name', 'ГОЛОМТ БАНК')}
- Дансны дугаар: {bank.get('account_number', '97001500 2815116628')}
- Хүлээн авагч: {bank.get('account_name', 'Tuvshok Channel')}
- Заавар: {bank.get('instruction', 'Гүйлгээний утга дээр нэр/утас бичих')}
- Нөхцөл: Хандивын доод хэмжээ заагаагүй (дурын дүнгээр боломжоороо шилжүүлж болно)

КИНО БА ДРАМЫН ЖАГСААЛТ:
"""
    for idx, d in enumerate(dramas, 1):
        text += f"{idx}. {d.get('name')} | Ангиуд: {d.get('episodes')} | Төлөв: {d.get('status')} ({d.get('note', '')})\n"

    text += f"""
КИНО ҮЗЭХ АЛБАН ЁСНЫ ГРУППИЙН ЛИНКҮҮД:
- Telegram групп холбоос: {links.get('telegram_group', 'https://t.me/+tuvshok_te_ju_yon')}
- Facebook групп холбоос: {links.get('facebook_group', 'https://www.facebook.com/groups/tuvshok')}
- VIP суваг: {links.get('vip_channel', '')}

ЧУХАЛ ЗААВАР:
- Хэрэглэгч гүйлгээ хийсэн баримтын зураг явуулах эсвэл гүйлгээ хийснээ баталгаажуулбал дээрх Telegram болон Facebook группын линкийг шууд илгээнэ.
- Хэрэв кино үзье гэвэл дээрх дансны мэдээллийг өгч, баримтаа зургаар явуулахад линк өгнө гэдгийг эелдэг тайлбарлана.

БАЙНГА АСУУДАГ АСУУЛТУУД (FAQ):
"""
    for idx, faq in enumerate(faqs, 1):
        text += f"Асуулт {idx}: {faq.get('question')}\nХариулт: {faq.get('answer')}\n"

    text += f"\nБОДЛОГО: {policies}\n===================================\n"
    return text
