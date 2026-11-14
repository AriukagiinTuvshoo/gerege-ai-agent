from typing import Dict, Any, List, Optional
import database


class CRMRepository:
    """Харилцагчийн бүртгэл (Leads), Чат сесс болон Цаг захиалгын өгөгдлийн давхарга"""

    @staticmethod
    def list_leads(page_id: Optional[str]) -> List[Dict[str, Any]]:
        return database.get_all_registrations(page_id=page_id)

    @staticmethod
    def get_lead(lead_id: int) -> Optional[Dict[str, Any]]:
        return database.get_lead_by_id(lead_id)

    @staticmethod
    def update_lead_status(lead_id: int, status: str, notes: Optional[str] = None) -> None:
        database.update_lead_status(lead_id, status, notes)

    @staticmethod
    def list_sessions(page_id: Optional[str]) -> List[Dict[str, Any]]:
        return database.get_active_sessions(page_id=page_id)

    @staticmethod
    def get_messages(sender_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        return database.get_conversation_history(sender_id=sender_id, limit=limit)

    @staticmethod
    def list_appointments(
        page_id: str,
        date_str: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        return database.list_appointments(page_id=page_id, date_str=date_str, status=status, limit=limit)

    @staticmethod
    def get_appointment(appointment_id: int) -> Optional[Dict[str, Any]]:
        return database.get_appointment_by_id(appointment_id)
