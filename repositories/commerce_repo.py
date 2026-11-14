from typing import Dict, Any, List, Optional
import database


class CommerceRepository:
    """QPay Финтек, Карго Агуулах болон Маркетингийн өгөгдлийн давхарга"""

    @staticmethod
    def get_invoice(invoice_id: str) -> Optional[Dict[str, Any]]:
        return database.get_invoice(invoice_id)

    @staticmethod
    def list_invoices(page_id: Optional[str], limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        return database.list_invoices(page_id=page_id, limit=limit, status=status)

    @staticmethod
    def get_fintech_summary(page_id: Optional[str]) -> Dict[str, Any]:
        return database.get_fintech_summary(page_id)

    @staticmethod
    def get_cargo_package(page_id: str, tracking_code: str) -> Optional[Dict[str, Any]]:
        return database.get_cargo_package(page_id, tracking_code)

    @staticmethod
    def list_cargo_packages(page_id: str, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        return database.list_cargo_packages(page_id, status=status, limit=limit)

    @staticmethod
    def get_cargo_summary(page_id: str) -> Dict[str, Any]:
        return database.get_cargo_summary(page_id)
