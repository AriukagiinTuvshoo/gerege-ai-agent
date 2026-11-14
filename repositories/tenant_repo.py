from typing import Dict, Any, List, Optional
import database


class TenantRepository:
    """Салбар / Харилцагчийн (Tenant) өгөгдлийн сангийн хандалтын давхарга"""

    @staticmethod
    def list_pages(mask_secrets: bool = True, include_magic_token: bool = False) -> List[Dict[str, Any]]:
        return database.get_all_pages(mask_secrets=mask_secrets, include_magic_token=include_magic_token)

    @staticmethod
    def get_page(page_id: str, mask_secrets: bool = False, include_magic_token: bool = False) -> Optional[Dict[str, Any]]:
        return database.get_page(page_id, mask_secrets=mask_secrets, include_magic_token=include_magic_token)

    @staticmethod
    def save_page(**kwargs) -> None:
        database.save_page(**kwargs)

    @staticmethod
    def delete_page(page_id: str) -> bool:
        return database.delete_page(page_id)

    @staticmethod
    def set_credentials(page_id: str, username: str, password: Optional[str] = None) -> Dict[str, str]:
        return database.set_client_credentials(page_id, username, password)
