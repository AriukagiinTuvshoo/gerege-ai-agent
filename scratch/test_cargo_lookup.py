import unittest
from unittest.mock import patch
import sheets_service
import agent
import database

class TestCargoLookup(unittest.TestCase):
    def setUp(self):
        self.mock_sheet_data = [
            {
                "Код": "1254",
                "Нэр": "Энхээ",
                "Утас": "85898952",
                "Барааны Нэр": "Өвлийн Куртка (Хар, L)",
                "Төлөв": "Улаанбаатар салбарт ирсэн (Олгоход бэлэн)",
                "Байршил": "Төв салбар (10-р хороолол)",
                "Төлбөр": "15,000₮"
            },
            {
                "Код": "9981",
                "Нэр": "Бат",
                "Утас": "99112233",
                "Барааны Нэр": "Гутал",
                "Төлөв": "Замдаа яваа (Эрээнээс гарсан)",
                "Байршил": "Замдаа",
                "Төлбөр": "20,000₮"
            }
        ]

    @patch("sheets_service.fetch_google_sheet_data")
    def test_search_by_code(self, mock_fetch):
        mock_fetch.return_value = self.mock_sheet_data
        url = "https://docs.google.com/spreadsheets/d/test_id/edit"
        
        # 1. 1254 кодоор хайх
        results = sheets_service.search_sheet_records(url, "1254 dugaartai baraa maan irsen bnuu")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["Код"], "1254")
        self.assertIn("Олгоход бэлэн", results[0]["Төлөв"])

        # 2. Утасны дугаараар хайх
        results_phone = sheets_service.search_sheet_records(url, "85898952 utastai kargo irsen bnuu")
        self.assertEqual(len(results_phone), 1)
        self.assertEqual(results_phone[0]["Нэр"], "Энхээ")

        # 3. Context үүсгэлт шалгах
        ctx = sheets_service.get_sheet_lookup_context(url, "1254 dugaartai baraa maan irsen bnuu")
        self.assertIn("Өвлийн Куртка", ctx)
        self.assertIn("10-р хороолол", ctx)
        print("Generated Context Preview:\n", ctx)

if __name__ == "__main__":
    unittest.main()
