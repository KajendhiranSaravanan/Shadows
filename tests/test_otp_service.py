import unittest
from unittest.mock import patch

import otp_service


class SendOtpTests(unittest.TestCase):
    def setUp(self):
        self.user = {"id": 1, "email": "analyst@example.com", "full_name": "Analyst"}

    @patch("otp_service.database.create_otp")
    @patch("otp_service.database.get_setting")
    @patch("otp_service._send_email_smtp")
    @patch("otp_service.generate_otp", return_value="123456")
    def test_send_otp_uses_smtp_when_configured(
        self,
        mock_generate_otp,
        mock_send_email,
        mock_get_setting,
        mock_create_otp,
    ):
        mock_get_setting.side_effect = lambda category: {
            "smtp_settings": {
                "host": "smtp.example.com",
                "port": 587,
                "user": "mailer@example.com",
                "password": "secret",
                "sender": "mailer@example.com",
                "use_tls": True,
            },
            "otp_settings": {"otp_length": 6, "validity_minutes": 5, "max_attempts": 3},
        }.get(category)

        result = otp_service.send_otp(self.user, purpose="login")

        mock_create_otp.assert_called_once_with(1, "123456", "login", 5)
        mock_send_email.assert_called_once()
        self.assertEqual(result, {"delivered": True, "dev_mode": False, "otp": None})

    @patch("otp_service.database.create_otp")
    @patch("otp_service.database.get_setting")
    @patch("otp_service.generate_otp", return_value="654321")
    def test_send_otp_falls_back_to_dev_mode_without_smtp(
        self,
        mock_generate_otp,
        mock_get_setting,
        mock_create_otp,
    ):
        mock_get_setting.side_effect = lambda category: {
            "smtp_settings": {},
            "otp_settings": {"otp_length": 6, "validity_minutes": 5, "max_attempts": 3},
        }.get(category)

        result = otp_service.send_otp(self.user, purpose="login")

        mock_create_otp.assert_called_once_with(1, "654321", "login", 5)
        self.assertEqual(result["dev_mode"], True)
        self.assertEqual(result["delivered"], False)
        self.assertEqual(result["otp"], "654321")


if __name__ == "__main__":
    unittest.main()