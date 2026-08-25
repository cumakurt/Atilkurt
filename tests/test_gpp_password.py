"""Tests for GPP cpassword evidence handling."""

import base64
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from analysis.gpp_password_extractor import GPPPasswordExtractor


class TestGPPPasswordExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = GPPPasswordExtractor()

    def test_gpos_without_cpassword_are_not_reported(self):
        gpos = [
            {
                "name": "Default Domain Policy",
                "gPCFileSysPath": r"\\example.com\SYSVOL\example.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}",
            },
            {
                "name": "Desktop Settings",
                "gPCFileSysPath": r"\\example.com\SYSVOL\example.com\Policies\{11111111-1111-1111-1111-111111111111}",
            },
        ]
        self.assertEqual(self.extractor.analyze_gpp_passwords(gpos), [])

    def test_cpassword_evidence_is_reported_without_secret(self):
        risks = self.extractor.analyze_gpp_passwords([{
            "name": "Local Admins",
            "gPCFileSysPath": r"\\example.com\SYSVOL\Policies\{AAAA}",
            "cpassword": "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw",
        }])
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["type"], "gpp_password_found")
        blob = " ".join(str(value) for value in risks[0].values())
        self.assertNotIn("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw", blob)

    def test_decrypt_roundtrip_uses_null_iv(self):
        plaintext = "TestGPPPass1"
        cipher = AES.new(GPPPasswordExtractor.GPP_AES_KEY, AES.MODE_CBC, GPPPasswordExtractor.GPP_AES_IV)
        encrypted = base64.b64encode(cipher.encrypt(pad(plaintext.encode("utf-16-le"), 16))).decode()
        self.assertEqual(self.extractor.decrypt_gpp_password(encrypted), plaintext)

    def test_invalid_ciphertext_returns_none(self):
        self.assertIsNone(self.extractor.decrypt_gpp_password("not-valid-base64!!!"))


if __name__ == "__main__":
    unittest.main()
