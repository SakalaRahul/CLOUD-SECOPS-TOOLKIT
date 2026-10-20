import io
import json
import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from secops import s3audit, vulnscan


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "op")


class VulnScanTests(unittest.TestCase):
    def test_parse_requirements_skips_comments_and_unpinned(self):
        text = "requests==2.19.0  # old\n# comment\nflask\nDjango==3.0.0\n"
        self.assertEqual(
            vulnscan.parse_requirements(text),
            [("requests", "2.19.0"), ("django", "3.0.0")],
        )

    def test_build_query(self):
        q = vulnscan.build_query([("requests", "2.19.0")])
        self.assertEqual(q["queries"][0]["package"]["ecosystem"], "PyPI")
        self.assertEqual(q["queries"][0]["version"], "2.19.0")

    def test_query_osv_uses_opener(self):
        payload = json.dumps({"results": [{"vulns": [{"id": "GHSA-1"}]}]}).encode()
        opener = MagicMock()
        opener.return_value.__enter__.return_value = io.BytesIO(payload)
        results = vulnscan.query_osv([("requests", "2.19.0")], opener=opener)
        self.assertEqual(results[0]["vulns"][0]["id"], "GHSA-1")

    def test_triage_and_report(self):
        pkgs = [("requests", "2.19.0"), ("flask", "3.0.0")]
        results = [{"vulns": [{"id": "GHSA-1"}]}, {}]
        findings = vulnscan.triage(pkgs, results)
        self.assertEqual(len(findings), 1)
        self.assertIn("requests==2.19.0: GHSA-1", vulnscan.render_report(findings))
        self.assertEqual(vulnscan.render_report([]), "No known vulnerabilities found.")


class S3AuditTests(unittest.TestCase):
    def make_s3(self, pab=None, enc_error=None, versioning="Enabled"):
        s3 = MagicMock()
        if pab is None:
            s3.get_public_access_block.side_effect = client_error(
                "NoSuchPublicAccessBlockConfiguration"
            )
        else:
            s3.get_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": pab
            }
        if enc_error:
            s3.get_bucket_encryption.side_effect = client_error(enc_error)
        s3.get_bucket_versioning.return_value = {"Status": versioning}
        return s3

    def test_clean_bucket(self):
        s3 = self.make_s3(pab={"BlockPublicAcls": True, "IgnorePublicAcls": True})
        self.assertEqual(s3audit.audit_bucket(s3, "good"), [])

    def test_insecure_bucket(self):
        s3 = self.make_s3(
            pab=None,
            enc_error="ServerSideEncryptionConfigurationNotFoundError",
            versioning="Suspended",
        )
        issues = s3audit.audit_bucket(s3, "bad")
        self.assertEqual(len(issues), 3)

    def test_unexpected_error_is_raised(self):
        s3 = self.make_s3(pab={"BlockPublicAcls": True})
        s3.get_bucket_encryption.side_effect = client_error("AccessDenied")
        with self.assertRaises(ClientError):
            s3audit.audit_bucket(s3, "x")

    def test_audit_all_and_render(self):
        s3 = self.make_s3(pab=None)
        s3.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
        report = s3audit.audit_all(s3)
        self.assertIn("b1", report)
        self.assertIn("S3 findings:", s3audit.render_report(report))
        self.assertEqual(s3audit.render_report({}), "All buckets passed the audit.")


if __name__ == "__main__":
    unittest.main()
