import tempfile
import unittest
from pathlib import Path

from cve_lookup import build_cpe, cpe_for_installed, rank_cpe_cves, select_cpe_cves
from nvd_noise import (
    filter_banner_token,
    has_version_evidence,
    is_hostname_noise_keyword,
    should_skip_nvd_keyword,
    stack_is_cdn_opaque,
    summary_conflicts_with_products,
)


class TestNvdNoise(unittest.TestCase):
    def test_hostname_example_blocked(self):
        self.assertTrue(is_hostname_noise_keyword("example", "example.com"))
        self.assertTrue(is_hostname_noise_keyword("example.com", "example.com"))

    def test_version_keyword_allowed(self):
        self.assertFalse(
            should_skip_nvd_keyword(
                "openssh 6.6.1p1",
                "version",
                target_host="scanme.nmap.org",
                has_version_evidence=True,
            )
        )

    def test_header_skipped_without_version(self):
        self.assertTrue(
            should_skip_nvd_keyword(
                "missing hsts",
                "header",
                target_host="example.com",
                has_version_evidence=False,
            )
        )

    def test_cdn_opaque_blocks_cloudflare(self):
        self.assertTrue(
            should_skip_nvd_keyword(
                "cloudflare",
                "inventory",
                cdn_opaque=True,
                has_version_evidence=False,
            )
        )

    def test_banner_token_noise(self):
        self.assertFalse(filter_banner_token("cloudflare", "example.com"))
        self.assertFalse(filter_banner_token("example", "example.com"))

    def test_version_evidence_observation(self):
        obs = [
            {
                "parsed_version": {"product": "openssh", "version_token": "6.6.1p1"},
                "nvd_keywords": [],
            }
        ]
        self.assertTrue(has_version_evidence(obs))

    def test_cdn_opaque_findings(self):
        findings = {
            "observations": [],
            "port_banners": {80: "HTTP/1.1 400 Server: cloudflare"},
            "web_inventory": {"server": "cloudflare", "tech_hints": ["cloudflare"]},
        }
        self.assertTrue(stack_is_cdn_opaque(findings))

    def test_apache_cxf_conflict(self):
        self.assertTrue(
            summary_conflicts_with_products(
                "Apache CXF 2.4.5 allows remote attackers",
                {"apache"},
            )
        )


class TestCpeRankCap(unittest.TestCase):
    def test_rank_prefers_kev_and_cvss(self):
        rows = [
            {"cve_id": "CVE-2000-0001", "cvss": 5.0, "known_exploited": False},
            {"cve_id": "CVE-2020-0001", "cvss": 7.5, "known_exploited": False},
            {"cve_id": "CVE-2015-0001", "cvss": 6.0, "known_exploited": True},
        ]
        ranked = rank_cpe_cves(rows)
        self.assertEqual(ranked[0]["cve_id"], "CVE-2015-0001")

    def test_select_drops_not_applicable(self):
        cves = [
            {
                "cve_id": "CVE-2014-2532",
                "summary": "OpenSSH before 6.6",
                "cvss": 5.0,
            },
            {
                "cve_id": "CVE-2015-5600",
                "summary": "OpenSSH before 7.0",
                "cvss": 8.0,
            },
        ]
        from version_match import version_tuple

        installed = [
            {
                "product": "openssh",
                "version_token": "6.6.1p1",
                "version_tuple": version_tuple("6.6.1p1"),
            }
        ]
        kept, stats = select_cpe_cves(cves, max_keep=5, installed=installed)
        ids = {c["cve_id"] for c in kept}
        self.assertNotIn("CVE-2014-2532", ids)
        self.assertGreaterEqual(stats["dropped_version"], 1)

    def test_select_caps_count(self):
        rows = [
            {"cve_id": f"CVE-202{i}-0001", "cvss": float(i), "known_exploited": False}
            for i in range(10)
        ]
        kept, stats = select_cpe_cves(rows, max_keep=3, installed=None)
        self.assertEqual(len(kept), 3)
        self.assertEqual(stats["kept"], 3)


class TestNvdCache(unittest.TestCase):
    def test_cache_roundtrip(self):
        import cve_lookup as cl

        with tempfile.TemporaryDirectory() as tmp:
            cl.NVD_CACHE_DIR = Path(tmp)
            cl.NVD_CACHE_ENABLED = True
            cl.NVD_CACHE_TTL = 3600
            cl.reset_nvd_fetch_stats()
            url = "https://example.test/nvd?test=1"
            payload = {"vulnerabilities": [{"cve": {"id": "CVE-TEST-1"}}]}
            cl._write_cache(url, payload)
            got = cl._read_cache(url)
            self.assertIsNotNone(got)
            self.assertEqual(got["vulnerabilities"][0]["cve"]["id"], "CVE-TEST-1")


class TestVersionExtract(unittest.TestCase):
    def test_tomcat_banner(self):
        from version_extract import parse_banner_version

        pv = parse_banner_version("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n")
        self.assertIsNotNone(pv)
        self.assertEqual(pv["product"], "tomcat")

    def test_vsftpd_banner(self):
        from version_extract import parse_banner_version

        pv = parse_banner_version("220 (vsFTPd 3.0.3)")
        self.assertEqual(pv["product"], "vsftpd")
        self.assertEqual(pv["version_token"], "3.0.3")


class TestCpeBuild(unittest.TestCase):
    def test_apache_http_server_cpe(self):
        cpe = build_cpe("apache", "2.4.7")
        self.assertEqual(cpe, "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*")

    def test_tomcat_cpe(self):
        cpe = build_cpe("tomcat", "9.0.50")
        self.assertIn("apache:tomcat:9.0.50", cpe or "")

    def test_vsftpd_cpe(self):
        cpe = build_cpe("vsftpd", "3.0.3")
        self.assertIn("vsftpd:vsftpd:3.0.3", cpe or "")

    def test_openssh_cpe(self):
        cpe = build_cpe("openssh", "6.6.1p1")
        self.assertIn("openbsd:openssh:6.6.1p1", cpe or "")

    def test_unknown_product(self):
        self.assertIsNone(build_cpe("ftp", "1.0"))

    def test_installed_row(self):
        cpe = cpe_for_installed({"product": "nginx", "version_token": "1.18.0"})
        self.assertIn("nginx:nginx:1.18.0", cpe or "")


if __name__ == "__main__":
    unittest.main()
