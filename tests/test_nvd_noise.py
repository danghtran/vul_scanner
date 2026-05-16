import unittest

from cve_lookup import build_cpe, cpe_for_installed
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


class TestCpeBuild(unittest.TestCase):
    def test_apache_http_server_cpe(self):
        cpe = build_cpe("apache", "2.4.7")
        self.assertEqual(cpe, "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*")

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
