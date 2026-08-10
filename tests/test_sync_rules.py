import json
import os
import stat
import tempfile
import textwrap
import unittest
from pathlib import Path

from tools.sync_rules import (
    ConversionError,
    convert_lsr_content,
    generate_rule_artifacts,
    to_snake_case,
)


class ConvertLsrContentTests(unittest.TestCase):
    def test_sorts_and_deduplicates_grouped_values_within_each_category(self) -> None:
        payload = textwrap.dedent(
            """
            DOMAIN,test.apple.com
            DOMAIN,google.com
            DOMAIN,apple.com
            DOMAIN,cdn.apple.com
            DOMAIN,apple.com
            DOMAIN-SUFFIX,google.com
            DOMAIN-SUFFIX,cdn.apple.com
            DOMAIN-SUFFIX,apple.com
            DOMAIN-SUFFIX,apple.com
            DOMAIN-KEYWORD,zeta
            DOMAIN-KEYWORD,alpha
            DOMAIN-KEYWORD,alpha
            IP-CIDR6,2001:db8::/48
            IP-CIDR,17.0.0.0/8
            IP-CIDR,10.0.0.0/24
            IP-CIDR,10.0.0.0/8
            IP-CIDR,10.0.0.0/8
            IP-CIDR6,2001:db8::/32
            PROCESS-NAME,zsh
            PROCESS-NAME,curl
            PROCESS-NAME,curl
            """
        )

        rule_set, unsupported = convert_lsr_content(payload, source_name="Sorted.lsr")

        self.assertEqual(
            rule_set,
            {
                "version": 3,
                "rules": [
                    {
                        "domain": ["apple.com", "cdn.apple.com", "google.com", "test.apple.com"],
                        "domain_suffix": ["apple.com", "cdn.apple.com", "google.com"],
                        "domain_keyword": ["alpha", "zeta"],
                        "ip_cidr": ["10.0.0.0/8", "10.0.0.0/24", "17.0.0.0/8", "2001:db8::/32", "2001:db8::/48"],
                    },
                    {"process_name": ["curl", "zsh"]},
                ],
            },
        )
        self.assertEqual(unsupported, [])

    def test_converts_basic_entries_to_grouped_sing_box_rules(self) -> None:
        payload = textwrap.dedent(
            """
            # comment
            DOMAIN,example.com
            DOMAIN,example.net
            DOMAIN-SUFFIX,example.org
            DOMAIN-KEYWORD,openai
            IP-CIDR,10.0.0.0/24,no-resolve
            IP-CIDR6,2001:db8::/32
            PROCESS-NAME,curl
            """
        )

        rule_set, unsupported = convert_lsr_content(payload, source_name="Sample.lsr")

        self.assertEqual(
            rule_set,
            {
                "version": 3,
                "rules": [
                    {
                        "domain": ["example.com", "example.net"],
                        "domain_suffix": ["example.org"],
                        "domain_keyword": ["openai"],
                        "ip_cidr": ["10.0.0.0/24", "2001:db8::/32"],
                    },
                    {"process_name": ["curl"]},
                ],
            },
        )
        self.assertEqual(unsupported, [])

    def test_sorts_by_category_before_grouping_simple_rules(self) -> None:
        payload = textwrap.dedent(
            """
            DOMAIN,example.com // comment
            DOMAIN-SUFFIX,example.org
            AND,((DOMAIN-KEYWORD,chatgpt-async-webps-prod-),(DOMAIN-SUFFIX,azurefd.net))
            DOMAIN,example.net
            DOMAIN-SUFFIX,example.edu
            """
        )

        rule_set, unsupported = convert_lsr_content(payload, source_name="AI.lsr")

        self.assertEqual(
            rule_set,
            {
                "version": 3,
                "rules": [
                    {
                        "domain": ["example.com", "example.net"],
                        "domain_suffix": ["example.edu", "example.org"],
                    },
                    {
                        "type": "logical",
                        "mode": "and",
                        "rules": [
                            {"domain_suffix": ["azurefd.net"]},
                            {"domain_keyword": ["chatgpt-async-webps-prod-"]},
                        ],
                    },
                ],
            },
        )
        self.assertEqual(unsupported, [])

    def test_normalizes_logical_rules_without_changing_boolean_semantics(self) -> None:
        payload = textwrap.dedent(
            """
            NOT,((DOMAIN,b.example.com))
            OR,((DOMAIN,b.example.com),(DOMAIN,a.example.com),(DOMAIN-SUFFIX,z.example.com),(DOMAIN-SUFFIX,a.example.com),(DOMAIN,a.example.com))
            AND,((PROCESS-NAME,zsh),(DOMAIN,b.example.com),(PROCESS-NAME,curl),(DOMAIN,a.example.com))
            """
        )

        rule_set, unsupported = convert_lsr_content(payload, source_name="Logical.lsr")

        self.assertEqual(
            rule_set,
            {
                "version": 3,
                "rules": [
                    {
                        "type": "logical",
                        "mode": "and",
                        "rules": [
                            {"domain": ["a.example.com"]},
                            {"domain": ["b.example.com"]},
                            {"process_name": ["curl"]},
                            {"process_name": ["zsh"]},
                        ],
                    },
                    {
                        "type": "logical",
                        "mode": "or",
                        "rules": [
                            {
                                "domain": ["a.example.com", "b.example.com"],
                                "domain_suffix": ["a.example.com", "z.example.com"],
                            },
                        ],
                    },
                    {
                        "domain": ["b.example.com"],
                        "invert": True,
                    },
                ],
            },
        )
        self.assertEqual(unsupported, [])

    def test_applies_not_inside_or_rule(self) -> None:
        payload = "OR,((DOMAIN,included.example.com),(NOT,((DOMAIN,excluded.example.com))))\n"

        rule_set, unsupported = convert_lsr_content(payload, source_name="Logical.lsr")

        self.assertEqual(
            rule_set["rules"],
            [
                {
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        {"domain": ["included.example.com"]},
                        {"domain": ["excluded.example.com"], "invert": True},
                    ],
                }
            ],
        )
        self.assertEqual(unsupported, [])

    def test_applies_not_to_logical_rule(self) -> None:
        payload = "NOT,((AND,((DOMAIN,b.example.com),(DOMAIN,a.example.com))))\n"

        rule_set, unsupported = convert_lsr_content(payload, source_name="Logical.lsr")

        self.assertEqual(
            rule_set["rules"],
            [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {"domain": ["a.example.com"]},
                        {"domain": ["b.example.com"]},
                    ],
                    "invert": True,
                }
            ],
        )
        self.assertEqual(unsupported, [])

    def test_cancels_double_logical_not(self) -> None:
        payload = "NOT,((NOT,((DOMAIN,double.example.com))))\n"

        rule_set, unsupported = convert_lsr_content(payload, source_name="Logical.lsr")

        self.assertEqual(rule_set["rules"], [{"domain": ["double.example.com"]}])
        self.assertEqual(unsupported, [])

    def test_ignores_ip_asn_entries(self) -> None:
        payload = "IP-ASN,62014,no-resolve\nDOMAIN,example.com\n"

        rule_set, unsupported = convert_lsr_content(payload, source_name="Telegram.lsr")

        self.assertEqual(rule_set["rules"], [{"domain": ["example.com"]}])
        self.assertEqual(unsupported, [])

    def test_raises_for_invalid_and_syntax(self) -> None:
        with self.assertRaises(ConversionError):
            convert_lsr_content("AND,(DOMAIN,example.com)\n", source_name="Broken.lsr")


class NamingTests(unittest.TestCase):
    def test_converts_pascal_case_names_to_snake_case(self) -> None:
        self.assertEqual(to_snake_case("AppleCN"), "apple_cn")
        self.assertEqual(to_snake_case("AppleCDN"), "apple_cdn")
        self.assertEqual(to_snake_case("AI"), "ai")

    def test_applies_name_overrides(self) -> None:
        self.assertEqual(to_snake_case("YouTube"), "youtube")
        self.assertEqual(to_snake_case("TikTok"), "tiktok")
        self.assertEqual(to_snake_case("iCloud"), "icloud")


class GenerateRuleArtifactsTests(unittest.TestCase):
    def test_generates_json_srs_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            output_dir = Path(tmpdir) / "output"
            source_dir.mkdir()
            output_dir.mkdir()

            (source_dir / "DemoRule.lsr").write_text("DOMAIN,example.com\n", encoding="utf-8")
            (source_dir / "boost.lsr").write_text("DOMAIN,ignored.example\n", encoding="utf-8")
            (output_dir / ".generated-files.txt").write_text("stale.json\nstale.srs\n", encoding="utf-8")
            (output_dir / "stale.json").write_text("old", encoding="utf-8")
            (output_dir / "stale.srs").write_text("old", encoding="utf-8")

            fake_sing_box = output_dir / "fake-sing-box"
            fake_sing_box.write_text(
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import pathlib
                    import sys

                    json_path = pathlib.Path(sys.argv[-1])
                    output_path = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
                    output_path.write_text('compiled:' + json_path.read_text(), encoding='utf-8')
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fake_sing_box.chmod(fake_sing_box.stat().st_mode | stat.S_IEXEC)

            result = generate_rule_artifacts(
                source_dir=source_dir,
                output_dir=output_dir,
                sing_box_binary=fake_sing_box,
                manifest_name=".generated-files.txt",
                clean=True,
            )

            demo_json = (output_dir / "demo_rule.json").resolve()
            demo_srs = (output_dir / "demo_rule.srs").resolve()
            manifest = output_dir / ".generated-files.txt"

            self.assertTrue(demo_json.exists())
            self.assertTrue(demo_srs.exists())
            self.assertEqual(json.loads(demo_json.read_text(encoding="utf-8"))["rules"], [{"domain": ["example.com"]}])
            self.assertIn("compiled:", demo_srs.read_text(encoding="utf-8"))
            self.assertFalse((output_dir / "boost.json").exists())
            self.assertFalse((output_dir / "boost.srs").exists())
            self.assertFalse((output_dir / "stale.json").exists())
            self.assertFalse((output_dir / "stale.srs").exists())
            self.assertEqual(manifest.read_text(encoding="utf-8").splitlines(), ["demo_rule.json", "demo_rule.srs"])
            self.assertEqual(result.generated_files, [demo_json, demo_srs])


if __name__ == "__main__":
    unittest.main()
