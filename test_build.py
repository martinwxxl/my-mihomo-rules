import json
from pathlib import Path
import tempfile
import unittest
from build import normalize, split_rule, assign_categories, overlaps, guard_drop, make_config
from publish import verify_dist
from pro_cn import render_template
import yaml


class BuildTests(unittest.TestCase):
    def test_original_settings_survive_rule_replacement_and_ipv6(self):
        template = """ipv6: false
dns:
  ipv6: false
  nameserver: [https://dns.example/dns-query]
proxy-groups:
  - {name: 国内流量, type: select, proxies: [DIRECT]}
  - {name: 漏网之鱼, type: select, proxies: [DIRECT]}
profile: {store-selected: true}
# 规则路由
rules: [MATCH,漏网之鱼]
rule-providers: {}
"""
        generated = make_config({}, ["domesticmedia", "domestic"], "yaml")
        rendered = yaml.safe_load(render_template(template, generated))
        self.assertTrue(rendered['ipv6'])
        self.assertTrue(rendered['dns']['ipv6'])
        self.assertEqual(rendered['dns']['nameserver'], ['https://dns.example/dns-query'])
        self.assertEqual(rendered['proxy-groups'], yaml.safe_load(template)['proxy-groups'])
        self.assertIn('RULE-SET,domesticmedia-classical,国内流量', rendered['rules'])
        self.assertEqual(rendered['profile'], {'store-selected': True})

    def test_normalization(self):
        self.assertEqual(normalize(" domain-suffix , ExAmPle.COM. "), "DOMAIN-SUFFIX,example.com")
        self.assertEqual(normalize("IP-CIDR,10.0.0.1/8,no-resolve"), "IP-CIDR,10.0.0.0/8,no-resolve")
        for rule in ("DOMAIN,", "DOMAIN,https://example.com", "IP-CIDR,not-ip", "MATCH,DIRECT"):
            with self.assertRaises(ValueError):
                normalize(rule)

    def test_mrs_preserves_semantics(self):
        self.assertEqual(split_rule("DOMAIN-SUFFIX,example.com"), ("domain", "+.example.com"))
        for rule in ("DOMAIN-KEYWORD,emby", "PROCESS-NAME,com.mb.android", "IP-CIDR,10.0.0.0/8"):
            self.assertEqual(split_rule(rule), ("classical", rule))
        self.assertEqual(split_rule("IP-CIDR,10.0.0.0/8,no-resolve"), ("ipcidr", "10.0.0.0/8"))

    def test_conflict_priority_and_overlap(self):
        raw = {"ai": ["DOMAIN,a.example.com", "DOMAIN,a.example.com"],
               "domestic": ["DOMAIN,a.example.com", "DOMAIN-SUFFIX,example.com"]}
        categories, conflicts = assign_categories(raw, ["ai", "domestic"])
        self.assertEqual(categories["ai"], ["DOMAIN,a.example.com"])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(overlaps(categories, ["ai", "domestic"])[0]["winner"], "ai")

    def test_cidr_overlap(self):
        categories = {"ads": ["IP-CIDR,10.0.0.0/8,no-resolve"], "domestic": ["IP-CIDR,10.1.0.0/16"]}
        self.assertEqual(overlaps(categories, ["ads", "domestic"])[0]["winner"], "ads")

    def test_large_drop_aborts(self):
        with tempfile.TemporaryDirectory() as temporary:
            previous = Path(temporary) / "manifest.json"
            previous.write_text(json.dumps({"source_counts": {"Emby": 100}}))
            with self.assertRaises(ValueError):
                guard_drop(previous, {"Emby": 49}, 0.5)
            guard_drop(previous, {"Emby": 50}, 0.5)


    def test_publish_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / "SHA256SUMS").write_text("abc  ../credential\n")
            with self.assertRaises(ValueError):
                verify_dist(path)





if __name__ == "__main__":
    unittest.main()
