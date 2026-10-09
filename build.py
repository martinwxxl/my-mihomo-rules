"""Fail-closed blackmatrix7 rule build; all network sources share one commit."""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request

import yaml
from validate_runtime import validate_runtime

ROOT = Path(__file__).resolve().parent
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "martinwxxl/my-mihomo-rules")
CHECK_URL = "https://www.gstatic.com/generate_204"
REGIONS = {
    "香港": r"(?i)(香港|港|Hong[ _-]?Kong|\bHK\b|\bHKG\b|🇭🇰)",
    "台湾": r"(?i)(台湾|台灣|台北|Taiwan|Taipei|\bTW\b|\bTPE\b|🇹🇼)",
    "日本": r"(?i)(日本|东京|大阪|Japan|Tokyo|Osaka|\bJP\b|\bNRT\b|🇯🇵)",
    "狮城": r"(?i)(新加坡|狮城|Singapore|\bSG\b|\bSIN\b|🇸🇬)",
    "韩国": r"(?i)(韩国|韓國|首尔|首爾|Korea|Seoul|\bKR\b|\bICN\b|🇰🇷)",
    "美国": r"(?i)(美国|美國|美东|美西|United[ _-]?States|America|\bUSA?\b|🇺🇸)",
}
POLICIES = {
    "ads": "广告拦截", "speedtest": "网络测试", "im": "即时通讯", "social": "社交平台",
    "ai": "人工智能", "development": "开发服务", "emby": "EMBY", "streaming": "国际媒体",
    "games": "游戏平台", "crypto": "货币平台", "google": "谷歌服务", "facebook": "脸书服务",
    "microsoft": "微软服务", "apple": "苹果服务", "domesticmedia": "国内媒体",
    "global": "国外流量", "domestic": "国内流量",
}


def download(url):
    headers = {"User-Agent": "my-mihomo-rules", "Accept": "application/vnd.github+json"}
    # Token is sent only to GitHub API, never raw sources or arbitrary hosts.
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
                data = response.read(40_000_001)
                if len(data) > 40_000_000:
                    raise ValueError("Source exceeds 40 MB")
                return data
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def normalize(rule):
    if not isinstance(rule, str) or "\n" in rule:
        raise ValueError(f"Invalid rule: {rule!r}")
    fields = [part.strip() for part in rule.split(",")]
    kind = fields[0].upper()
    if len(fields) < 2 or not fields[1]:
        raise ValueError(f"Invalid classical rule: {rule}")
    fields[0] = kind
    if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
        if len(fields) != 2:
            raise ValueError(f"Invalid domain fields: {rule}")
        domain = fields[1].rstrip(".").lower().encode("idna").decode("ascii")
        if len(domain) > 253 or not all(re.fullmatch(r"[a-z0-9_-]{1,63}", x) for x in domain.split(".")):
            raise ValueError(f"Invalid domain: {rule}")
        fields[1] = domain
    elif kind in ("IP-CIDR", "IP-CIDR6"):
        if len(fields) > 3 or (len(fields) == 3 and fields[2].lower() != "no-resolve"):
            raise ValueError(f"Invalid CIDR fields: {rule}")
        net = ipaddress.ip_network(fields[1], strict=False)
        fields[0] = "IP-CIDR6" if net.version == 6 else "IP-CIDR"
        fields[1] = str(net)
        if len(fields) == 3:
            fields[2] = "no-resolve"
    elif kind in ("DOMAIN-KEYWORD", "DOMAIN-WILDCARD"):
        fields[1] = fields[1].lower()
    # Complex classical rules remain classical, with Mihomo as final syntax gate.
    elif kind in ("MATCH", "RULE-SET", "SUB-RULE"):
        raise ValueError(f"Unsafe provider rule: {rule}")
    return ",".join(fields)


def split_rule(rule):
    fields = rule.split(",")
    if fields[0] == "DOMAIN":
        return "domain", fields[1]
    if fields[0] == "DOMAIN-SUFFIX":
        return "domain", "+." + fields[1]
    # Preserve DNS resolution semantics. Only explicit no-resolve IPs go to MRS.
    if fields[0] in ("IP-CIDR", "IP-CIDR6") and fields[-1] == "no-resolve":
        return "ipcidr", fields[1]
    return "classical", rule


def assign_categories(raw, priority):
    owner, result, conflicts = {}, {}, []
    for category in priority:
        result[category] = []
        for rule in sorted(set(raw[category])):
            # no-resolve affects resolution, not the destination being owned.
            key = rule.removesuffix(",no-resolve")
            if key in owner:
                conflicts.append({"rule": rule, "winner": owner[key], "removed_from": category})
            else:
                owner[key] = category
                result[category].append(rule)
    return result, conflicts


def overlaps(categories, priority):
    """Detect cross-category suffix/exact, keyword and CIDR coverage. Report only."""
    rank = {name: i for i, name in enumerate(priority)}
    suffixes, keywords, nets, details = {}, [], {}, []
    for category, rules in categories.items():
        for rule in rules:
            f = rule.split(",")
            if f[0] == "DOMAIN-SUFFIX":
                suffixes.setdefault(f[1], []).append(category)
            elif f[0] == "DOMAIN-KEYWORD":
                keywords.append((f[1], category))
            elif f[0] in ("IP-CIDR", "IP-CIDR6"):
                net = ipaddress.ip_network(f[1])
                nets.setdefault((net.version, net.prefixlen, int(net.network_address)), []).append(category)
    def record(rule, category, other, reason):
        if other != category:
            winner = min((category, other), key=rank.get)
            details.append({"rule": rule, "category": category, "overlap_with": other,
                            "winner": winner, "reason": reason})
    for category, rules in categories.items():
        for rule in rules:
            f = rule.split(",")
            if f[0] in ("DOMAIN", "DOMAIN-SUFFIX"):
                labels = f[1].split(".")
                for i in range(len(labels)):
                    for other in suffixes.get(".".join(labels[i:]), []):
                        record(rule, category, other, "domain suffix coverage")
                for keyword, other in keywords:
                    if keyword in f[1]:
                        record(rule, category, other, "domain keyword coverage")
            elif f[0] in ("IP-CIDR", "IP-CIDR6"):
                net = ipaddress.ip_network(f[1])
                for prefix in range(net.prefixlen + 1):
                    parent = net.supernet(new_prefix=prefix) if prefix < net.prefixlen else net
                    for other in nets.get((net.version, prefix, int(parent.network_address)), []):
                        record(rule, category, other, "CIDR coverage")
    return details


def write_yaml(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")


def make_config(index, priority, fmt, local=False):
    cfg = {"mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
           "ipv6": False, "profile": {"store-selected": True},
           "dns": {"enable": True, "listen": "127.0.0.1:7874", "enhanced-mode": "fake-ip",
                   "fake-ip-range": "198.18.0.1/16", "fake-ip-filter": ["*.lan", "*.local"],
                   "default-nameserver": ["223.5.5.5", "119.29.29.29"],
                   "nameserver": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
                   "proxy-server-nameserver": ["https://dns.alidns.com/dns-query"]}}
    cfg["proxy-providers"] = {}
    for name in ("primary", "backup"):
        cfg["proxy-providers"][name] = {"type": "file", "path": f"./proxy_provider/{name}.yaml",
            "override": {"additional-prefix": name + " | "},
            "health-check": {"enable": True, "url": CHECK_URL, "interval": 60,
                             "timeout": 5000, "lazy": False, "expected-status": 204}}
    groups = []
    for name, provider in (("主机场", "primary"), ("备机场", "backup")):
        groups.append({"name": name, "type": "url-test", "use": [provider], "url": CHECK_URL,
                       "interval": 60, "timeout": 5000, "tolerance": 50, "lazy": False,
                       "expected-status": 204, "empty-fallback": "REJECT"})
    groups += [{"name": "机场故障转移", "type": "fallback", "proxies": ["主机场", "备机场"],
                "url": CHECK_URL, "interval": 60, "timeout": 5000, "lazy": False,
                "expected-status": 204, "empty-fallback": "REJECT"},
               {"name": "全球手动", "type": "select", "proxies": ["机场故障转移"],
                "use": ["primary", "backup"]}]
    health = {"url": CHECK_URL, "interval": 60, "timeout": 5000,
              "lazy": False, "expected-status": 204, "empty-fallback": "REJECT"}
    for region, pattern in REGIONS.items():
        for airport, provider in (("主机场", "primary"), ("备机场", "backup")):
            groups.append({"name": region + airport, "type": "url-test", "use": [provider],
                           "filter": pattern, "tolerance": 50, "hidden": True, **health})
        groups.append({"name": region + "故障转移", "type": "fallback",
                       "proxies": [region + "主机场", region + "备机场"], **health})
        groups.append({"name": region + "自动", "type": "url-test", "use": ["primary", "backup"],
                       "filter": pattern, "tolerance": 50, "hidden": True, **health})
        groups.append({"name": region + "均衡", "type": "load-balance", "use": ["primary", "backup"],
                       "filter": pattern, "strategy": "consistent-hashing", "hidden": True, **health})
        groups.append({"name": region + "策略", "type": "select", "use": ["primary", "backup"],
                       "filter": pattern, "proxies": [region + "故障转移", region + "自动", region + "均衡"]})
    region_choices = [region + "策略" for region in REGIONS]
    general = ["机场故障转移", "全球手动", *region_choices, "主机场", "备机场", "DIRECT"]
    preferred = {"im": "狮城", "social": "美国", "ai": "美国", "development": "美国",
                 "emby": "美国", "streaming": "美国", "games": "美国", "crypto": "日本",
                 "google": "美国", "facebook": "美国", "microsoft": "美国"}
    for category, name in POLICIES.items():
        if category == "ads":
            choices = ["REJECT-DROP", "REJECT", "DIRECT"]
        elif category in ("apple", "domesticmedia", "domestic"):
            choices = ["DIRECT", *general[:-1]]
        elif category in preferred:
            # A region preference falls back to other healthy airport nodes when absent.
            route = name + "优先路由"
            groups.append({"name": route, "type": "fallback", "hidden": True,
                           "proxies": [preferred[category] + "故障转移", "机场故障转移"], **health})
            choices = [route, preferred[category] + "策略", *general]
        else:
            choices = general
        groups.append({"name": name, "type": "select", "proxies": list(dict.fromkeys(choices))})
    groups.append({"name": "漏网之鱼", "type": "select", "proxies": general})
    cfg["proxy-groups"] = groups
    cfg["rule-providers"] = {}
    rules = ["IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
             "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
             "DOMAIN-SUFFIX,lan,DIRECT", "DOMAIN-SUFFIX,local,DIRECT"]
    for category in priority:
        entries = [("classical", f"rules/{category}.yaml")] if fmt == "yaml" else index[category]
        for behavior, path in entries:
            key = category + "-" + behavior
            provider = {"type": "file" if local else "http", "behavior": behavior,
                        "format": "mrs" if path.endswith(".mrs") else "yaml",
                        "path": "./" + path}
            if not local:
                provider.update({"url": f"https://raw.githubusercontent.com/{REPOSITORY}/release/{path}",
                                 "interval": 86400})
            cfg["rule-providers"][key] = provider
            rule = f"RULE-SET,{key},{POLICIES[category]}"
            if behavior == "ipcidr":
                rule += ",no-resolve"
            rules.append(rule)
    rules.append("MATCH,漏网之鱼")
    cfg["rules"] = rules
    return cfg


def run_core(core, args, cwd=None):
    subprocess.run([core, *map(str, args)], check=True, cwd=cwd, timeout=180)


def guard_drop(previous, source_counts, limit):
    if not previous:
        return
    old = json.loads(Path(previous).read_text(encoding="utf-8"))
    for name, count in source_counts.items():
        before = old.get("source_counts", {}).get(name)
        if before and count < before * (1 - limit):
            raise ValueError(f"{name}: suspicious source shrink {before} -> {count}")


def build(args):
    spec = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    priority = spec["priority"]
    if set(priority) != set(spec["categories"]) or len(priority) != len(set(priority)):
        raise ValueError("Priority must include every category exactly once")
    core = str(Path(args.mihomo).resolve())
    out = Path(args.output).resolve()
    if out.exists():
        raise ValueError("Output must be a new directory (avoid stale output)")
    out.mkdir(parents=True)
    refs = subprocess.check_output(["git", "ls-remote", "--exit-code",
        f'https://github.com/{spec["upstream"]}.git', 'refs/heads/' + spec["ref"]],
        text=True, timeout=60, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    snapshot = refs.split()[0]
    if not re.fullmatch(r"[0-9a-f]{40}", snapshot):
        raise ValueError("Invalid upstream commit")
    rawbase = f'https://raw.githubusercontent.com/{spec["upstream"]}/{snapshot}'
    names = sorted({s for v in spec["categories"].values() for s in v})
    def fetch(name):
        source_path = spec.get("files", {}).get(name, f"rule/Clash/{name}/{name}.yaml")
        url = f"{rawbase}/{source_path}"
        try:
            data = download(url)
        except Exception as error:
            raise ValueError(f"Could not fetch {name}: {url}") from error
        document = yaml.safe_load(data)
        if not isinstance(document, dict) or not isinstance(document.get("payload"), list) or not document["payload"]:
            raise ValueError(f"Missing/non-list/empty payload: {name}")
        rules = [normalize(rule) for rule in document["payload"]]
        total = re.search(r"^# TOTAL:\s*(\d+)\s*$", data.decode("utf-8-sig"), re.MULTILINE)
        if total and len(rules) != int(total.group(1)):
            raise ValueError(f"{name}: source header TOTAL differs from payload; incomplete source variant")
        # Keep upstream header and provenance in redistribution notice.
        header = "\n".join(line for line in data.decode("utf-8-sig").splitlines() if line.startswith("#"))
        return name, rules, {"url": url, "sha256": hashlib.sha256(data).hexdigest(), "header": header}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fetched = list(pool.map(fetch, names))
    sources = {name: rules for name, rules, _ in fetched}
    source_counts = {name: len(rules) for name, rules in sources.items()}
    guard_drop(args.previous, source_counts, spec["max_drop_fraction"])
    raw = {category: [rule for name in names_ for rule in sources[name]]
           for category, names_ in spec["categories"].items()}
    categories, duplicates = assign_categories(raw, priority)
    coverage = overlaps(categories, priority)
    index = {}
    for category, rules in categories.items():
        if not rules:
            raise ValueError(f"Category empty after deduplication: {category}")
        write_yaml(out / f"rules/{category}.yaml", {"payload": rules})
        parts = {"domain": [], "ipcidr": [], "classical": []}
        for rule in rules:
            behavior, value = split_rule(rule)
            parts[behavior].append(value)
        index[category] = []
        for behavior, payload in parts.items():
            if not payload:
                continue
            path = f"rules/{category}-{behavior}.yaml"
            write_yaml(out / path, {"payload": sorted(set(payload))})
            if behavior != "classical":
                mrspath = path.removesuffix(".yaml") + ".mrs"
                run_core(core, ["convert-ruleset", behavior, "yaml", out / path, out / mrspath])
                if (out / mrspath).stat().st_size == 0:
                    raise ValueError("Empty MRS")
                index[category].append((behavior, mrspath))
            else:
                index[category].append((behavior, path))
    for fmt in ("yaml", "mrs"):
        write_yaml(out / f"openclash-{fmt}.yaml", make_config(index, priority, fmt))
        # Both configurations are validated against local generated providers.
        validation = out / ("validate-" + fmt)
        validation.mkdir()
        shutil.copytree(out / "rules", validation / "rules")
        for name in ("primary", "backup"):
            write_yaml(validation / f"proxy_provider/{name}.yaml", {"proxies": [{"name": "ci-" + name,
                       "type": "http", "server": "127.0.0.1", "port": 9}]})
        local_config = make_config(index, priority, fmt, local=True)
        write_yaml(validation / "config.yaml", local_config)
        run_core(core, ["-t", "-d", validation, "-f", validation / "config.yaml"])
        validate_runtime(core, validation, local_config)
        shutil.rmtree(validation)
    manifest = {"schema": 1, "upstream": spec["upstream"], "upstream_commit": snapshot,
                "builder_commit": os.environ.get("GITHUB_SHA", "local"),
                "mihomo": subprocess.check_output([core, "-v"], text=True).strip(),
                "priority": priority, "source_counts": source_counts,
                "category_counts": {k: len(v) for k, v in categories.items()},
                "sources": {name: provenance for name, _, provenance in fetched}}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "conflicts.json").write_text(json.dumps({"policy": "first category in priority wins; overlaps retained and order resolves",
        "exact_duplicates": duplicates, "coverage_overlaps": coverage,
        "limits": "Domain suffix/exact/keyword and CIDR coverage checked. Regex, process and logical-rule overlap cannot be proven statically."},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(ROOT / "LICENSE", out / "LICENSE")
    shutil.copyfile(ROOT / "NOTICE.md", out / "NOTICE.md")
    (out / "README.md").write_text("# Validated rule release\n\nSee the [source repository](https://github.com/" + REPOSITORY + ").\n"
        "Use openclash-yaml.yaml or openclash-mrs.yaml. Airport credentials are local-only.\n", encoding="utf-8")
    sums = [hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.relative_to(out).as_posix()
            for p in sorted(out.rglob("*")) if p.is_file()]
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(json.dumps({"upstream_commit": snapshot, "counts": manifest["category_counts"],
                      "deduplicated": len(duplicates), "overlaps": len(coverage)}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--output", default="dist")
    parser.add_argument("--previous")
    build(parser.parse_args())
