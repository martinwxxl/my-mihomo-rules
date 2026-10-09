"""Keep upstream Pro_cn verbatim except rules/providers and requested IPv6."""
import copy
import hashlib
import re
import subprocess
import yaml


def fetch_template(download):
    commit = subprocess.check_output(['git', 'ls-remote', '--exit-code',
        'https://github.com/666OS/YYDS.git', 'refs/heads/main'], text=True, timeout=60).split()[0]
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Invalid Pro_cn commit')
    base = f'https://raw.githubusercontent.com/666OS/YYDS/{commit}/'
    text = download(base + 'mihomo/config/cn/Pro_cn.yaml').decode('utf-8-sig')
    license_text = download(base + 'LICENSE.txt')
    return text, license_text, {'repository': '666OS/YYDS', 'commit': commit,
        'url': base + 'mihomo/config/cn/Pro_cn.yaml',
        'sha256': hashlib.sha256(text.encode()).hexdigest(),
        'changes': ['rules', 'rule-providers', 'ipv6=true', 'dns.ipv6=true']}


def render_template(text, generated):
    original = yaml.safe_load(text)
    # Keep all original non-routing bytes, including comments, anchors and icons.
    prefix, separator, _ = text.partition('# 规则路由')
    if not separator:
        raise ValueError('Pro_cn rules boundary changed; manual review required')
    prefix = re.sub(r'(?m)^(\s*ipv6:)\s*false\s*$', r'\1 true', prefix)
    rules = [rule.replace(',国内媒体', ',国内流量') for rule in generated['rules']]
    providers = copy.deepcopy(generated['rule-providers'])
    rendered = prefix + '# 规则路由：仅规则来源改为自建仓库；IPv6 按用户要求开启\n'
    rendered += yaml.safe_dump({'rules': rules, 'rule-providers': providers},
                               allow_unicode=True, sort_keys=False)
    parsed = yaml.safe_load(rendered)
    expected = copy.deepcopy(original)
    expected['ipv6'] = True
    expected['dns']['ipv6'] = True
    expected['rules'] = rules
    expected['rule-providers'] = providers
    if parsed != expected:
        raise ValueError('Unexpected change outside rules/providers/IPv6')
    groups = {g['name'] for g in parsed['proxy-groups']} | {'DIRECT', 'REJECT', 'REJECT-DROP'}
    for rule in rules:
        target = rule.split(',')[-2] if rule.endswith(',no-resolve') else rule.split(',')[-1]
        if target not in groups:
            raise ValueError('Unknown original Pro_cn policy: ' + target)
    return rendered
