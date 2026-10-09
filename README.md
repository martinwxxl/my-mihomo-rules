# my-mihomo-rules

[![Build](https://github.com/martinwxxl/my-mihomo-rules/actions/workflows/build.yml/badge.svg)](https://github.com/martinwxxl/my-mihomo-rules/actions/workflows/build.yml)

自建、自维护的 Mihomo / OpenClash 规则仓库。规则全部来自 blackmatrix7/ios_rule_script，Emby 使用其现成列表。分类和地区选择参考 [Pro_cn](https://raw.githubusercontent.com/666OS/YYDS/refs/heads/main/mihomo/config/cn/Pro_cn.yaml)，以独立实现保留主备机场优先级。机场优先，Cloudflare 节点后续再接入。

## 构建与发布

main 保存构建代码和来源；release 保存通过校验的配置、规则、manifest.json、conflicts.json、SHA256SUMS。每天北京时间 04:23 构建，也支持推送和手动运行；GitHub 定时任务可能延迟。

每次固定一个上游提交，抓取完整 classical 文件，规范化、去重、检查交叉覆盖，转换兼容 MRS 并启动内核验证。任何源下载失败、空列表、声明数量不符、较上次源数量骤降超过 50%、转换或校验失败，均不发布。通过全部校验后，一次非强制推送更新 release；失败保留上次发布，历史提交可用于回滚。

## 分类与默认策略

下表顺序为分类优先级。局域网规则在分类之前，最终未匹配流量交给漏网之鱼。国内媒体独立分类是本项目额外提供的选择。

| 分类 | 上游列表 | 默认策略 |
|---|---|---|
| 广告拦截 | Privacy / AdvertisingLite | REJECT-DROP，可改 REJECT 或 DIRECT |
| 网络测试 | Speedtest | 机场故障转移 |
| 即时通讯 | Telegram / Line / Whatsapp | 狮城优先路由 |
| 社交平台 | Twitter / Instagram / Discord / Reddit | 美国优先路由 |
| 人工智能 | OpenAI / Claude / Gemini / Copilot | 美国优先路由 |
| 开发服务 | Developer / GitHub | 美国优先路由 |
| EMBY | Emby | 美国优先路由 |
| 国际媒体 | GlobalMedia | 美国优先路由 |
| 游戏平台 | Game | 美国优先路由 |
| 货币平台 | Cryptocurrency | 日本优先路由 |
| 谷歌服务 | Google | 美国优先路由 |
| 脸书服务 | Facebook | 美国优先路由 |
| 微软服务 | Microsoft | 美国优先路由 |
| 苹果服务 | Apple | DIRECT |
| 国内媒体 | ChinaMedia | DIRECT |
| 国外流量 | Proxy | 机场故障转移 |
| 国内流量 | China / ChinaIPs | DIRECT |
| 漏网之鱼 | MATCH | 机场故障转移 |

所有分类都可在面板独立选择。国内网站、国内媒体和苹果默认直连，但没有写死 DIRECT。

分类内去重，跨分类同一规则归优先级较高分类。域名后缀、精确域名、关键词和 IP 包含关系写入 conflicts.json，按规则顺序确定策略。正常交叉覆盖不一概删除；正则、进程和复杂逻辑规则无法静态穷尽冲突。

## 地区与主备机场

香港、台湾、日本、狮城、韩国、美国均有“地区策略”“地区故障转移”“地区自动”“地区均衡”，以及隐藏的地区主/备测速组。

地区策略默认选择地区故障转移：先用主机场中该地区的健康节点，再用备用机场中该地区的健康节点。地区自动对两家机场该地区节点测速；地区均衡在两家的该地区节点之间做 consistent-hashing 负载均衡。全球手动及地区策略也可直接选择节点。

服务的地区优先路由先尝试首选地区的主备故障转移。该地区全部不可用或没有节点时，再使用通用机场故障转移。地区优先意味着，例如备用机场美国节点可能先于主机场其他地区节点使用；同一地区内主机场优先。空地区使用 REJECT，避免空组自动变成直连。

所有自动健康检查每 60 秒执行，超时 5 秒，lazy=false。主机场恢复后后续检查优先回切，已有连接可能需要重连。两个机场都不可用时代理请求失败，不自动直连。手动选择地区自动、地区均衡或具体节点时，采用相应模式，不再保证主机场优先。

地区通过节点名称匹配；非标准名称可调整 build.py 的 REGIONS。204 探测只证明目标可达，不能保证 AI、流媒体或 Emby 解锁。面板选择会被记住，升级后需检查实际选择。

## YAML 与 MRS

完整 classical 规则为 rules/<category>.yaml。仅 DOMAIN、DOMAIN-SUFFIX、带 no-resolve 的 IP-CIDR/IP-CIDR6 转换 MRS。关键词、进程名、ASN、需要 DNS 解析的 IP 和其他复杂规则继续使用 classical YAML，不丢规则或改变解析语义。兼容 domain/ipcidr 同时输出 YAML 和 MRS。

## OpenClash 与 IPTV 覆写

使用 Mihomo 内核。下载 [完整 YAML 配置](https://raw.githubusercontent.com/martinwxxl/my-mihomo-rules/release/openclash-yaml.yaml) 或 [MRS 混合配置](https://raw.githubusercontent.com/martinwxxl/my-mihomo-rules/release/openclash-mrs.yaml)。所有 rule-providers 指向自建 release，每 24 小时刷新。

模板默认读取 ./proxy_provider/primary.yaml 和 ./proxy_provider/backup.yaml，相对 Mihomo 工作目录，必须是 proxies: [...] 格式。OpenClash 通常使用 /etc/openclash，需在实际安装中确认。需要自动下载机场订阅时，在本地改为 HTTP provider，添加私人 URL、interval: 3600，保留 path、override、health-check。

推荐导入 [覆写模块](openclash/My_Mihomo_Rules_OpenClash_IPTV.conf)，参数为 EN_KEY1=主机场Clash订阅地址;EN_KEY2=备用机场Clash订阅地址，停用旧 Pro_cn 模块。模块每天 06:00 更新自建模板并重启应用覆写；保留 sntp.me、micu 直连和 fj.chinamobile.com 的专用 IPv4 直连。其他分类、地区策略和 DNS 不替换。

已有私人地址的本地覆写版不需要再次填参数，但不能上传公共仓库。订阅 URL、节点密码、UUID、控制器密钥都只保存在本地；CI 不需要机场 secrets。不要将私人订阅交给公共转换站。

首次升级完整分类版需重新下载基础 YAML 并重启应用覆写。只刷新规则 provider 不会新增策略组。TUN/TProxy、DNS 劫持、LAN、IPv6 按实际网络配置；不要让其他模板覆写替换本配置策略组或规则。

## 验证与维护

固定 Mihomo v1.19.32，安装包检查官方 release SHA-256。Actions 固定核验提交和 Ubuntu 24.04。测试覆盖规范化、优先级、MRS 语义、数量骤降、国内默认策略、地区主备顺序、发布路径。

CI 使用真实配置生成函数及本地模拟机场，验证美国地区主故障切备用、恢复回切；再用只有香港节点的机场验证美国优先路由退到通用主备机场。YAML 与混合 MRS 先通过 mihomo -t，再启动内核确认每个规则 provider 加载且非空。测试不代表真实机场解锁、家庭 IPTV 播放或路由器覆写流程已验证。

本地使用 Python 3.12：安装 requirements.txt，运行 install_mihomo.py，然后执行 python -m unittest -v test_build 和 python build.py --mihomo runtime/mihomo --output dist。Windows 内核路径为 runtime/mihomo.exe，dist 必须是新目录。

manifest.json 保留来源 URL、提交、哈希、原注释和数量；SHA256SUMS 校验发布文件。回滚时将 provider URL 中的 release 改成某个已验证发布提交 SHA。

规则及构建代码采用 GPL-2.0。参考说明见 LICENSE、NOTICE.md。地区和分类逻辑独立实现，未复制 Pro_cn 模板或 666OS 规则文件。
