# my-mihomo-rules

[![Build](https://github.com/martinwxxl/my-mihomo-rules/actions/workflows/build.yml/badge.svg)](https://github.com/martinwxxl/my-mihomo-rules/actions/workflows/build.yml)

自己部署、自己维护的 Mihomo / OpenClash 规则仓库。机场优先，Cloudflare 节点接入留待后续。所有规则从 blackmatrix7/ios_rule_script 获取，Emby 使用其现成列表。

## 架构

- `main`：构建代码、上游分类表、测试和 GitHub Actions。
- `release`：通过验证的一整套规则、OpenClash 接入配置、来源与冲突报告、SHA256SUMS。客户端只订阅此分支。
- GitHub Actions 每天北京时间 04:23 构建，也支持 main 推送和手动运行。定时任务可能延迟。
- 一次构建固定一个上游提交；任何源下载失败、空文件、格式错误、源数量比上次下降超过 50%、MRS 转换或核心校验失败，都不发布。
- 全部成功后，以一次非强制 Git 推送更新 release。失败保留上一个发布；第一次失败则不创建 release。

## 分类与冲突

| 优先级 | 分类 | 上游列表 | 默认策略 |
|---:|---|---|---|
| 1 | ads | AdvertisingLite | REJECT |
| 2 | ai | OpenAI / Claude / Gemini / Copilot | AI |
| 3 | emby | Emby | Emby |
| 4 | streaming | GlobalMedia | 流媒体 |
| 5 | apple | Apple | Apple |
| 6 | social | Telegram / Twitter / Facebook / Instagram / Discord / Reddit | 社交 |
| 7 | development | Developer / GitHub | 开发 |
| 8 | domestic | China / ChinaIPs / ChinaMedia | DIRECT |

分类内去重，跨分类同一规则归优先级较高分类。域名后缀/精确域名/关键词与 IP 网段包含关系写入 conflicts.json，按以上顺序执行。它们通常是正常的交叉覆盖，不一概删除；正则、进程规则、逻辑组合无法静态穷尽冲突，保留给 Mihomo 语法检查和真实流量验证。

`rules/<category>.yaml` 是完整 classical 规则。MRS 版本仅转换 DOMAIN、DOMAIN-SUFFIX 和带 no-resolve 的 IP-CIDR/IP-CIDR6；DOMAIN-KEYWORD、PROCESS-NAME、需要 DNS 解析的 IP 与其他复杂类型仍使用 classical YAML，避免丢规则或改变解析语义。兼容的 domain/ipcidr 同时输出 YAML 和 MRS。

## OpenClash 接入

使用 Mihomo 内核。先下载发布配置：

- [完整 YAML 配置](https://raw.githubusercontent.com/martinwxxl/my-mihomo-rules/release/openclash-yaml.yaml)
- [MRS + classical 混合配置](https://raw.githubusercontent.com/martinwxxl/my-mihomo-rules/release/openclash-mrs.yaml)

配置包含本仓库 release 上的 rule-providers，刷新周期 24 小时。下载文件导入 OpenClash，保留其中的规则和策略组；OpenClash 的 TUN/TProxy、DNS 劫持、LAN 与 IPv6 设置按你的路由器网络环境配置。不要启用会把本配置规则/策略组替换掉的模板覆写。先用 YAML 版本，确认内核版本后可换混合 MRS 版本。

两份配置默认从本地读取机场节点，路径相对 Mihomo 工作目录；OpenClash 通常是 `/etc/openclash`，需在你的安装中确认。

```sh
mkdir -p /etc/openclash/proxy_provider
chmod 700 /etc/openclash/proxy_provider
# 在路由器本地保存 provider 格式节点文件：
# /etc/openclash/proxy_provider/primary.yaml
# /etc/openclash/proxy_provider/backup.yaml
chmod 600 /etc/openclash/proxy_provider/primary.yaml /etc/openclash/proxy_provider/backup.yaml
```

文件格式是 `proxies: [...]`，不是完整 Clash 配置，也不是 base64 通用订阅。建议用机场提供的 Clash/Mihomo 订阅格式；不要把私人订阅发给公共转换站。若现有订阅是完整配置，可在本地提取其 `proxies` 节点列表，或采用下面的 HTTP provider 方式。

需要订阅自动刷新时，只在路由器的本地配置将两个 proxy-providers 改为 `type: http`，添加你自己的 `url` 和 `interval: 3600`；保留 path、override、health-check。例：

```yaml
proxy-providers:
  primary:
    type: http
    url: '仅在路由器本地填主机场的 Clash/Mihomo 订阅地址'
    interval: 3600
    path: ./proxy_provider/primary.yaml
    override:
      additional-prefix: 'primary | '
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 60
      timeout: 5000
      lazy: false
      expected-status: 204
  backup:
    type: http
    url: '仅在路由器本地填备机场的 Clash/Mihomo 订阅地址'
    interval: 3600
    path: ./proxy_provider/backup.yaml
    override:
      additional-prefix: 'backup | '
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 60
      timeout: 5000
      lazy: false
      expected-status: 204
```

本地加了订阅 URL 后，不要使用会覆盖整份配置的远程配置自动更新；规则 provider 自己每 24 小时刷新。订阅 URL、节点密码、控制器密钥都不得提交 GitHub，GitHub Actions 也不需要机场 secrets。`.gitignore` 仅是辅助，提交前仍需检查。

## 主备优先级与故障转移

主机场、备机场各用 `url-test` 选择自身健康节点。外层 `机场故障转移` 为 `fallback`，顺序固定为 `[主机场, 备机场]`，优先使用健康主机场，主机场全不可用时使用备机场，后续检查主机场恢复后优先回主机场。不是把两家节点混合起来按最低延迟选。

健康检查每 60 秒一次，超时 5 秒，关闭 lazy。故障发现取决于检查时机，已有连接可能需要重新连接；备用订阅和节点必须事先可用。两个机场都不可用时代理请求失败，fallback 不含 DIRECT，不会自动转直连。

AI、Emby、流媒体、Apple、社交、开发默认选 `机场故障转移`，可在面板手动改成某机场或 DIRECT。面板手动选择会被记住；要保留自动故障转移，请让分类策略继续选择 `机场故障转移`。通用 204 检查只证明探测目标可达，不能保证 AI/Netflix/Emby 解锁；需要地域时，在本地按分类复制一组主备 url-test 并加节点 filter，然后套相同 fallback 顺序。

## 验证与回滚

CI 包含规则规范化、优先级、网段覆盖、MRS 语义、数量骤降、主备顺序和发布路径校验测试，并用两个本地模拟机场实测“主机场正常 → 主机场故障改走备用 → 主机场恢复回切”。固定 Mihomo v1.19.32，安装包校验官方 release SHA-256；生成 MRS 后，分别用 `mihomo -t` 校验完整 YAML 与混合 MRS，再启动内核，通过本地控制接口确认每个 rule-provider 实际加载且非空。CI 不连接私人机场，因此不代表家庭路由器实际播放或解锁已验证。

查看 Actions 中构建摘要，以及 release/manifest.json 与 conflicts.json。release 保留历史提交；客户端需要固定回滚版本时，将 rule-provider URL 中的 `release` 改为一个已验证发布提交 SHA。可以手动修正 sources.json 后重新构建，不需要删除上一个发布。

本地运行（Python 3.12、amd64）：

```sh
python -m pip install -r requirements.txt
python install_mihomo.py
python -m unittest -v test_build
python build.py --mihomo runtime/mihomo --output dist
# Windows 使用 --mihomo runtime/mihomo.exe
```

`dist` 必须是新目录，避免混入旧构建文件。程序会保存上游 URL、提交、原文件哈希、原注释头与分类数量；所有发布文件可用 SHA256SUMS 验证。

规则与构建代码采用 GPL-2.0，完整上游与作者说明见 LICENSE、NOTICE.md、manifest.json。
