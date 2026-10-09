# my-mihomo-rules

以 blackmatrix7/ios_rule_script 构建自有规则，以 YYDS666 的原版 Pro_cn 作为配置模板。

## 当前版本

直接抓取同一提交下的原版 Pro_cn，保留原注释、锚点和所有非规则设置；只替换 rules、rule-providers，并按用户要求将 ipv6 和 dns.ipv6 开启。配置语义对比发现任何其他变化时构建失败。上游提交、来源与修改范围记录在 manifest.json。

策略组名称、分类、地区过滤、默认选择、300 秒自动测速、均衡、地区故障转移、DNS、嗅探、端口、面板及认证设置都使用原版。没有增加主机场优先策略，也没有新增国内媒体策略组。国内媒体规则归入原版国内流量。原版自动测速可能选择备用机场更快的节点；故障转移仍按原版地区顺序运行。

推荐 YAML：

https://raw.githubusercontent.com/martinwxxl/my-mihomo-rules/release/openclash-yaml.yaml

兼容 MRS：

https://raw.githubusercontent.com/martinwxxl/my-mihomo-rules/release/openclash-mrs.yaml

原版 proxy-providers 留空，私人订阅由本地覆写注入。不要把机场订阅、节点凭据或令牌提交到公共仓库。

## OpenClash 接入

导入 openclash/My_Mihomo_Rules_OpenClash_IPTV.conf，参数为 EN_KEY1=主机场Clash订阅;EN_KEY2=备用机场Clash订阅。已有私人版本可直接导入，不需要参数。停用此前自建策略覆写模块和旧 Pro_cn 模块，选中 Pro_cn.yaml。

模块沿用用户原来的 Primary/Backup 订阅提供者、24 小时订阅刷新、300 秒健康检查，以及局域网访问和 IPTV 覆写；只将基础模板的下载地址换成自建规则仓库。每日上午 06:00 按原模块设定刷新模板。福建移动 IPTV 专用直连节点继续强制 IPv4；全局和 DNS 的 IPv6 已开启。客户端能否使用 IPv6 还取决于路由器网络和机场节点。

模板自带的认证和控制设置来自上游；OpenClash 会按其运行设置处理。路由器实际覆写、机场订阅下载、解锁和 IPTV 播放尚未实测。

## 构建与验证

每天北京时间 04:23 自动构建，也可手动运行 Actions。每次构建固定 blackmatrix7 和 Pro_cn 各自的提交快照。规则规范化、分类内外去重，按优先级处理完全重复；域名及 IP 覆盖冲突写入 conflicts.json，复杂逻辑规则的冲突无法穷尽判断。

只有 DOMAIN/DOMAIN-SUFFIX 转换为 domain MRS，带 no-resolve 的 IP-CIDR 转换为 ipcidr MRS；其他规则保留 classical YAML，避免丢失行为。混合 MRS 配置仍可能包含 classical YAML。

CI 验证原版设置保持不变和 IPv6、分类映射，再用固定 Mihomo v1.19.32 解析两份配置并实际启动确认每个规则提供者加载且非空。测试用的代理提供者仅为占位节点，验证配置不会发布。旧版自建主备故障转移测试已移除，因为当前策略完全交由 Pro_cn。

只有全部验证通过，才校验 SHA256SUMS 并非强制推送 release 分支。失败保留上一次成功发布。manifest.json 记录规则源文件原始注释、文件摘要、数量、上游提交和模板提交。数量异常下降或模板结构变化时停止发布。

## 许可与来源

规则及本仓库构建代码保留 GPL-2.0 和 LICENSE。Pro_cn 模板保留 YYDS666 / 666OS/YYDS 署名，按上游 GPL-3.0 附带 LICENSE-Pro_cn.txt 和 NOTICE-Pro_cn.md。上游声明见 https://github.com/666OS/YYDS ，包括其禁止转载/发布到中国互联网平台的说明。详细来源见 NOTICE.md 和发布 manifest.json。
