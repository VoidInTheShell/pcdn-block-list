# PCDN Block List

这是一个把多个专门的 PCDN / P2P-CDN 域名清单合并、去重并转换为两种常用格式的规则源。规则文件由脚本生成，请不要直接编辑产物。

## 直接订阅

AdGuard Home：将下面的地址作为过滤器 URL 添加：

<https://raw.githubusercontent.com/VoidInTheShell/pcdn-block-list/master/pcdn_block_adh.txt>

Clash / Mihomo：使用下面的 YAML Rule Provider：

<https://raw.githubusercontent.com/VoidInTheShell/pcdn-block-list/master/pcdn_block_clash.yaml>

如果客户端无法访问 `raw.githubusercontent.com`，可以将域名替换为 `cdn.jsdelivr.net/gh`：

<https://cdn.jsdelivr.net/gh/VoidInTheShell/pcdn-block-list@master/pcdn_block_adh.txt>

<https://cdn.jsdelivr.net/gh/VoidInTheShell/pcdn-block-list@master/pcdn_block_clash.yaml>

Clash / Mihomo 配置示例：

```yaml
rule-providers:
  PCDN:
    type: http
    behavior: domain
    format: yaml
    url: "https://raw.githubusercontent.com/VoidInTheShell/pcdn-block-list/master/pcdn_block_clash.yaml"
    path: ./RuleSet/pcdn_block_clash.yaml
    interval: 21600

rules:
  - RULE-SET,PCDN,REJECT,no-resolve
```

这份规则是主动拦截用的，可能影响依赖相同 CDN/P2P 基础设施的正常业务；建议先在自己的网络和设备上观察命中情况，再决定是否长期启用。

## 自动同步

`.github/workflows/sync-pcdn.yml` 会：

- 每 6 小时抓取一次所有必需上游；
- 支持在 GitHub Actions 页面手动运行；
- 在 `sources.json`、脚本或规则相关文件变更后自动重新生成；
- 运行标准库单元测试、严格语法解析和生成结果校验；
- 只有所有上游抓取并解析成功时才提交变更，抓取失败、空文件或未知语法会 fail closed，不会用残缺结果覆盖已有产物；
- 将每个上游的 SHA-256、识别行数和规则数写入 [`sources.lock.json`](sources.lock.json)，即使规则集合没有变化，上游内容变化也可审计。

Pull Request 只执行验证，不会向目标分支写入；定时任务和 `master` 分支上的相关变更会由 `github-actions[bot]` 提交 `chore: sync PCDN rules`。

本地复现：

```powershell
python scripts/sync_rules.py
python -m unittest discover -s tests -v
python scripts/sync_rules.py --check
```

## 当前上游

以下都是专门面向 PCDN 或 P2P-CDN 的机器可读清单，地址和分支直接写在 [`sources.json`](sources.json) 中：

| 来源 | 输入格式 | 纳入原因 |
| --- | --- | --- |
| [uselibrary/PCDN](https://github.com/uselibrary/PCDN) | Clash/Mihomo | 通用 CDN、视频平台、P2P 和斗鱼专用域名/正则 |
| [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) | 纯域名 | 专门的 `discretion/pcdn.txt`，补充了当前列表没有的域名 |
| [thhbdd/Block-pcdn-domains](https://github.com/thhbdd/Block-pcdn-domains) | AdGuard | 专门的 `ban.txt`，并由其仓库发布订阅 |
| [susetao/PCDNFilter-CHN-](https://github.com/susetao/PCDNFilter-CHN-) | AdGuard Home | 面向 PCDN 的合并清单，README 当前指向 `PCDNFilter.txt` |
| [Womsxd/MyAdBlockRules](https://github.com/Womsxd/MyAdBlockRules) | AdGuard | `p2pcdnblock.txt`，补充腾讯、快手、斗鱼、星域云、哔哩哔哩、金山云等规则 |

原 README 中的 V2EX 页面是讨论/线索，不是稳定的机器可读上游，因此不再由 CI 抓取；需要人工核验的新线索应先转换成可审计的专门清单，再加入 `sources.json`。
