# 自用PCDN屏蔽规则集

# 使用方法
## ADGuardHome使用：https://sub.short.uegov.org/8vzyKY
## Clash使用：https://sub.short.uegov.org/RC0mDN
## Clash使用示例：

```
rules:
  - RULE-SET,PCDN,REJECT,no-resolve
rule-providers:
  PCDN:
    type: http
    behavior: domain
    url: "https://gh-proxy.com/raw.githubusercontent.com/VoidInTheShell/pcdn-block-list/refs/heads/master/pcdn_block_clash.yaml"
    path: ./RuleSet/pcdn.yaml
    interval: 86400
```

规则整合自：
- https://github.com/uselibrary/PCDN/blob/main/pcdn.list
- https://github.com/privacy-protection-tools/anti-AD/blob/5f9d5aba3af68bd18cd0c207a1a879b7cc71db58/discretion/pcdn.txt
- https://github.com/thhbdd/Block-pcdn-domains/blob/main/ban.txt
- https://github.com/susetao/PCDNFilter-CHN-
- https://github.com/Womsxd/MyAdBlockRules/refs/heads/master/p2pcdnblock.txt
- https://www.v2ex.com/t/1127079

