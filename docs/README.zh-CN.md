# GitHub Agentic Workflow Safety Lab｜中文说明

这是一个用于审查 GitHub Actions 与 Agent 工作流的公开安全实验室。它的核心目标不是证明某个工作流“绝对安全”，而是把常被混在一起的信任边界拆开并自动检查。

## 核心问题

传统 CI/CD 风险包括：

- `GITHUB_TOKEN` 权限过大；
- Action 使用可变标签而非完整提交 SHA；
- 把 Issue、PR、评论等不可信文本直接拼入 Shell；
- `pull_request_target` 拉取并执行 PR 代码；
- 不可信 PR 使用长期存在的自托管 Runner；
- 下载 Artifact 后直接执行；
- 将网络脚本直接管道给 Bash；
- OIDC、Secrets 和部署环境边界不清。

Agent 工作流又增加：

- Prompt Injection（提示词注入）；
- 将 Secrets 直接交给模型或 Agent 依赖；
- 将模型输出直接当命令执行；
- Agent 同时拥有解释权和仓库写权限；
- 公共评论变成无人鉴权的执行入口；
- Agent 直接 Push、Merge 或修改主分支。

## 推荐架构

```text
不可信输入
→ 只读分析
→ 有类型的提案
→ 静态校验
→ 人工或 Environment 审批
→ 最小权限写入
→ 审计结果
```

不要采用：

```text
不可信输入
→ 带 Secrets 和写 Token 的 Agent
→ Shell
→ 直接 Push
```

## 工具能力

```bash
gawsl list-rules
gawsl explain AG002
gawsl verify-lab --root .
gawsl scan . --format text
gawsl scan . --format json
gawsl scan . --format sarif --output result.sarif
```

项目包含 22 条规则与 10 对漏洞/加固样例。漏洞样例全部位于 `examples/`，不会被 GitHub 作为真实 Workflow 执行。

## 成熟度说明

`v0.1.0` 已验证：

- YAML 解析与 `on` 键兼容；
- 规则命中和稳定指纹；
- 漏洞/加固配对；
- 配置和限时豁免；
- Text、JSON、SARIF 输出；
- CLI；
- Python 3.11–3.13；
- 公开面隐私扫描；
- Wheel 重复构建。

尚未宣称：

- 替代 GitHub CodeQL、组织策略或安全审计；
- 覆盖所有 YAML 语义和表达式数据流；
- 阻止运行时 Prompt Injection；
- 证明第三方 Action 或模型安全；
- 自动修复所有问题；
- 对生产仓库做过渗透测试。

详细内容见 [威胁模型](threat-model.md)、[规则参考](rule-reference.md) 和 [实验指南](lab-guide.md)。
