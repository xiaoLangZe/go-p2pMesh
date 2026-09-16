# 安全审计范围与结论登记（A2）

> 本文件是 **A2 要求的安全审计的记录载体**。只有在审计真实完成、下表每一行都填上
> 结论后，`scripts/release.sh audit` 才会放行。审计未完成不得发布 —— 这是 P12 的
> 退出条件，也是不可绕过的交付纪律。

## 审计项目清单（来自 §23 风险清单与 I1–I10 不变量）

| # | 审计项 | 覆盖代码 | 状态 | 结论 |
|---|---|---|---|---|
| 1 | I4：SQL 拼接与标识符注入 | `internal/storage`、`scripts/sqlscan` | 自动化门禁已就位（`check-sql.sh`） | 未审计 |
| 2 | I5：API 默认不暴露 | `pkg/server`、`internal/api`（回环默认、mTLS 可选） | 代码级检查通过 | 未审计 |
| 3 | I6：降级不静默 | `internal/tunnel`（`allow_unreliable_fallback`） | 单元测试覆盖 | 未审计 |
| 4 | I7：房间加盐寻址 | `pkg/types/salt.go`、`DeriveIPv6Addr` | 测试覆盖 | 未审计 |
| 5 | I8：ID 冲突拒绝 + D5 防抢注 | `internal/storage`（`RegisterNode`、`UnbindNodeID`） | 测试覆盖 | 未审计 |
| 6 | I9：根权威不中转 | `internal/relay`（`Hub.Root()` 拒绝）、`CertAuth` 两级链 | 测试覆盖 | 未审计 |
| 7 | I10：拒绝扫描四层机制 | `internal/portcontrol`（`Scanner`） | 测试覆盖 | 未审计 |
| 8 | Noise IK 握手正确性 | `internal/crypto`（flynn/noise 封装） | 未独立验证参数 | 未审计 |
| 9 | 证书链与 TOFU 语义 | `internal/crypto`（`ChainVerify`） | 测试覆盖 | 未审计 |
| 10 | JWT 与口令存储 | `internal/api`（HS256、bcrypt cost 12） | 自评测试覆盖 | 未审计 |
| 11 | 中继端到端加密不绕过 | `internal/relay`（仅转发密文） | 代码结构保证 | 未审计 |
| 12 | 供应链：依赖清单与大版本检查 | `go.mod`/`go.sum` | 未执行 | 未审计 |
| 13 | 独立渗透测试（选做） | 全库 | 未执行 | 未审计 |

## 结论

**（待审计完成后填写。未填写或写"未通过"，`release.sh audit` 将拒绝放行。）**