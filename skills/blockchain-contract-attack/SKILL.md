---
name: blockchain-contract-attack
description: >-
  区块链/智能合约:Etherscan,slither/mythril,重入/访问控制/预言机/闪电贷,跨链桥,RPC暴露。Use when auditing smart contracts, DeFi, or blockchain attack surfaces.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 区块链 / 智能合约

## 适用场景

适合已确认链、合约地址、源码或字节码、RPC 和资金范围，需要评估智能合约或链上基础设施风险。

## 核心判断

先确认链、合约、权限、资金流、外部调用和运行环境，再判断重入、访问控制、预言机、随机数、代理和跨链风险。

## 证据标准

- 源码或字节码需要与链上地址和版本对应。
- 重入和外部调用需要调用顺序、状态更新和资金流证据。
- 权限问题需要实际角色和调用者证据。
- 经济攻击需要市场条件、资金量和可执行交易证据。

## 决策树

- 合约源码可得：先做静态审计和权限映射。
- 只有字节码：先验证地址、代理和函数选择器。
- 发现重入或权限候选：在测试链或只读模拟中验证。
- 涉及资金或治理：可优先使用测试链、只读模拟或回滚方案。
- 无链上或本地证据：保留候选，不作利用结论。

## 常见误判

- 把 Etherscan 验证源码当成当前代理实现。
- 把 Slither 命中当成可利用。
- 忽略 owner、proxy admin 和时间锁。
- 在主网执行验证交易。
- 把理论经济攻击当成已成功。

```
=== 区块链/智能合约 ===
源码: Etherscan getsourcecode API | 审计 slither/mythril/manticore
手工: 重入(.call{value}先转账后改状态违反C-E-I) | 访问控制(onlyOwner缺失) | 整数溢出(<0.8无SafeMath)
  预言机操纵(闪电贷瞬时操纵AMM价格) | 随机数(block.timestamp可控) | 授权滥用(无限approve/permit重放) | delegatecall代理storage冲突
DeFi: 闪电贷攻击/三明治(抢跑)/治理攻击/签名重放 | 跨链桥:签名阈值绕过/重放 | RPC:暴露8545直接eth_sendTransaction
```
